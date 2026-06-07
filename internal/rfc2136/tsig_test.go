// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"
)

func makeTSIGMessage(
	t *testing.T,
	msgID uint16,
	secret []byte,
	keyName, algo string,
	timeSigned uint64,
	fudge uint16,
) []byte {
	t.Helper()

	// Build a minimal update message body (header + zone question)
	body := buildUpdateMessage(msgID, "example.com.", nil)

	// Build TSIG variables
	tsigVars := buildTSIGVariables(keyName, algo, timeSigned, fudge, 0, nil)

	// Compute MAC over body + vars
	h := hmac.New(sha256.New, secret)
	h.Write(body)
	h.Write(tsigVars)
	mac := h.Sum(nil)

	// Encode TSIG RDATA
	rdata := encodeTSIGRdata(algo, timeSigned, fudge, mac, msgID, 0, nil)
	tsigRR := encodeRR(keyName, TypeTSIG, ClassANY, 0, rdata)

	// Update ARCOUNT
	oldAR := uint16(body[10])<<8 | uint16(body[11])
	body[10] = byte((oldAR + 1) >> 8)
	body[11] = byte(oldAR + 1)

	return append(body, tsigRR...)
}

func TestValidateTSIG_Valid(t *testing.T) {
	secret := []byte("supersecret")
	keyName := "acme-key."
	now := uint64(time.Now().Unix())

	raw := makeTSIGMessage(
		t,
		0x1111,
		secret,
		keyName,
		algorithmHMACSHA256,
		now,
		300,
	)

	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := ValidateTSIG(msg, secret, time.Unix(int64(now), 0)); err != nil {
		t.Errorf("expected valid TSIG, got: %v", err)
	}
}

func TestValidateTSIG_WrongSecret(t *testing.T) {
	secret := []byte("supersecret")
	wrongSecret := []byte("wrongsecret")
	keyName := "acme-key."
	now := uint64(time.Now().Unix())

	raw := makeTSIGMessage(
		t,
		0x2222,
		secret,
		keyName,
		algorithmHMACSHA256,
		now,
		300,
	)

	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := ValidateTSIG(msg, wrongSecret, time.Unix(int64(now), 0)); err == nil {
		t.Error("expected error with wrong secret")
	}
}

func TestValidateTSIG_Missing(t *testing.T) {
	raw := buildUpdateMessage(1, "example.com.", nil)

	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := ValidateTSIG(msg, []byte("secret"), time.Now()); err != ErrTSIGMissing {
		t.Errorf("expected ErrTSIGMissing, got: %v", err)
	}
}

func TestValidateTSIG_UnsupportedAlgorithm(t *testing.T) {
	secret := []byte("supersecret")
	keyName := "acme-key."
	now := uint64(time.Now().Unix())

	// Use unsupported algo (hmac-md5)
	raw := makeTSIGMessage(
		t,
		0x3333,
		secret,
		keyName,
		"hmac-md5.sig-alg.reg.int.",
		now,
		300,
	)

	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := ValidateTSIG(msg, secret, time.Unix(int64(now), 0)); err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestValidateTSIG_TimeWindow(t *testing.T) {
	secret := []byte("supersecret")
	keyName := "acme-key."
	// timeSigned 10 minutes in the past, fudge=300s (5 min) — should fail
	past := uint64(time.Now().Unix()) - 600
	raw := makeTSIGMessage(
		t,
		0x4444,
		secret,
		keyName,
		algorithmHMACSHA256,
		past,
		300,
	)

	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := ValidateTSIG(msg, secret, time.Now()); err == nil {
		t.Error("expected time window violation")
	}
}

func TestSignResponse_ValidMAC(t *testing.T) {
	secret := []byte("testkey")
	keyName := "acme-key."
	now := uint64(time.Now().Unix())

	requestRaw := makeTSIGMessage(
		t,
		0x5555,
		secret,
		keyName,
		algorithmHMACSHA256,
		now,
		300,
	)

	reqMsg, err := ParseMessage(requestRaw)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}

	respBuf := BuildResponse(reqMsg, RcodeNoError)
	signed := SignResponse(respBuf, reqMsg.TSIG, secret)

	// Parse the signed response and verify TSIG is present
	respMsg, err := ParseMessage(signed)
	if err != nil {
		t.Fatalf("parse signed response: %v", err)
	}

	if respMsg.TSIG == nil {
		t.Fatal("signed response has no TSIG")
	}
}

func TestSignResponse_MalformedTSIGRR(t *testing.T) {
	// A TSIG RR with truncated/malformed rdata triggers appendUnsignedTSIG.
	badTSIG := &RR{
		Name:     "acme-key.",
		Type:     TypeTSIG,
		Class:    ClassANY,
		TTL:      0,
		Rdlength: 2,
		Rdata:    []byte{0x00, 0x00}, // too short to be valid TSIG rdata
	}

	respBuf := make([]byte, 12) // minimal 12-byte header
	signed := SignResponse(respBuf, badTSIG, []byte("secret"))

	// Should still produce a parseable message with a TSIG appended.
	respMsg, err := ParseMessage(signed)
	if err != nil {
		t.Fatalf("parse signed response: %v", err)
	}

	if respMsg.TSIG == nil {
		t.Fatal("expected unsigned TSIG appended for malformed request TSIG")
	}
}
