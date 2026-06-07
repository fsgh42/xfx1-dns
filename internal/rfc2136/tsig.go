// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// algorithmHMACSHA256 is the TSIG algorithm name for HMAC-SHA256 (RFC 4635).
	algorithmHMACSHA256 = "hmac-sha256."

	// tsigFudgeDefault is the default allowed clock skew in seconds (RFC 2845 §2.3).
	tsigFudgeDefault = 300
)

var (
	ErrTSIGMissing             = errors.New("TSIG record missing")
	ErrTSIGBadAlgorithm        = errors.New("unsupported TSIG algorithm")
	ErrTSIGBadSignature        = errors.New("TSIG MAC verification failed")
	ErrTSIGTimeWindowViolation = errors.New("TSIG time out of range")
)

// TSIGRecord holds the parsed fields of a TSIG RR's RDATA (RFC 2845 §2.3).
type TSIGRecord struct {
	Algorithm  string // e.g. "hmac-sha256."
	TimeSigned uint64 // 48-bit Unix seconds
	Fudge      uint16
	MAC        []byte
	OrigID     uint16
	Error      uint16
	OtherData  []byte
}

// ParseTSIGRdata parses the RDATA of a TSIG RR.
func ParseTSIGRdata(rr *RR) (*TSIGRecord, error) {
	data := rr.Rdata
	// Algorithm name (domain name wire format)
	algo, n, err := parseName(data, 0)
	if err != nil {
		return nil, fmt.Errorf("tsig algorithm name: %w", err)
	}

	offset := n

	if offset+10 > len(data) {
		return nil, errors.New("tsig rdata truncated (fixed fields)")
	}

	// Time Signed: 6 bytes big-endian
	var timeSigned uint64
	for i := range 6 {
		timeSigned = (timeSigned << 8) | uint64(data[offset+i])
	}

	offset += 6

	fudge := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	macSize := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(macSize) > len(data) {
		return nil, errors.New("tsig rdata truncated (MAC)")
	}

	mac := make([]byte, macSize)
	copy(mac, data[offset:offset+int(macSize)])
	offset += int(macSize)

	if offset+6 > len(data) {
		return nil, errors.New("tsig rdata truncated (tail)")
	}

	origID := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	tsigError := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	otherLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	var otherData []byte

	if int(otherLen) > 0 {
		if offset+int(otherLen) > len(data) {
			return nil, errors.New("tsig rdata truncated (other data)")
		}

		otherData = make([]byte, otherLen)
		copy(otherData, data[offset:offset+int(otherLen)])
	}

	tsr := &TSIGRecord{
		Algorithm:  strings.ToLower(algo),
		TimeSigned: timeSigned,
		Fudge:      fudge,
		MAC:        mac,
		OrigID:     origID,
		Error:      tsigError,
		OtherData:  otherData,
	}

	return tsr, nil
}

// ValidateTSIG validates the TSIG on msg using the given shared secret.
// msg.Raw must be the original message bytes without the TSIG RR appended.
// now is used for time window validation.
func ValidateTSIG(msg *Message, secret []byte, now time.Time) error {
	if msg.TSIG == nil {
		return ErrTSIGMissing
	}

	tsig, err := ParseTSIGRdata(msg.TSIG)
	if err != nil {
		return fmt.Errorf("parse TSIG rdata: %w", err)
	}

	if tsig.Algorithm != algorithmHMACSHA256 {
		return fmt.Errorf("%w: %s", ErrTSIGBadAlgorithm, tsig.Algorithm)
	}

	// Time window check
	nowSec := uint64(now.Unix())

	fudge := uint64(tsig.Fudge)
	if fudge == 0 {
		fudge = tsigFudgeDefault
	}

	if nowSec > tsig.TimeSigned+fudge ||
		(tsig.TimeSigned > nowSec && tsig.TimeSigned-nowSec > fudge) {
		return ErrTSIGTimeWindowViolation
	}

	// Compute expected MAC per RFC 2845 §3.4.2
	mac := computeMAC(secret, msg.Raw, msg.TSIG, tsig)

	if !hmac.Equal(mac, tsig.MAC) {
		return ErrTSIGBadSignature
	}

	return nil
}

// SignResponse builds TSIG RDATA for a response and appends the TSIG RR to buf.
// buf should already contain the response message (12 bytes header + any records).
// The response TSIG is signed with the request TSIG's key name and algorithm.
func SignResponse(responseBuf []byte, requestTSIG *RR, secret []byte) []byte {
	tsig, err := ParseTSIGRdata(requestTSIG)
	if err != nil {
		// Build unsigned TSIG with error
		return appendUnsignedTSIG(responseBuf, requestTSIG)
	}

	now := uint64(time.Now().Unix())

	fudge := tsig.Fudge
	if fudge == 0 {
		fudge = tsigFudgeDefault
	}

	// Per RFC 2845 §4.2: response MAC = HMAC(request_MAC_wire + response_bytes + TSIG_vars).
	var signBuf []byte
	signBuf = append(signBuf, encodeMACWire(tsig.MAC)...)
	signBuf = append(signBuf, responseBuf...)
	tsigVars := buildTSIGVariables(
		requestTSIG.Name,
		tsig.Algorithm,
		now,
		fudge,
		0,
		nil,
	)
	signBuf = append(signBuf, tsigVars...)

	mac := hmacSHA256(secret, signBuf)

	tsigRdata := encodeTSIGRdata(
		tsig.Algorithm,
		now,
		fudge,
		mac,
		binary.BigEndian.Uint16(responseBuf[0:2]),
		0,
		nil,
	)
	tsigRR := encodeRR(requestTSIG.Name, TypeTSIG, ClassANY, 0, tsigRdata)

	// Update ARCOUNT in response header
	arcount := binary.BigEndian.Uint16(responseBuf[10:12])
	binary.BigEndian.PutUint16(responseBuf[10:12], arcount+1)

	return append(responseBuf, tsigRR...)
}

// appendUnsignedTSIG appends an unsigned TSIG (for error responses).
func appendUnsignedTSIG(buf []byte, requestTSIG *RR) []byte {
	tsig, _ := ParseTSIGRdata(requestTSIG)

	var algo string

	if tsig != nil {
		algo = tsig.Algorithm
	} else {
		algo = algorithmHMACSHA256
	}

	rdata := encodeTSIGRdata(
		algo,
		uint64(time.Now().Unix()),
		tsigFudgeDefault,
		nil,
		binary.BigEndian.Uint16(buf[0:2]),
		RcodeRefused,
		nil,
	)
	tsigRR := encodeRR(requestTSIG.Name, TypeTSIG, ClassANY, 0, rdata)
	arcount := binary.BigEndian.Uint16(buf[10:12])
	binary.BigEndian.PutUint16(buf[10:12], arcount+1)

	return append(buf, tsigRR...)
}

// computeMAC computes the HMAC-SHA256 MAC for TSIG validation (RFC 2845 §3.4.2).
// The MAC covers: message bytes (with TSIG AR removed) + TSIG variables.
func computeMAC(secret, msgBytes []byte, tsigRR *RR, tsig *TSIGRecord) []byte {
	var data []byte

	data = append(data, msgBytes...)
	vars := buildTSIGVariables(
		tsigRR.Name,
		tsig.Algorithm,
		tsig.TimeSigned,
		tsig.Fudge,
		tsig.Error,
		tsig.OtherData,
	)
	data = append(data, vars...)

	return hmacSHA256(secret, data)
}

// buildTSIGVariables encodes the TSIG variables for MAC computation (RFC 2845 §3.4.2).
func buildTSIGVariables(
	keyName, algo string,
	timeSigned uint64,
	fudge uint16,
	tsigError uint16,
	otherData []byte,
) []byte {
	var buf []byte

	buf = append(buf, encodeName(keyName)...)
	// CLASS ANY (2 bytes big-endian = 0x00FF)
	buf = append(buf, byte(ClassANY>>8), byte(ClassANY))
	// TTL = 0 (4 bytes)
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, encodeName(algo)...)

	// Time Signed (6 bytes)
	for i := 5; i >= 0; i-- {
		buf = append(buf, byte(timeSigned>>(uint(i)*8)))
	}

	buf = append(buf, byte(fudge>>8), byte(fudge))
	buf = append(buf, byte(tsigError>>8), byte(tsigError))
	buf = append(buf, byte(len(otherData)>>8), byte(len(otherData)))
	buf = append(buf, otherData...)

	return buf
}

// encodeTSIGRdata encodes TSIG RDATA.
func encodeTSIGRdata(
	algo string,
	timeSigned uint64,
	fudge uint16,
	mac []byte,
	origID uint16,
	tsigError uint16,
	otherData []byte,
) []byte {
	var buf []byte

	buf = append(buf, encodeName(algo)...)

	for i := 5; i >= 0; i-- {
		buf = append(buf, byte(timeSigned>>(uint(i)*8)))
	}

	buf = append(buf, byte(fudge>>8), byte(fudge))
	buf = append(buf, byte(len(mac)>>8), byte(len(mac)))
	buf = append(buf, mac...)
	buf = append(buf, byte(origID>>8), byte(origID))
	buf = append(buf, byte(tsigError>>8), byte(tsigError))
	buf = append(buf, byte(len(otherData)>>8), byte(len(otherData)))
	buf = append(buf, otherData...)

	return buf
}

// encodeRR encodes a full DNS RR in wire format.
func encodeRR(
	name string,
	rrtype, class uint16,
	ttl uint32,
	rdata []byte,
) []byte {
	var buf []byte

	buf = append(buf, encodeName(name)...)
	buf = append(buf, byte(rrtype>>8), byte(rrtype))
	buf = append(buf, byte(class>>8), byte(class))
	buf = append(buf, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
	buf = append(buf, byte(len(rdata)>>8), byte(len(rdata)))
	buf = append(buf, rdata...)

	return buf
}

// encodeMACWire encodes a MAC as the wire format used in RFC 2845 §3.4.3:
// 2-byte big-endian length followed by the MAC bytes.
func encodeMACWire(mac []byte) []byte {
	buf := make([]byte, 2+len(mac))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(mac)))
	copy(buf[2:], mac)

	return buf
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(secret, data []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)

	return h.Sum(nil)
}
