// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// parsedDNSKEY holds a DNSKEY record parsed from a DNS response.
type parsedDNSKEY struct {
	flags   uint16
	alg     uint8
	pubKey  []byte // raw public key bytes per RFC 4034 §2.1
	keyTag  uint16
	rawData []byte // full RDATA (for keytag computation)
}

// parsedRRSIG holds a parsed RRSIG record from a DNS response.
type parsedRRSIG struct {
	typeCovered uint16
	algorithm   uint8
	labels      uint8
	origTTL     uint32
	expiration  uint32
	inception   uint32
	keyTag      uint16
	signerName  string
	headerRdata []byte // RRSIG RDATA bytes up to and including the signer name (signing input prefix)
	signature   []byte
}

// fetchDNSKEYs queries addr for the DNSKEY RRset of zone and returns all parsed keys.
func fetchDNSKEYs(
	addr, zone string,
	timeout time.Duration,
) ([]parsedDNSKEY, error) {
	qtype, ok := rec.RRtypeToWire[rec.TypeDNSKEY]
	if !ok {
		return nil, errors.New("DNSKEY wire type not found")
	}

	msg := buildQuery(0xAB12, zone, qtype, true, true)

	resp, err := sendTCP(addr, timeout, msg)
	if err != nil {
		return nil, fmt.Errorf("query DNSKEY: %w", err)
	}

	parsed, err := parseResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse DNSKEY response: %w", err)
	}

	var keys []parsedDNSKEY

	for _, rr := range parsed.answers {
		if rr.rtype != qtype {
			continue
		}

		k, err := parseDNSKEYRdata(rr.rdata)
		if err != nil {
			continue
		}

		keys = append(keys, k)
	}

	return keys, nil
}

// parseDNSKEYRdata decodes raw DNSKEY RDATA (RFC 4034 §2.1).
func parseDNSKEYRdata(rdata []byte) (parsedDNSKEY, error) {
	if len(rdata) < 4 {
		return parsedDNSKEY{}, errors.New("DNSKEY RDATA too short")
	}

	flags := binary.BigEndian.Uint16(rdata[0:2])
	// rdata[2] = protocol (always 3)
	alg := rdata[3]
	pubKey := make([]byte, len(rdata)-4)
	copy(pubKey, rdata[4:])

	return parsedDNSKEY{
		flags:   flags,
		alg:     alg,
		pubKey:  pubKey,
		keyTag:  dnskeyTag(rdata),
		rawData: rdata,
	}, nil
}

// dnskeyTag computes the key tag per RFC 4034 Appendix B.
func dnskeyTag(rdata []byte) uint16 {
	var ac uint32

	for i, b := range rdata {
		if i&1 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}

	ac += ac >> 16

	return uint16(ac & 0xFFFF)
}

// parseRRSIGRdata decodes raw RRSIG RDATA (RFC 4034 §3.1).
func parseRRSIGRdata(rdata []byte) (parsedRRSIG, error) {
	// Fixed header: typeCovered(2)+alg(1)+labels(1)+origTTL(4)+exp(4)+inc(4)+keyTag(2) = 18
	if len(rdata) < 18 {
		return parsedRRSIG{}, errors.New("RRSIG RDATA too short")
	}

	r := parsedRRSIG{
		typeCovered: binary.BigEndian.Uint16(rdata[0:2]),
		algorithm:   rdata[2],
		labels:      rdata[3],
		origTTL:     binary.BigEndian.Uint32(rdata[4:8]),
		expiration:  binary.BigEndian.Uint32(rdata[8:12]),
		inception:   binary.BigEndian.Uint32(rdata[12:16]),
		keyTag:      binary.BigEndian.Uint16(rdata[16:18]),
	}

	// Signer name is uncompressed in RRSIG RDATA (RFC 4034 §6.2).
	name, nameEnd, err := parseUncompressedDomain(rdata, 18)
	if err != nil {
		return parsedRRSIG{}, fmt.Errorf("parse signer name: %w", err)
	}

	r.signerName = name
	r.headerRdata = rdata[:nameEnd] // everything before the signature
	r.signature = make([]byte, len(rdata)-nameEnd)
	copy(r.signature, rdata[nameEnd:])

	return r, nil
}

// verifyRRSIG verifies one RRSIG over the given RRset against the provided keys.
// Returns nil on success or an error describing the failure.
func verifyRRSIG(
	rrsig parsedRRSIG,
	rrset []parsedRR,
	keys []parsedDNSKEY,
) error {
	// Check validity window.
	now := uint32(time.Now().UTC().Unix())
	if now < rrsig.inception {
		return fmt.Errorf(
			"RRSIG not yet valid (inception %d, now %d)",
			rrsig.inception,
			now,
		)
	}

	if now > rrsig.expiration {
		return fmt.Errorf("RRSIG expired at %d (now %d)", rrsig.expiration, now)
	}

	// Find matching DNSKEY by key tag and algorithm.
	var key *parsedDNSKEY

	for i := range keys {
		if keys[i].keyTag == rrsig.keyTag && keys[i].alg == rrsig.algorithm {
			key = &keys[i]
			break
		}
	}

	if key == nil {
		return fmt.Errorf(
			"no DNSKEY for tag %d alg %d",
			rrsig.keyTag,
			rrsig.algorithm,
		)
	}

	input, err := buildSigningInput(rrsig, rrset)
	if err != nil {
		return fmt.Errorf("build signing input: %w", err)
	}

	return verifySig(input, rrsig.signature, rrsig.algorithm, key.pubKey)
}

// buildSigningInput assembles the data that was signed per RFC 4034 §6.2.
func buildSigningInput(rrsig parsedRRSIG, rrset []parsedRR) ([]byte, error) {
	var buf bytes.Buffer

	// 1. RRSIG RDATA without the signature (header + signer name).
	buf.Write(rrsig.headerRdata)

	// 2. RRset in canonical order (sorted by RDATA bytes).
	sorted := make([]parsedRR, len(rrset))
	copy(sorted, rrset)
	slices.SortFunc(sorted, func(a, b parsedRR) int {
		return bytes.Compare(a.rdata, b.rdata)
	})

	for _, rr := range sorted {
		// Owner name: lowercase, uncompressed wire format.
		ownerLower := rec.Domain(strings.ToLower(rr.name))
		if err := ownerLower.Write(&buf); err != nil {
			return nil, fmt.Errorf("encode owner: %w", err)
		}

		binary.Write(&buf, binary.BigEndian, rrsig.typeCovered)
		binary.Write(&buf, binary.BigEndian, uint16(1)) // class IN
		binary.Write(&buf, binary.BigEndian, rrsig.origTTL)
		binary.Write(&buf, binary.BigEndian, uint16(len(rr.rdata)))
		buf.Write(rr.rdata)
	}

	return buf.Bytes(), nil
}

// verifySig verifies a raw DNS signature against input data using the given algorithm.
func verifySig(input, sig []byte, alg uint8, pubKeyBytes []byte) error {
	switch alg {
	case 13: // ECDSAP256SHA256 (RFC 6605)
		if len(pubKeyBytes) != 64 {
			return fmt.Errorf(
				"alg 13 pubkey: want 64 bytes, got %d",
				len(pubKeyBytes),
			)
		}

		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(pubKeyBytes[:32]),
			Y:     new(big.Int).SetBytes(pubKeyBytes[32:]),
		}

		h := sha256.Sum256(input)

		derSig, err := dnssec.ECDSAFixedSizeToDER(sig, 13)
		if err != nil {
			return fmt.Errorf("decode P-256 sig: %w", err)
		}

		if !ecdsa.VerifyASN1(pub, h[:], derSig) {
			return errors.New("P-256 signature invalid")
		}

		return nil

	case 14: // ECDSAP384SHA384 (RFC 6605)
		if len(pubKeyBytes) != 96 {
			return fmt.Errorf(
				"alg 14 pubkey: want 96 bytes, got %d",
				len(pubKeyBytes),
			)
		}

		pub := &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(pubKeyBytes[:48]),
			Y:     new(big.Int).SetBytes(pubKeyBytes[48:]),
		}

		h := sha512.Sum384(input)

		derSig, err := dnssec.ECDSAFixedSizeToDER(sig, 14)
		if err != nil {
			return fmt.Errorf("decode P-384 sig: %w", err)
		}

		if !ecdsa.VerifyASN1(pub, h[:], derSig) {
			return errors.New("P-384 signature invalid")
		}

		return nil

	case 15: // ED25519 (RFC 8080)
		if len(pubKeyBytes) != 32 {
			return fmt.Errorf(
				"alg 15 pubkey: want 32 bytes, got %d",
				len(pubKeyBytes),
			)
		}

		pub := ed25519.PublicKey(pubKeyBytes)

		if !ed25519.Verify(pub, input, sig) {
			return errors.New("ED25519 signature invalid")
		}

		return nil

	default:
		return fmt.Errorf("unsupported algorithm %d", alg)
	}
}
