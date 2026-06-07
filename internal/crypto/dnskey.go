// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// DNSKEYRecord holds the parsed fields of a DNSKEY RR.
type DNSKEYRecord struct {
	Owner     string // e.g. "xfx1.de."
	TTL       uint32
	Flags     uint16 // 256=ZSK, 257=KSK
	Protocol  uint8  // always 3
	Algorithm uint8  // 8, 13, 14, or 15
	PublicKey []byte // raw decoded public key bytes
}

// ParseDNSKEY parses a DNSKEY RR presentation string.
// Returns an error if the string is not a valid DNSKEY RR.
//
// Accepted format (parentheses and extra whitespace within the key material are stripped):
//
//	<owner> <ttl> IN DNSKEY <flags> <protocol> <algorithm> <base64-pubkey>
func ParseDNSKEY(s string) (*DNSKEYRecord, error) {
	// Strip parentheses and collapse whitespace inside them — BIND sometimes
	// wraps the base64 key in parentheses with embedded spaces/newlines.
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")

	fields := strings.Fields(s)
	// Minimum without TTL: owner IN DNSKEY flags protocol algorithm pubkey = 7 fields
	if len(fields) < 7 {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: too few fields: %d",
			len(fields),
		)
	}

	owner := fields[0]

	// TTL is optional: ldns-keygen omits it, producing "owner IN DNSKEY ...".
	// Detect by checking whether fields[1] is numeric.
	var ttl64 uint64

	i := 1
	if n, err := strconv.ParseUint(fields[i], 10, 32); err == nil {
		ttl64 = n
		i++
	}

	if len(fields) < i+6 {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: too few fields: %d",
			len(fields),
		)
	}

	if !strings.EqualFold(fields[i], "IN") {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: expected class IN, got %q",
			fields[i],
		)
	}

	i++
	if !strings.EqualFold(fields[i], "DNSKEY") {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: expected type DNSKEY, got %q",
			fields[i],
		)
	}

	i++

	flags64, err := strconv.ParseUint(fields[i], 10, 16)
	if err != nil {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: invalid flags %q: %w",
			fields[i],
			err,
		)
	}

	i++

	proto64, err := strconv.ParseUint(fields[i], 10, 8)
	if err != nil {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: invalid protocol %q: %w",
			fields[i],
			err,
		)
	}

	i++

	alg64, err := strconv.ParseUint(fields[i], 10, 8)
	if err != nil {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: invalid algorithm %q: %w",
			fields[i],
			err,
		)
	}

	i++

	// Remaining fields are base64 key material, possibly split across tokens.
	// Strip BIND-style inline comments (;{...}).
	var keyParts []string

	for _, f := range fields[i:] {
		if strings.HasPrefix(f, ";") {
			break
		}

		keyParts = append(keyParts, f)
	}

	keyB64 := strings.Join(keyParts, "")

	pubKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf(
			"crypto: DNSKEY: invalid base64 public key: %w",
			err,
		)
	}

	return &DNSKEYRecord{
		Owner:     owner,
		TTL:       uint32(ttl64),
		Flags:     uint16(flags64),
		Protocol:  uint8(proto64),
		Algorithm: uint8(alg64),
		PublicKey: pubKey,
	}, nil
}

// IsKSK reports whether this key is a Key Signing Key (flags == 257).
func (k *DNSKEYRecord) IsKSK() bool { return k.Flags == 257 }

// IsZSK reports whether this key is a Zone Signing Key (flags == 256).
func (k *DNSKEYRecord) IsZSK() bool { return k.Flags == 256 }

// KeyTag computes the DNSKEY key tag per RFC 4034 Appendix B.
// The key tag is used in RRSIG records to identify the signing key.
func (k *DNSKEYRecord) KeyTag() uint16 {
	// Algorithm 1 (RSAMD5) uses the last two bytes of the public key as the
	// key tag; all other algorithms use the checksum below.
	if k.Algorithm == 1 {
		n := len(k.PublicKey)
		if n < 2 {
			return 0
		}

		return binary.BigEndian.Uint16(k.PublicKey[n-2:])
	}

	wire := make([]byte, 4+len(k.PublicKey))
	binary.BigEndian.PutUint16(wire[0:2], k.Flags)
	wire[2] = k.Protocol
	wire[3] = k.Algorithm
	copy(wire[4:], k.PublicKey)

	var ac uint32

	for i, b := range wire {
		if i%2 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}

	ac += ac >> 16

	return uint16(ac & 0xFFFF)
}
