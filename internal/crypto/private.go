// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// PrivateKey is a parsed private key ready for signing.
type PrivateKey struct {
	Algorithm uint8 // 8=RSASHA256, 13=ECDSAP256SHA256, 14=ECDSAP384SHA384, 15=ED25519
	Key       gocrypto.Signer
}

// ParsePrivateKey parses a BIND-format private key string.
// Supports algorithms 8 (RSASHA256), 13 (ECDSAP256SHA256),
// 14 (ECDSAP384SHA384), and 15 (ED25519).
func ParsePrivateKey(s string) (*PrivateKey, error) {
	fields := parseKV(s)

	fmtVal, ok := fields["Private-key-format"]
	if !ok {
		return nil, fmt.Errorf(
			"crypto: private key: missing Private-key-format field",
		)
	}

	if !strings.HasPrefix(fmtVal, "v1") {
		return nil, fmt.Errorf(
			"crypto: private key: unsupported format %q",
			fmtVal,
		)
	}

	algStr, ok := fields["Algorithm"]
	if !ok {
		return nil, fmt.Errorf("crypto: private key: missing Algorithm field")
	}
	// Algorithm field is "<num> (<name>)" — take the first token.
	algNum, err := parseAlgNum(algStr)
	if err != nil {
		return nil, err
	}

	switch algNum {
	case 15:
		return parseED25519(fields)
	case 13:
		return parseECDSA(fields, elliptic.P256(), 13)
	case 14:
		return parseECDSA(fields, elliptic.P384(), 14)
	case 8:
		return parseRSA(fields)
	default:
		return nil, fmt.Errorf(
			"crypto: private key: unsupported algorithm %d",
			algNum,
		)
	}
}

// parseKV splits a BIND key file into a map of trimmed Key→Value pairs.
// Unknown keys are silently retained; duplicate keys use the last value.
func parseKV(s string) map[string]string {
	m := make(map[string]string)

	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		m[key] = val
	}

	return m
}

func parseAlgNum(s string) (uint8, error) {
	tok := strings.Fields(s)
	if len(tok) == 0 {
		return 0, fmt.Errorf("crypto: private key: empty Algorithm field")
	}

	var n uint8

	_, err := fmt.Sscanf(tok[0], "%d", &n)
	if err != nil {
		return 0, fmt.Errorf(
			"crypto: private key: invalid algorithm %q: %w",
			tok[0],
			err,
		)
	}

	return n, nil
}

func decodeB64Field(fields map[string]string, name string) ([]byte, error) {
	v, ok := fields[name]
	if !ok {
		return nil, fmt.Errorf("crypto: private key: missing field %q", name)
	}

	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf(
			"crypto: private key: field %q: invalid base64: %w",
			name,
			err,
		)
	}

	return b, nil
}

func decodeBigInt(fields map[string]string, name string) (*big.Int, error) {
	b, err := decodeB64Field(fields, name)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}

func parseED25519(fields map[string]string) (*PrivateKey, error) {
	seed, err := decodeB64Field(fields, "PrivateKey")
	if err != nil {
		return nil, err
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf(
			"crypto: private key: ED25519 seed must be %d bytes, got %d",
			ed25519.SeedSize,
			len(seed),
		)
	}

	key := ed25519.NewKeyFromSeed(seed)

	return &PrivateKey{Algorithm: 15, Key: key}, nil
}

func parseECDSA(
	fields map[string]string,
	curve elliptic.Curve,
	alg uint8,
) (*PrivateKey, error) {
	scalar, err := decodeB64Field(fields, "PrivateKey")
	if err != nil {
		return nil, err
	}

	// ecdsa.ParseRawPrivateKey (added in Go 1.24) derives the public key point
	// internally — no manual ScalarBaseMult needed.
	priv, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	if err != nil {
		return nil, fmt.Errorf(
			"crypto: private key: ECDSA alg %d: %w",
			alg,
			err,
		)
	}

	return &PrivateKey{Algorithm: alg, Key: priv}, nil
}

func parseRSA(fields map[string]string) (*PrivateKey, error) {
	n, err := decodeBigInt(fields, "Modulus")
	if err != nil {
		return nil, err
	}

	ePub, err := decodeBigInt(fields, "PublicExponent")
	if err != nil {
		return nil, err
	}

	d, err := decodeBigInt(fields, "PrivateExponent")
	if err != nil {
		return nil, err
	}

	p1, err := decodeBigInt(fields, "Prime1")
	if err != nil {
		return nil, err
	}

	p2, err := decodeBigInt(fields, "Prime2")
	if err != nil {
		return nil, err
	}

	exp1, err := decodeBigInt(fields, "Exponent1")
	if err != nil {
		return nil, err
	}

	exp2, err := decodeBigInt(fields, "Exponent2")
	if err != nil {
		return nil, err
	}

	coeff, err := decodeBigInt(fields, "Coefficient")
	if err != nil {
		return nil, err
	}

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(ePub.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p1, p2},
		Precomputed: rsa.PrecomputedValues{
			Dp:        exp1,
			Dq:        exp2,
			Qinv:      coeff,
			CRTValues: []rsa.CRTValue{},
		},
	}
	priv.Precompute()

	return &PrivateKey{Algorithm: 8, Key: priv}, nil
}
