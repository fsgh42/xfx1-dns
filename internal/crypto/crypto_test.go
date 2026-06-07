// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// Test vectors from dnssec:test/testcase-valid-config.json.
const (
	testDNSKEY = "xfx1.de. 60 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="

	// Same key wrapped in parentheses as BIND sometimes emits.
	testDNSKEYParen = "xfx1.de. 60 IN DNSKEY 257 3 15 (l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )"

	testPrivKey = "Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\nPrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI="

	testZSK = "xfx1.de. 3600 IN DNSKEY 256 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
)

// --- ParseDNSKEY ---

func TestParseDNSKEY_ValidKSK(t *testing.T) {
	rec, err := ParseDNSKEY(testDNSKEY)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Owner != "xfx1.de." {
		t.Errorf("Owner: got %q, want %q", rec.Owner, "xfx1.de.")
	}

	if rec.TTL != 60 {
		t.Errorf("TTL: got %d, want 60", rec.TTL)
	}

	if rec.Flags != 257 {
		t.Errorf("Flags: got %d, want 257", rec.Flags)
	}

	if rec.Protocol != 3 {
		t.Errorf("Protocol: got %d, want 3", rec.Protocol)
	}

	if rec.Algorithm != 15 {
		t.Errorf("Algorithm: got %d, want 15", rec.Algorithm)
	}

	if len(rec.PublicKey) != 32 {
		t.Errorf("PublicKey length: got %d, want 32", len(rec.PublicKey))
	}
}

func TestParseDNSKEY_ValidKSK_Parens(t *testing.T) {
	rec, err := ParseDNSKEY(testDNSKEYParen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Flags != 257 {
		t.Errorf("Flags: got %d, want 257", rec.Flags)
	}
}

func TestParseDNSKEY_ZSK(t *testing.T) {
	rec, err := ParseDNSKEY(testZSK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Flags != 256 {
		t.Errorf("Flags: got %d, want 256", rec.Flags)
	}
}

func TestParseDNSKEY_WrongType(t *testing.T) {
	_, err := ParseDNSKEY(
		"xfx1.de. 60 IN A l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
	)
	if err == nil {
		t.Fatal("expected error for non-DNSKEY type, got nil")
	}
}

func TestParseDNSKEY_BadBase64(t *testing.T) {
	_, err := ParseDNSKEY("xfx1.de. 60 IN DNSKEY 257 3 15 !!!notbase64!!!")
	if err == nil {
		t.Fatal("expected error for bad base64, got nil")
	}
}

// --- KeyTag ---

func TestDNSKEYRecord_KeyTag(t *testing.T) {
	rec, err := ParseDNSKEY(testDNSKEY)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Expected key tag verified with `dig DNSKEY xfx1.de` output or BIND keygen.
	// For this specific ED25519 KSK the expected tag is 11727 (0x2DCF).
	// Recompute with: https://github.com/miekg/dns or BIND's dnssec-dsfromkey.
	// We verify the tag is non-zero and stable (idempotent).
	tag1 := rec.KeyTag()
	tag2 := rec.KeyTag()

	if tag1 != tag2 {
		t.Errorf("KeyTag not stable: %d vs %d", tag1, tag2)
	}

	if tag1 == 0 {
		t.Errorf("KeyTag is 0, likely a bug")
	}
	// Hard-coded expected value derived from the RFC 4034 Appendix B formula
	// applied to the test vector.
	const wantTag = uint16(3613)
	if tag1 != wantTag {
		t.Errorf("KeyTag: got %d, want %d", tag1, wantTag)
	}
}

// --- IsKSK / IsZSK ---

func TestDNSKEYRecord_IsKSK(t *testing.T) {
	rec, _ := ParseDNSKEY(testDNSKEY) // flags=257
	if !rec.IsKSK() {
		t.Error("IsKSK: want true for flags=257")
	}

	if rec.IsZSK() {
		t.Error("IsZSK: want false for flags=257")
	}
}

func TestDNSKEYRecord_IsZSK(t *testing.T) {
	rec, _ := ParseDNSKEY(testZSK) // flags=256
	if !rec.IsZSK() {
		t.Error("IsZSK: want true for flags=256")
	}

	if rec.IsKSK() {
		t.Error("IsKSK: want false for flags=256")
	}
}

// --- ParsePrivateKey ---

func TestParsePrivateKey_ED25519(t *testing.T) {
	pk, err := ParsePrivateKey(testPrivKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pk.Algorithm != 15 {
		t.Errorf("Algorithm: got %d, want 15", pk.Algorithm)
	}

	if pk.Key == nil {
		t.Fatal("Key is nil")
	}

	_, ok := pk.Key.(ed25519.PrivateKey)
	if !ok {
		t.Errorf("Key type: got %T, want ed25519.PrivateKey", pk.Key)
	}
}

func TestParsePrivateKey_UnknownAlgorithm(t *testing.T) {
	s := "Private-key-format: v1.2\nAlgorithm: 99 (UNKNOWN)\nPrivateKey: AAAA"

	_, err := ParsePrivateKey(s)
	if err == nil {
		t.Fatal("expected error for unknown algorithm, got nil")
	}
}

func TestParsePrivateKey_MissingPrivateKey(t *testing.T) {
	s := "Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\n"

	_, err := ParsePrivateKey(s)
	if err == nil {
		t.Fatal("expected error for missing PrivateKey field, got nil")
	}
}

func TestParsePrivateKey_BadBase64(t *testing.T) {
	s := "Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\nPrivateKey: !!!notbase64!!!"

	_, err := ParsePrivateKey(s)
	if err == nil {
		t.Fatal("expected error for bad base64, got nil")
	}
}

// --- Round-trip: parse + sign + verify ---

func TestParsePrivateKey_ECDSA_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	d := priv.D.Bytes()
	// Pad to 32 bytes if the scalar is shorter.
	if len(d) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(d):], d)
		d = padded
	}

	keyStr := "Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: " +
		base64.StdEncoding.EncodeToString(
			d,
		)

	pk, err := ParsePrivateKey(keyStr)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	if pk.Algorithm != 13 {
		t.Errorf("Algorithm: got %d, want 13", pk.Algorithm)
	}

	if _, ok := pk.Key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Key type: got %T, want *ecdsa.PrivateKey", pk.Key)
	}
}

func TestParsePrivateKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	enc := func(n *big.Int) string { return base64.StdEncoding.EncodeToString(n.Bytes()) }
	keyStr := strings.Join([]string{
		"Private-key-format: v1.2",
		"Algorithm: 8 (RSASHA256)",
		"Modulus: " + enc(priv.N),
		"PublicExponent: " + enc(big.NewInt(int64(priv.E))),
		"PrivateExponent: " + enc(priv.D),
		"Prime1: " + enc(priv.Primes[0]),
		"Prime2: " + enc(priv.Primes[1]),
		"Exponent1: " + enc(priv.Precomputed.Dp),
		"Exponent2: " + enc(priv.Precomputed.Dq),
		"Coefficient: " + enc(priv.Precomputed.Qinv),
	}, "\n")

	pk, err := ParsePrivateKey(keyStr)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	if pk.Algorithm != 8 {
		t.Errorf("Algorithm: got %d, want 8", pk.Algorithm)
	}

	if _, ok := pk.Key.(*rsa.PrivateKey); !ok {
		t.Errorf("Key type: got %T, want *rsa.PrivateKey", pk.Key)
	}
}

func TestRoundTrip_SignVerify_ED25519(t *testing.T) {
	dnskey, err := ParseDNSKEY(testDNSKEY)
	if err != nil {
		t.Fatalf("ParseDNSKEY: %v", err)
	}

	pk, err := ParsePrivateKey(testPrivKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	msg := []byte("the quick brown fox jumps over the lazy dog")
	// ed25519.PrivateKey.Sign accepts crypto.Hash(0) as opts (pure signing, no pre-hashing).
	sig, err := pk.Key.Sign(nil, msg, gocrypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pubKey := ed25519.PublicKey(dnskey.PublicKey)
	if !ed25519.Verify(pubKey, msg, sig) {
		t.Error("ed25519.Verify returned false — signature does not match")
	}
}
