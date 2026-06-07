// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"strings"
	"testing"
)

func TestCRName_SimpleA(t *testing.T) {
	name, err := CRName("rfc2136", "A", "example.com.", []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// source-rrtype-sanitized-hash
	if !strings.HasPrefix(name, "rfc2136-a-example-com-") {
		t.Errorf("unexpected name: %s", name)
	}
}

func TestCRName_ACMEChallengeTXT(t *testing.T) {
	rdata := []byte("abc123")

	name, err := CRName("rfc2136", "TXT", "_acme-challenge.example.com.", rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// underscore and leading hyphen stripped: "_acme-challenge" → "acme-challenge"
	if !strings.HasPrefix(name, "rfc2136-txt-acme-challenge-example-com-") {
		t.Errorf("unexpected name: %s", name)
	}
}

func TestCRName_Idempotent(t *testing.T) {
	rdata := []byte{192, 168, 1, 1}
	name1, _ := CRName("rfc2136", "A", "host.example.com.", rdata)
	name2, _ := CRName("rfc2136", "A", "host.example.com.", rdata)

	if name1 != name2 {
		t.Errorf("not idempotent: %s != %s", name1, name2)
	}
}

func TestCRName_DifferentRdataDifferentHash(t *testing.T) {
	name1, _ := CRName("rfc2136", "A", "host.example.com.", []byte{1, 2, 3, 4})
	name2, _ := CRName("rfc2136", "A", "host.example.com.", []byte{5, 6, 7, 8})

	if name1 == name2 {
		t.Error("different rdata should produce different names")
	}
}

func TestCRName_Overflow(t *testing.T) {
	// build an FQDN that when sanitized will push the name past 253 chars
	// "rfc2136-txt-" (12) + label (240) + "-example-com-" (13) + hash (8) = 273 chars
	longLabel := strings.Repeat("a", 240)
	fqdn := longLabel + ".example.com."

	_, err := CRName("rfc2136", "TXT", fqdn, []byte("data"))
	if err == nil {
		t.Fatal("expected overflow error, got nil")
	}
}

func TestCRName_DotToHyphenAndLowercase(t *testing.T) {
	name, err := CRName("rfc2136", "A", "FOO.BAR.COM.", []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(name, "rfc2136-a-foo-bar-com-") {
		t.Errorf("expected lowercased hyphenated name, got: %s", name)
	}
}

func TestCRName_TrailingDotStripped(t *testing.T) {
	nameWith, _ := CRName(
		"rfc2136",
		"A",
		"host.example.com.",
		[]byte{1, 2, 3, 4},
	)
	nameWithout, _ := CRName(
		"rfc2136",
		"A",
		"host.example.com",
		[]byte{1, 2, 3, 4},
	)
	// Both should produce same sanitized component since we strip the trailing dot
	if nameWith != nameWithout {
		t.Errorf(
			"trailing dot should be stripped: %s != %s",
			nameWith,
			nameWithout,
		)
	}
}
