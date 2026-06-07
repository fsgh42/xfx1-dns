// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import "testing"

func TestLoadKeys_ValidKSKAndZSK(t *testing.T) {
	secrets := []KeySecret{
		{KeyType: "ksk", PrivateKey: testPrivKey},
		{KeyType: "zsk", PrivateKey: testPrivKey},
	}

	keys, err := LoadKeys(secrets, testZone())
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	if !keys[0].IsKSK() {
		t.Error("first key should be KSK (flags=257)")
	}

	if !keys[1].IsZSK() {
		t.Error("second key should be ZSK (flags=256)")
	}
}

func TestLoadKeys_InvalidKeyType(t *testing.T) {
	secrets := []KeySecret{
		{KeyType: "tsig", PrivateKey: testPrivKey},
	}

	_, err := LoadKeys(secrets, testZone())
	if err == nil {
		t.Fatal("expected error for invalid keyType, got nil")
	}
}

func TestLoadKeys_MalformedPrivateKey(t *testing.T) {
	secrets := []KeySecret{
		{KeyType: "ksk", PrivateKey: "not a valid key"},
	}

	_, err := LoadKeys(secrets, testZone())
	if err == nil {
		t.Fatal("expected error for malformed private key")
	}
}

func TestLoadKeys_Empty(t *testing.T) {
	keys, err := LoadKeys(nil, testZone())
	if err != nil {
		t.Fatalf("expected no error for empty list, got: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("expected empty slice, got %d keys", len(keys))
	}
}
