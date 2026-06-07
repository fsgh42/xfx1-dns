// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// Test vectors from internal/crypto/crypto_test.go — same key pair.
const (
	testPrivKey = "Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\nPrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI="
)

func mustDomain(s string) rec.Domain {
	d, err := rec.NewDomain(s)
	if err != nil {
		panic(err)
	}

	return d
}

func testZone() rec.Domain { return mustDomain("xfx1.de.") }

func makeSOA(zone rec.Domain) *rec.RR {
	return &rec.RR{
		Name:   zone,
		RRtype: rec.TypeSOA,
		TTL:    rec.RRttl(3600),
		Opts: &rec.RRoptsSOA{
			Mname:   mustDomain("ns1.xfx1.de."),
			Rname:   mustDomain("hostmaster.xfx1.de."),
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minimum: 300,
		},
	}
}

func makeNS(zone rec.Domain) *rec.RR {
	return &rec.RR{
		Name:   zone,
		RRtype: rec.TypeNS,
		TTL:    rec.RRttl(3600),
		Opts:   &rec.RRoptsNS{Ns: mustDomain("ns1.xfx1.de.")},
	}
}

func makeA(name string) *rec.RR {
	return &rec.RR{
		Name:   mustDomain(name),
		RRtype: rec.TypeA,
		TTL:    rec.RRttl(300),
		Opts:   &rec.RRoptsA{Target: []byte{1, 2, 3, 4}},
	}
}

func loadTestKeys(t *testing.T) (*SigningKey, *SigningKey) {
	t.Helper()

	kskSecrets := []KeySecret{{KeyType: "ksk", PrivateKey: testPrivKey}}

	ksk, err := LoadKeys(kskSecrets, testZone())
	if err != nil {
		t.Fatalf("LoadKeys KSK: %v", err)
	}

	zskSecrets := []KeySecret{{KeyType: "zsk", PrivateKey: testPrivKey}}

	zsk, err := LoadKeys(zskSecrets, testZone())
	if err != nil {
		t.Fatalf("LoadKeys ZSK: %v", err)
	}

	return ksk[0], zsk[0]
}
