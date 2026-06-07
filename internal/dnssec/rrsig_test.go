// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"strings"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func TestSignRRset_ARecord(t *testing.T) {
	_, zsk := loadTestKeys(t)
	aRR := makeA("www.xfx1.de.")
	opts := DefaultRRSIGOpts(0)

	rrsig, err := SignRRset([]*rec.RR{aRR}, zsk, opts)
	if err != nil {
		t.Fatalf("SignRRset: %v", err)
	}

	if rrsig.TypeCovered != rec.RRtypeToWire[rec.TypeA] {
		t.Errorf(
			"TypeCovered: got %d, want %d",
			rrsig.TypeCovered,
			rec.RRtypeToWire[rec.TypeA],
		)
	}

	if rrsig.Algorithm != 15 {
		t.Errorf("Algorithm: got %d, want 15", rrsig.Algorithm)
	}

	if rrsig.Labels != 3 { // www.xfx1.de. = 3 labels
		t.Errorf("Labels: got %d, want 3", rrsig.Labels)
	}

	if rrsig.OrigTTL != 300 {
		t.Errorf("OrigTTL: got %d, want 300", rrsig.OrigTTL)
	}

	if rrsig.KeyTag == 0 {
		t.Error("KeyTag is 0")
	}

	if len(rrsig.Signature) != 64 { // ED25519 signature is always 64 bytes
		t.Errorf("Signature length: got %d, want 64", len(rrsig.Signature))
	}

	if !strings.HasSuffix(rrsig.SignerName, ".") {
		t.Errorf("SignerName missing trailing dot: %q", rrsig.SignerName)
	}
}

func TestSignRRset_DNSKEYWithKSK(t *testing.T) {
	ksk, _ := loadTestKeys(t)
	zone := testZone()
	dkRR := &rec.RR{
		Name:   zone,
		RRtype: rec.TypeDNSKEY,
		TTL:    rec.RRttl(60),
		Opts: &rec.RRoptsDNSKEY{
			Flags:     ksk.DNSKEY.Flags,
			Protocol:  ksk.DNSKEY.Protocol,
			Algorithm: ksk.DNSKEY.Algorithm,
			PublicKey: ksk.DNSKEY.PublicKey,
		},
	}

	rrsig, err := SignRRset([]*rec.RR{dkRR}, ksk, DefaultRRSIGOpts(0))
	if err != nil {
		t.Fatalf("SignRRset DNSKEY: %v", err)
	}

	if rrsig.TypeCovered != rec.RRtypeToWire[rec.TypeDNSKEY] {
		t.Errorf(
			"TypeCovered: got %d, want DNSKEY wire type",
			rrsig.TypeCovered,
		)
	}
}

func TestSignRRset_EmptyRRset(t *testing.T) {
	_, zsk := loadTestKeys(t)

	_, err := SignRRset(nil, zsk, DefaultRRSIGOpts(0))
	if err == nil {
		t.Fatal("expected error for empty RRset")
	}
}

func TestDefaultRRSIGOpts_ExpirationAfterInception(t *testing.T) {
	opts := DefaultRRSIGOpts(0)
	want := uint32(7 * 24 * 3600)
	got := opts.Expiration - opts.Inception

	if got != want {
		t.Errorf("Expiration-Inception: got %d, want %d", got, want)
	}
}

func TestSignDB_RRSIGsProduced(t *testing.T) {
	zone := testZone()
	ksk, zsk := loadTestKeys(t)

	dkRR := &rec.RR{
		Name:   zone,
		RRtype: rec.TypeDNSKEY,
		TTL:    rec.RRttl(60),
		Opts: &rec.RRoptsDNSKEY{
			Flags:     ksk.DNSKEY.Flags,
			Protocol:  ksk.DNSKEY.Protocol,
			Algorithm: ksk.DNSKEY.Algorithm,
			PublicKey: ksk.DNSKEY.PublicKey,
		},
	}
	records := []*rec.RR{
		makeSOA(zone),
		makeNS(zone),
		makeA("www.xfx1.de."),
		dkRR,
	}
	d := db.NewDB(zone, records)

	rrsigs, err := SignDB(d, []*SigningKey{ksk, zsk}, 0)
	if err != nil {
		t.Fatalf("SignDB: %v", err)
	}

	if len(rrsigs) == 0 {
		t.Fatal("expected RRSIGs, got none")
	}

	var hasDNSKEYSig, hasASig bool

	for _, rr := range rrsigs {
		opts := rr.Opts.(*rec.RRoptsRRSIG)
		if opts.TypeCovered == rec.RRtypeToWire[rec.TypeDNSKEY] {
			hasDNSKEYSig = true
		}

		if opts.TypeCovered == rec.RRtypeToWire[rec.TypeA] {
			hasASig = true
		}
	}

	if !hasDNSKEYSig {
		t.Error("expected RRSIG for DNSKEY RRset")
	}

	if !hasASig {
		t.Error("expected RRSIG for A RRset")
	}
}

func TestSignDB_KSKOnly(t *testing.T) {
	zone := testZone()
	ksk, _ := loadTestKeys(t)

	dkRR := &rec.RR{
		Name:   zone,
		RRtype: rec.TypeDNSKEY,
		TTL:    rec.RRttl(60),
		Opts: &rec.RRoptsDNSKEY{
			Flags:     ksk.DNSKEY.Flags,
			Protocol:  ksk.DNSKEY.Protocol,
			Algorithm: ksk.DNSKEY.Algorithm,
			PublicKey: ksk.DNSKEY.PublicKey,
		},
	}
	records := []*rec.RR{
		makeSOA(zone),
		makeNS(zone),
		makeA("www.xfx1.de."),
		dkRR,
	}
	d := db.NewDB(zone, records)

	rrsigs, err := SignDB(d, []*SigningKey{ksk}, 0)
	if err != nil {
		t.Fatalf("SignDB KSK-only: %v", err)
	}

	var hasDNSKEYSig, hasSOASig, hasASig bool

	for _, rr := range rrsigs {
		opts := rr.Opts.(*rec.RRoptsRRSIG)
		switch opts.TypeCovered {
		case rec.RRtypeToWire[rec.TypeDNSKEY]:
			hasDNSKEYSig = true
		case rec.RRtypeToWire[rec.TypeSOA]:
			hasSOASig = true
		case rec.RRtypeToWire[rec.TypeA]:
			hasASig = true
		}
	}

	if !hasDNSKEYSig {
		t.Error("KSK-only: expected RRSIG for DNSKEY RRset")
	}

	if !hasSOASig {
		t.Error(
			"KSK-only: expected RRSIG for SOA RRset (KSK must sign all RRsets when no ZSK)",
		)
	}

	if !hasASig {
		t.Error(
			"KSK-only: expected RRSIG for A RRset (KSK must sign all RRsets when no ZSK)",
		)
	}
}

func TestCountLabels(t *testing.T) {
	cases := []struct {
		input rec.Domain
		want  uint8
	}{
		{"xfx1.de.", 2},
		{"www.xfx1.de.", 3},
		{"a.b.c.xfx1.de.", 5},
		{"*.xfx1.de.", 2}, // wildcard label excluded per RFC 4034 §3.1.3
	}
	for _, tc := range cases {
		if got := countLabels(tc.input); got != tc.want {
			t.Errorf("countLabels(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestEcdsaErrorPaths(t *testing.T) {
	t.Run("DERToFixedSize_unsupported_algorithm", func(t *testing.T) {
		_, err := ecdsaDERToFixedSize(
			[]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02},
			99,
		)
		if err == nil {
			t.Error("expected error for unsupported algorithm, got nil")
		}
	})

	t.Run("FixedSizeToDER_unsupported_algorithm", func(t *testing.T) {
		_, err := ECDSAFixedSizeToDER(make([]byte, 64), 99)
		if err == nil {
			t.Error("expected error for unsupported algorithm, got nil")
		}
	})

	t.Run("FixedSizeToDER_wrong_size", func(t *testing.T) {
		// Algorithm 13 expects 64 bytes (32+32); passing 32 must fail.
		_, err := ECDSAFixedSizeToDER(make([]byte, 32), 13)
		if err == nil {
			t.Error("expected error for wrong size, got nil")
		}
	})
}

func TestECDSADERRoundTrip(t *testing.T) {
	r := make([]byte, 32)
	s := make([]byte, 32)
	r[0] = 0x01
	r[31] = 0xff
	s[0] = 0x02
	s[31] = 0xee
	fixed := append(r, s...)

	der, err := ECDSAFixedSizeToDER(fixed, 13)
	if err != nil {
		t.Fatalf("ECDSAFixedSizeToDER: %v", err)
	}

	back, err := ecdsaDERToFixedSize(der, 13)
	if err != nil {
		t.Fatalf("ecdsaDERToFixedSize: %v", err)
	}

	if string(fixed) != string(back) {
		t.Errorf("round-trip failed:\n  orig: %x\n  back: %x", fixed, back)
	}
}

func TestSignRRset_VerifySignature(t *testing.T) {
	_, zsk := loadTestKeys(t)
	aRR := makeA("www.xfx1.de.")
	opts := DefaultRRSIGOpts(0)

	rrsig, err := SignRRset([]*rec.RR{aRR}, zsk, opts)
	if err != nil {
		t.Fatalf("SignRRset: %v", err)
	}

	ok, err := verifyRRSIG(rrsig, []*rec.RR{aRR}, zsk)
	if err != nil {
		t.Fatalf("verifyRRSIG: %v", err)
	}

	if !ok {
		t.Fatal("signature verification failed")
	}
}

func TestSignRRset_VerifySignature_TamperedData(t *testing.T) {
	_, zsk := loadTestKeys(t)
	aRR := makeA("www.xfx1.de.")
	opts := DefaultRRSIGOpts(0)

	rrsig, err := SignRRset([]*rec.RR{aRR}, zsk, opts)
	if err != nil {
		t.Fatalf("SignRRset: %v", err)
	}

	differentRR := makeA("other.xfx1.de.")

	ok, err := verifyRRSIG(rrsig, []*rec.RR{differentRR}, zsk)
	if err != nil {
		t.Fatalf("verifyRRSIG: %v", err)
	}

	if ok {
		t.Fatal("expected verification to fail with tampered data")
	}
}
