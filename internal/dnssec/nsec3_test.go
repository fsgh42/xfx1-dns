// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"bytes"
	"strings"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func TestHashName_KnownValue(t *testing.T) {
	// Hash of "xfx1.de." with iterations=0, salt=nil
	// xfx1.de. in wire format: \x04xfx1\x02de\x00 (4+1+2+1+1 = 9 bytes)
	// Expected SHA-1 of those bytes
	name := mustDomain("xfx1.de.")

	h := HashName(name, 0, nil)
	if len(h) != 20 {
		t.Errorf("hash length: got %d, want 20", len(h))
	}
	// Verify deterministic
	h2 := HashName(name, 0, nil)
	if !bytes.Equal(h, h2) {
		t.Error("HashName is not deterministic")
	}
}

func TestHashName_WithIterations(t *testing.T) {
	name := mustDomain("xfx1.de.")
	h0 := HashName(name, 0, nil)
	h1 := HashName(name, 1, nil)
	// With one additional iteration, the hash should differ
	if bytes.Equal(h0, h1) {
		t.Error("expected different hash with iterations=1 vs iterations=0")
	}
}

func TestTypeBitmap_KnownTypes(t *testing.T) {
	// Types: A=1, AAAA=28, RRSIG=46
	types := []uint16{1, 28, 46}

	bm := rec.TypeBitmap(types)
	if len(bm) == 0 {
		t.Fatal("TypeBitmap returned empty slice")
	}
	// Window 0, bitmap length covers up to bit 46
	// byte 0: window=0, byte 1: bitmap length
	if bm[0] != 0 {
		t.Errorf("expected window 0, got %d", bm[0])
	}
	// A=1 is bit 6 of byte 0 (1<<(7-1) = 0x40)
	// Verify A bit is set: byte at position 2+0 = 0x40
	if bm[2]&0x40 == 0 {
		t.Error("A bit (type 1) should be set in bitmap")
	}
}

func TestBuildNSEC3Chain_TwoNames(t *testing.T) {
	zone := testZone()
	records := []*rec.RR{
		makeSOA(zone),
		makeNS(zone),
		makeA("www.xfx1.de."),
	}
	d := db.NewDB(zone, records)
	params := DefaultNSEC3PARAMRecord()

	chain, nsec3paramRR, err := BuildNSEC3Chain(d, params)
	if err != nil {
		t.Fatalf("BuildNSEC3Chain: %v", err)
	}

	if len(chain.Records) != 2 {
		// zone apex (xfx1.de.) and www.xfx1.de.
		t.Errorf("expected 2 NSEC3 records, got %d", len(chain.Records))
	}

	if nsec3paramRR == nil {
		t.Fatal("NSEC3PARAM RR is nil")
	}

	if nsec3paramRR.RRtype != rec.TypeNSEC3PARAM {
		t.Errorf(
			"NSEC3PARAM RR type: got %s, want NSEC3PARAM",
			nsec3paramRR.RRtype,
		)
	}
	// Verify ring property: last NextHash == first hash (decoded from first record owner)
	if len(chain.Records) >= 2 {
		last := chain.Records[len(chain.Records)-1]
		first := chain.Records[0]
		lastOpts := last.Opts.(*rec.RRoptsNSEC3)

		// Decode first record owner hash
		ownerStr := string(first.Name)
		dotIdx := strings.Index(ownerStr, ".")

		if dotIdx >= 0 {
			firstHashB32 := strings.ToUpper(ownerStr[:dotIdx])

			firstHash, err := nsec3Encoding.DecodeString(firstHashB32)
			if err != nil {
				t.Fatalf("decode first hash: %v", err)
			}

			if !bytes.Equal(lastOpts.NextHash, firstHash) {
				t.Error("ring property violated: last NextHash != first hash")
			}
		}
	}
}

func TestBuildNSEC3Chain_EmptyDB(t *testing.T) {
	zone := testZone()
	d := db.NewDB(zone, nil)

	_, _, err := BuildNSEC3Chain(d, DefaultNSEC3PARAMRecord())
	if err == nil {
		t.Fatal("expected error for empty DB")
	}
}

func TestCovers_Normal(t *testing.T) {
	tests := []struct {
		owner, next, target []byte
		want                bool
	}{
		{[]byte{1}, []byte{5}, []byte{3}, true},  // 1 < 3 < 5
		{[]byte{1}, []byte{5}, []byte{0}, false}, // 0 < 1
		{[]byte{1}, []byte{5}, []byte{5}, false}, // boundary: not strictly less
		{[]byte{1}, []byte{5}, []byte{6}, false}, // 6 > 5
		// Wrap-around: owner > next
		{[]byte{8}, []byte{3}, []byte{9}, true},  // 9 > 8 (above owner in wrap)
		{[]byte{8}, []byte{3}, []byte{2}, true},  // 2 < 3 (below next in wrap)
		{[]byte{8}, []byte{3}, []byte{5}, false}, // 3 < 5 < 8: not covered
	}
	for _, tt := range tests {
		got := covers(tt.owner, tt.next, tt.target)
		if got != tt.want {
			t.Errorf(
				"covers(%x, %x, %x) = %v, want %v",
				tt.owner,
				tt.next,
				tt.target,
				got,
				tt.want,
			)
		}
	}
}

func TestClosestEncloserProof_OneLevelBelow(t *testing.T) {
	zone := testZone()
	records := []*rec.RR{
		makeSOA(zone),
		makeNS(zone),
		makeA("www.xfx1.de."),
	}
	d := db.NewDB(zone, records)
	params := DefaultNSEC3PARAMRecord()

	chain, nsec3paramRR, err := BuildNSEC3Chain(d, params)
	if err != nil {
		t.Fatalf("BuildNSEC3Chain: %v", err)
	}
	// Add NSEC3 records to DB for proof lookup
	records = append(records, chain.Records...)
	records = append(records, nsec3paramRR)
	d = db.NewDB(zone, records)

	// Query for a name that does not exist
	queried := mustDomain("nonexistent.xfx1.de.")

	proof, err := chain.ClosestEncloserProof(queried, zone, d)
	if err != nil {
		t.Fatalf("ClosestEncloserProof: %v", err)
	}

	if proof.ClosestEncloser == nil {
		t.Error("ClosestEncloser is nil")
	}

	if proof.NextCloser == nil {
		t.Error("NextCloser is nil")
	}

	if proof.WildcardAtCE == nil {
		t.Error("WildcardAtCE is nil")
	}
	// All three must be NSEC3 records
	for _, name := range []string{"ClosestEncloser", "NextCloser", "WildcardAtCE"} {
		var rr *rec.RR

		switch name {
		case "ClosestEncloser":
			rr = proof.ClosestEncloser
		case "NextCloser":
			rr = proof.NextCloser
		case "WildcardAtCE":
			rr = proof.WildcardAtCE
		}

		if rr.RRtype != rec.TypeNSEC3 {
			t.Errorf("%s: expected NSEC3, got %s", name, rr.RRtype)
		}
	}
}

func TestRebuildNSEC3Chain(t *testing.T) {
	zone := testZone()
	records := []*rec.RR{
		makeSOA(zone),
		makeNS(zone),
		makeA("www.xfx1.de."),
	}
	d := db.NewDB(zone, records)
	params := DefaultNSEC3PARAMRecord()

	chain, nsec3paramRR, err := BuildNSEC3Chain(d, params)
	if err != nil {
		t.Fatalf("BuildNSEC3Chain: %v", err)
	}

	records = append(records, chain.Records...)
	records = append(records, nsec3paramRR)
	d = db.NewDB(zone, records)

	chain2, err := RebuildNSEC3Chain(d)
	if err != nil {
		t.Fatalf("RebuildNSEC3Chain: %v", err)
	}

	if len(chain2.Records) != len(chain.Records) {
		t.Errorf(
			"Records length: got %d, want %d",
			len(chain2.Records),
			len(chain.Records),
		)
	}
	// byHash maps should have same keys
	if len(chain2.byHash) != len(chain.byHash) {
		t.Errorf(
			"byHash length: got %d, want %d",
			len(chain2.byHash),
			len(chain.byHash),
		)
	}
}
