// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"net"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// responseTestDB builds a minimal zone used across response_test.go.
//
// Records:
//   - z.            SOA
//   - a.z.          A 1.2.3.4
//   - ns.z.         NS ns.z. (self-referential, for LookupAdditional coverage)
//   - alias.z.      CNAME target.invalid. (off-zone target)
//   - *.z.          A 10.0.0.1
func responseTestDB() *db.DB {
	zone := rec.Domain("z.")

	return db.NewDB(zone, []*rec.RR{
		rec.NewRR("z.", &rec.RRoptsSOA{
			Mname: "ns.z.", Rname: "hostmaster.z.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
		rec.NewRR("a.z.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
		rec.NewRR("ns.z.", &rec.RRoptsA{Target: net.ParseIP("5.6.7.8")}),
		rec.NewRR("alias.z.", &rec.RRoptsCNAME{Cname: "target.invalid."}),
		rec.NewRR("*.z.", &rec.RRoptsA{Target: net.ParseIP("10.0.0.1")}),
	})
}

// dnssecTestDB is responseTestDB with DNSSECEnabled and RRSIG records for A
// at a.z. and SOA at z., used to test appendDNSSEC / appendNegativeAuthority.
func dnssecTestDB() *db.DB {
	zone := rec.Domain("z.")
	d := db.NewDB(zone, []*rec.RR{
		rec.NewRR("z.", &rec.RRoptsSOA{
			Mname: "ns.z.", Rname: "hostmaster.z.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
		rec.NewRR(
			"z.",
			&rec.RRoptsRRSIG{TypeCovered: rec.RRtypeToWire[rec.TypeSOA]},
		),
		rec.NewRR("a.z.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
		rec.NewRR(
			"a.z.",
			&rec.RRoptsRRSIG{TypeCovered: rec.RRtypeToWire[rec.TypeA]},
		),
		rec.NewRR("alias.z.", &rec.RRoptsCNAME{Cname: "target.invalid."}),
		rec.NewRR(
			"alias.z.",
			&rec.RRoptsRRSIG{TypeCovered: rec.RRtypeToWire[rec.TypeCNAME]},
		),
		rec.NewRR("*.z.", &rec.RRoptsA{Target: net.ParseIP("10.0.0.1")}),
		rec.NewRR(
			"*.z.",
			&rec.RRoptsRRSIG{TypeCovered: rec.RRtypeToWire[rec.TypeA]},
		),
	})
	d.DNSSECEnabled = true

	return d
}

// ── lookupRRset ───────────────────────────────────────────────────────────────

func TestLookupRRset_DirectHit(t *testing.T) {
	d := responseTestDB()
	rcode, answers, _, owner := lookupRRset(d, "a.z.", rec.TypeA)

	if rcode != response.RcodeNoError {
		t.Fatalf("rcode = %d, want NoError", rcode)
	}

	if len(answers) != 1 {
		t.Fatalf("len(answers) = %d, want 1", len(answers))
	}

	if owner != "a.z." {
		t.Errorf("effectiveOwner = %q, want %q", owner, "a.z.")
	}
}

func TestLookupRRset_NODATA(t *testing.T) {
	d := responseTestDB()
	// z. exists (has SOA) but has no A record.
	rcode, answers, _, _ := lookupRRset(d, "z.", rec.TypeA)

	if rcode != response.RcodeNoError {
		t.Fatalf("rcode = %d, want NoError", rcode)
	}

	if len(answers) != 0 {
		t.Errorf("len(answers) = %d, want 0", len(answers))
	}
}

func TestLookupRRset_NXDOMAIN(t *testing.T) {
	// DB without wildcards so we get a clean NXDOMAIN.
	d := db.NewDB("z.", []*rec.RR{
		rec.NewRR("z.", &rec.RRoptsSOA{
			Mname: "ns.z.", Rname: "hostmaster.z.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
	})

	rcode, answers, _, _ := lookupRRset(d, "notexist.z.", rec.TypeA)

	if rcode != response.RcodeNXDomain {
		t.Fatalf("rcode = %d, want NXDomain", rcode)
	}

	if len(answers) != 0 {
		t.Errorf("len(answers) = %d, want 0", len(answers))
	}
}

func TestLookupRRset_WildcardHit(t *testing.T) {
	d := responseTestDB()
	rcode, answers, _, owner := lookupRRset(d, "unknown.z.", rec.TypeA)

	if rcode != response.RcodeNoError {
		t.Fatalf("rcode = %d, want NoError", rcode)
	}

	if len(answers) != 1 {
		t.Fatalf("len(answers) = %d, want 1", len(answers))
	}
	// Synthesised answer must carry the queried name, not the wildcard owner.
	if answers[0].Name != "unknown.z." {
		t.Errorf("answer Name = %q, want %q", answers[0].Name, "unknown.z.")
	}
	// effectiveOwner must be the wildcard so RRSIG lookup uses the right key.
	if owner != "*.z." {
		t.Errorf("effectiveOwner = %q, want %q", owner, "*.z.")
	}
}

func TestLookupRRset_WildcardNODATA(t *testing.T) {
	d := responseTestDB()
	// Wildcard exists with A, but we ask for MX → NODATA, effectiveOwner = wildcard.
	rcode, answers, _, owner := lookupRRset(d, "unknown.z.", rec.TypeMX)

	if rcode != response.RcodeNoError {
		t.Fatalf("rcode = %d, want NoError", rcode)
	}

	if len(answers) != 0 {
		t.Errorf("len(answers) = %d, want 0", len(answers))
	}

	if owner != "*.z." {
		t.Errorf("effectiveOwner = %q, want %q", owner, "*.z.")
	}
}

func TestLookupRRset_CNAMEFallback(t *testing.T) {
	d := responseTestDB()
	rcode, answers, additional, owner := lookupRRset(d, "alias.z.", rec.TypeA)

	if rcode != response.RcodeNoError {
		t.Fatalf("rcode = %d, want NoError", rcode)
	}

	if len(answers) != 1 {
		t.Fatalf("len(answers) = %d, want 1", len(answers))
	}

	if answers[0].RRtype != rec.TypeCNAME {
		t.Errorf("answer type = %q, want CNAME", answers[0].RRtype)
	}

	if len(additional) != 0 {
		t.Errorf(
			"len(additional) = %d, want 0 for off-zone target",
			len(additional),
		)
	}

	if owner != "alias.z." {
		t.Errorf("effectiveOwner = %q, want alias.z.", owner)
	}
}

// ── appendDNSSEC ──────────────────────────────────────────────────────────────

func TestAppendDNSSEC_DoBitFalse(t *testing.T) {
	d := dnssecTestDB()
	a := []*rec.RR{
		rec.NewRR("a.z.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
	}

	got, auth, err := appendDNSSEC(
		d,
		nil,
		"a.z.",
		"a.z.",
		rec.RRtypeToWire[rec.TypeA],
		response.RcodeNoError,
		a,
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 {
		t.Errorf("answers grew from 1 to %d with doBit=false", len(got))
	}

	if len(auth) != 0 {
		t.Errorf("authority grew with doBit=false")
	}
}

func TestAppendDNSSEC_DNSSECDisabled(t *testing.T) {
	d := dnssecTestDB()
	d.DNSSECEnabled = false
	a := []*rec.RR{
		rec.NewRR("a.z.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
	}

	got, _, err := appendDNSSEC(
		d,
		nil,
		"a.z.",
		"a.z.",
		rec.RRtypeToWire[rec.TypeA],
		response.RcodeNoError,
		a,
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 {
		t.Errorf("answers grew with DNSSECEnabled=false")
	}
}

func TestAppendDNSSEC_NoErrorAppendsRRSIG(t *testing.T) {
	d := dnssecTestDB()
	a := d.LookupByType("a.z.", rec.TypeA)

	got, _, err := appendDNSSEC(
		d,
		nil,
		"a.z.",
		"a.z.",
		rec.RRtypeToWire[rec.TypeA],
		response.RcodeNoError,
		a,
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("len(answers) = %d, want 2 (A + RRSIG)", len(got))
	}

	if got[1].RRtype != rec.TypeRRSIG {
		t.Errorf("second record type = %q, want RRSIG", got[1].RRtype)
	}
}

func TestAppendDNSSEC_NoErrorUsesEffectiveOwner(t *testing.T) {
	// Wildcard RRSIG lives at *.z., not at the queried name foo.z.
	// effectiveOwner must drive the RRSIG lookup.
	d := dnssecTestDB()
	a := synthesiseAnswers(d.LookupByType("*.z.", rec.TypeA), "foo.z.")

	got, _, err := appendDNSSEC(
		d,
		nil,
		"foo.z.",
		"*.z.",
		rec.RRtypeToWire[rec.TypeA],
		response.RcodeNoError,
		a,
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("len(answers) = %d, want 2 (A + RRSIG from *.z.)", len(got))
	}
}

func TestAppendDNSSEC_NoAnswersIsNoop(t *testing.T) {
	d := dnssecTestDB()

	got, _, err := appendDNSSEC(
		d,
		nil,
		"a.z.",
		"a.z.",
		rec.RRtypeToWire[rec.TypeA],
		response.RcodeNoError,
		nil,
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 0 {
		t.Errorf("answers non-empty for NODATA with doBit=true")
	}
}

func TestAppendDNSSEC_CNAMEFallbackUsesCNAMEType(t *testing.T) {
	d := dnssecTestDB()
	cnames := d.LookupByType("alias.z.", rec.TypeCNAME)

	got, _, err := appendDNSSEC(
		d,
		nil,
		"alias.z.",
		"alias.z.",
		rec.RRtypeToWire[rec.TypeA],
		response.RcodeNoError,
		cnames,
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("len(answers) = %d, want 2 (CNAME + RRSIG)", len(got))
	}

	sig, ok := got[1].Opts.(*rec.RRoptsRRSIG)
	if !ok {
		t.Fatalf("second answer opts = %T, want *rec.RRoptsRRSIG", got[1].Opts)
	}

	if sig.TypeCovered != rec.RRtypeToWire[rec.TypeCNAME] {
		t.Errorf("TypeCovered = %d, want CNAME", sig.TypeCovered)
	}
}

func TestAppendDNSSEC_NXDomainNilChainIsNoop(t *testing.T) {
	d := dnssecTestDB()

	_, auth, err := appendDNSSEC(
		d,
		nil,
		"nope.z.",
		"nope.z.",
		rec.RRtypeToWire[rec.TypeA],
		response.RcodeNXDomain,
		nil,
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(auth) != 0 {
		t.Errorf("authority non-empty for nil chain")
	}
}

// ── appendNegativeAuthority ───────────────────────────────────────────────────

func TestAppendNegativeAuthority_NoErrorWithAnswers(t *testing.T) {
	d := responseTestDB()
	a := d.LookupByType("a.z.", rec.TypeA)

	auth := appendNegativeAuthority(d, response.RcodeNoError, a, nil, false)

	if len(auth) != 0 {
		t.Errorf("authority modified for positive response")
	}
}

func TestAppendNegativeAuthority_NXDOMAIN(t *testing.T) {
	d := responseTestDB()

	auth := appendNegativeAuthority(d, response.RcodeNXDomain, nil, nil, false)

	if len(auth) != 1 {
		t.Fatalf("len(authority) = %d, want 1 (SOA)", len(auth))
	}

	if auth[0].RRtype != rec.TypeSOA {
		t.Errorf("authority[0] type = %q, want SOA", auth[0].RRtype)
	}
}

func TestAppendNegativeAuthority_NODATA(t *testing.T) {
	d := responseTestDB()

	auth := appendNegativeAuthority(d, response.RcodeNoError, nil, nil, false)

	if len(auth) != 1 {
		t.Fatalf("len(authority) = %d, want 1 (SOA)", len(auth))
	}

	if auth[0].RRtype != rec.TypeSOA {
		t.Errorf("authority[0] type = %q, want SOA", auth[0].RRtype)
	}
}

func TestAppendNegativeAuthority_NXDomainDNSSEC(t *testing.T) {
	d := dnssecTestDB()

	auth := appendNegativeAuthority(d, response.RcodeNXDomain, nil, nil, true)

	if len(auth) != 2 {
		t.Fatalf("len(authority) = %d, want 2 (SOA + RRSIG)", len(auth))
	}

	if auth[0].RRtype != rec.TypeSOA {
		t.Errorf("authority[0] type = %q, want SOA", auth[0].RRtype)
	}

	if auth[1].RRtype != rec.TypeRRSIG {
		t.Errorf("authority[1] type = %q, want RRSIG", auth[1].RRtype)
	}
}

// ── appendDNSSEC NSEC3 proof tests ────────────────────────────────────────────

// nsec3TestDB builds a DNSSEC-enabled DB with a real NSEC3 chain and stub
// RRSIGs for each NSEC3 record, so the proof-attachment path can be tested
// without a signing key.
func nsec3TestDB(t testing.TB) (*db.DB, *dnssec.NSEC3Chain) {
	t.Helper()

	zone := rec.Domain("z.")
	base := db.NewDB(zone, []*rec.RR{
		rec.NewRR("z.", &rec.RRoptsSOA{
			Mname: "ns.z.", Rname: "hostmaster.z.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
		rec.NewRR("a.z.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
	})

	chain, nsec3paramRR, err := dnssec.BuildNSEC3Chain(
		base,
		dnssec.DefaultNSEC3PARAMRecord(),
	)
	if err != nil {
		t.Fatalf("BuildNSEC3Chain: %v", err)
	}

	records := base.AllRecords()
	records = append(records, chain.Records...)
	records = append(records, nsec3paramRR)

	// Stub RRSIG for each NSEC3 record so the RRSIG-per-proof path is exercised.
	for _, nsec3RR := range chain.Records {
		records = append(records, rec.NewRR(
			nsec3RR.Name,
			&rec.RRoptsRRSIG{TypeCovered: rec.RRtypeToWire[rec.TypeNSEC3]},
		))
	}

	d := db.NewDB(zone, records)
	d.DNSSECEnabled = true

	chain2, err := dnssec.RebuildNSEC3Chain(d)
	if err != nil {
		t.Fatalf("RebuildNSEC3Chain: %v", err)
	}

	return d, chain2
}

func TestAppendDNSSEC_NXDomainProof(t *testing.T) {
	d, chain := nsec3TestDB(t)

	_, auth, err := appendDNSSEC(
		d, chain, "notexist.z.", "notexist.z.",
		rec.RRtypeToWire[rec.TypeA], response.RcodeNXDomain, nil, nil, true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(auth) == 0 {
		t.Fatal("authority empty, expected NSEC3 proof records")
	}

	for _, rr := range auth {
		if rr.RRtype != rec.TypeNSEC3 && rr.RRtype != rec.TypeRRSIG {
			t.Errorf(
				"unexpected authority RR type %q, want NSEC3 or RRSIG",
				rr.RRtype,
			)
		}
	}
}

func TestAppendDNSSEC_NXDomainChainError(t *testing.T) {
	d, chain := nsec3TestDB(t)

	// Passing the zone apex as queried name triggers an error from ClosestEncloserProof.
	_, _, err := appendDNSSEC(
		d, chain, d.Zone, d.Zone,
		rec.RRtypeToWire[rec.TypeA], response.RcodeNXDomain, nil, nil, true,
	)

	if err == nil {
		t.Fatal("expected error for zone apex query, got nil")
	}
}
