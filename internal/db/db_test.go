// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"encoding/json"
	"net"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func makeA(name, ip string) *rec.RR {
	return rec.NewRR(rec.Domain(name), &rec.RRoptsA{Target: net.ParseIP(ip)})
}

func makeNS(name, ns string) *rec.RR {
	return rec.NewRR(rec.Domain(name), &rec.RRoptsNS{Ns: rec.Domain(ns)})
}

func makeSOA(zone, mname, rname string) *rec.RR {
	return rec.NewRR(rec.Domain(zone), &rec.RRoptsSOA{
		Mname:   rec.Domain(mname),
		Rname:   rec.Domain(rname),
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minimum: 300,
	})
}

func TestNewDB(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeA("a.example.com.", "1.2.3.4"),
		makeNS("example.com.", "ns1.example.com."),
	}
	db := NewDB(zone, rrs)

	if len(db.ByType[rec.TypeA]) != 1 {
		t.Errorf("ByType[A] = %d, want 1", len(db.ByType[rec.TypeA]))
	}

	if len(db.ByType[rec.TypeNS]) != 1 {
		t.Errorf("ByType[NS] = %d, want 1", len(db.ByType[rec.TypeNS]))
	}

	if len(db.ByName[rec.Domain("a.example.com.")]) != 1 {
		t.Errorf(
			"ByName[a.example.com.] = %d, want 1",
			len(db.ByName[rec.Domain("a.example.com.")]),
		)
	}
}

func TestLookupByType(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeA("a.example.com.", "1.2.3.4"),
		makeA("b.example.com.", "5.6.7.8"),
	}
	db := NewDB(zone, rrs)

	got := db.LookupByType("a.example.com.", rec.TypeA)
	if len(got) != 1 {
		t.Errorf("LookupByType A a.example.com. = %d, want 1", len(got))
	}

	miss := db.LookupByType("c.example.com.", rec.TypeA)
	if len(miss) != 0 {
		t.Errorf("LookupByType miss = %d, want 0", len(miss))
	}
}

func TestLookupByName(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeA("a.example.com.", "1.2.3.4"),
		makeNS("a.example.com.", "ns1.example.com."),
	}
	db := NewDB(zone, rrs)

	gotA := db.LookupByName("a.example.com.", rec.TypeA)
	if len(gotA) != 1 {
		t.Errorf("LookupByName A = %d, want 1", len(gotA))
	}

	gotNS := db.LookupByName("a.example.com.", rec.TypeNS)
	if len(gotNS) != 1 {
		t.Errorf("LookupByName NS = %d, want 1", len(gotNS))
	}

	miss := db.LookupByName("a.example.com.", rec.TypeMX)
	if len(miss) != 0 {
		t.Errorf("LookupByName miss = %d, want 0", len(miss))
	}
}

func TestLookupAdditional(t *testing.T) {
	zone := rec.Domain("example.com.")
	nsRR := makeNS("example.com.", "ns1.example.com.")
	aRR := makeA("ns1.example.com.", "1.2.3.4")
	rrs := []*rec.RR{nsRR, aRR}
	db := NewDB(zone, rrs)

	additional := db.LookupAdditional([]*rec.RR{nsRR}, rec.TypeNS)
	if len(additional) != 1 {
		t.Errorf("LookupAdditional = %d, want 1", len(additional))
	}
}

func makeAAAA(name, ip string) *rec.RR {
	return rec.NewRR(rec.Domain(name), &rec.RRoptsAAAA{Target: net.ParseIP(ip)})
}

func makeMX(zone, exchange string, pref uint16) *rec.RR {
	return rec.NewRR(
		rec.Domain(zone),
		&rec.RRoptsMX{Preference: pref, Mx: rec.Domain(exchange)},
	)
}

func makeSRV(name, target string, port uint16) *rec.RR {
	return rec.NewRR(
		rec.Domain(name),
		&rec.RRoptsSRV{
			Priority: 10,
			Weight:   0,
			Port:     port,
			Target:   rec.Domain(target),
		},
	)
}

func makeCNAME(name, target string) *rec.RR {
	return rec.NewRR(
		rec.Domain(name),
		&rec.RRoptsCNAME{Cname: rec.Domain(target)},
	)
}

// TestMultipleARecords verifies that multiple A records for the same name are
// all stored and all returned by LookupByType.
func TestMultipleARecords(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeA("host.example.com.", "1.2.3.4"),
		makeA("host.example.com.", "1.2.3.5"),
		makeA("host.example.com.", "1.2.3.6"),
	}
	db := NewDB(zone, rrs)

	got := db.LookupByType("host.example.com.", rec.TypeA)
	if len(got) != 3 {
		t.Errorf("LookupByType A = %d records, want 3", len(got))
	}
}

// TestMultipleAAAARecords verifies the same for AAAA.
func TestMultipleAAAARecords(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeAAAA("host.example.com.", "2001:db8::1"),
		makeAAAA("host.example.com.", "2001:db8::2"),
	}
	db := NewDB(zone, rrs)

	got := db.LookupByType("host.example.com.", rec.TypeAAAA)
	if len(got) != 2 {
		t.Errorf("LookupByType AAAA = %d records, want 2", len(got))
	}
}

// TestLookupAdditional_MX checks that the A/AAAA records for an MX exchange
// are returned in the additional section.
func TestLookupAdditional_MX(t *testing.T) {
	zone := rec.Domain("example.com.")
	mxRR := makeMX("example.com.", "mail.example.com.", 10)
	aRR := makeA("mail.example.com.", "10.0.0.1")
	aaaaRR := makeAAAA("mail.example.com.", "2001:db8::1")
	db := NewDB(zone, []*rec.RR{mxRR, aRR, aaaaRR})

	additional := db.LookupAdditional([]*rec.RR{mxRR}, rec.TypeMX)
	if len(additional) != 2 {
		t.Errorf(
			"LookupAdditional MX = %d records, want 2 (A + AAAA)",
			len(additional),
		)
	}
}

// TestLookupAdditional_SRV checks glue records for an SRV target.
func TestLookupAdditional_SRV(t *testing.T) {
	zone := rec.Domain("example.com.")
	srvRR := makeSRV("_http._tcp.example.com.", "svc.example.com.", 80)
	aRR := makeA("svc.example.com.", "10.0.0.2")
	db := NewDB(zone, []*rec.RR{srvRR, aRR})

	additional := db.LookupAdditional([]*rec.RR{srvRR}, rec.TypeSRV)
	if len(additional) != 1 {
		t.Errorf("LookupAdditional SRV = %d records, want 1", len(additional))
	}
}

// TestLookupAdditional_CNAME checks glue for a CNAME target.
func TestLookupAdditional_CNAME(t *testing.T) {
	zone := rec.Domain("example.com.")
	cnRR := makeCNAME("www.example.com.", "real.example.com.")
	aRR := makeA("real.example.com.", "1.2.3.4")
	db := NewDB(zone, []*rec.RR{cnRR, aRR})

	additional := db.LookupAdditional([]*rec.RR{cnRR}, rec.TypeCNAME)
	if len(additional) != 1 {
		t.Errorf("LookupAdditional CNAME = %d records, want 1", len(additional))
	}
}

// TestLookupAdditional_Deduplication verifies that two answers pointing to the
// same target produce only one set of glue records.
func TestLookupAdditional_Deduplication(t *testing.T) {
	zone := rec.Domain("example.com.")
	mx1 := makeMX("example.com.", "mail.example.com.", 10)
	mx2 := makeMX(
		"example.com.",
		"mail.example.com.",
		20,
	) // same exchange, different pref
	aRR := makeA("mail.example.com.", "10.0.0.1")
	db := NewDB(zone, []*rec.RR{mx1, mx2, aRR})

	additional := db.LookupAdditional([]*rec.RR{mx1, mx2}, rec.TypeMX)
	if len(additional) != 1 {
		t.Errorf(
			"LookupAdditional dedup = %d records, want 1 (no duplicates)",
			len(additional),
		)
	}
}

// TestLookupAdditional_NoGlue verifies that records without targets (e.g. A)
// return nothing from the additional lookup.
func TestLookupAdditional_NoGlue(t *testing.T) {
	zone := rec.Domain("example.com.")
	aRR := makeA("host.example.com.", "1.2.3.4")
	db := NewDB(zone, []*rec.RR{aRR})

	additional := db.LookupAdditional([]*rec.RR{aRR}, rec.TypeA)
	if len(additional) != 0 {
		t.Errorf(
			"LookupAdditional A (no target) = %d records, want 0",
			len(additional),
		)
	}
}

// ── WildcardLookup tests ──────────────────────────────────────────────────────

func TestWildcardLookup_match(t *testing.T) {
	zone := rec.Domain("example.com.")
	db := NewDB(zone, []*rec.RR{makeA("*.example.com.", "1.2.3.4")})

	wc, rrs := db.WildcardLookup("foo.example.com.", zone, rec.TypeA)
	if wc != "*.example.com." {
		t.Errorf("wildcard = %q, want *.example.com.", wc)
	}

	if len(rrs) != 1 {
		t.Errorf("rrs = %d, want 1", len(rrs))
	}
}

func TestWildcardLookup_noMatch_exactNode(t *testing.T) {
	zone := rec.Domain("example.com.")
	db := NewDB(zone, []*rec.RR{
		makeA("foo.example.com.", "1.2.3.4"),
		makeA("*.example.com.", "9.9.9.9"),
	})

	// foo.example.com. exists as an exact node → blocks *.example.com. for sub.foo.example.com.
	wc, rrs := db.WildcardLookup("sub.foo.example.com.", zone, rec.TypeA)
	if wc != "" || rrs != nil {
		t.Errorf(
			"expected no match (blocked by exact node), got wc=%q rrs=%v",
			wc,
			rrs,
		)
	}
}

func TestWildcardLookup_noMatch_zoneApex(t *testing.T) {
	zone := rec.Domain("example.com.")
	db := NewDB(zone, []*rec.RR{makeA("*.example.com.", "1.2.3.4")})

	// Wildcards never apply to the zone apex itself.
	wc, rrs := db.WildcardLookup(zone, zone, rec.TypeA)
	if wc != "" || rrs != nil {
		t.Errorf("expected no match for zone apex, got wc=%q rrs=%v", wc, rrs)
	}
}

func TestWildcardLookup_typeMismatch(t *testing.T) {
	zone := rec.Domain("example.com.")
	db := NewDB(zone, []*rec.RR{makeA("*.example.com.", "1.2.3.4")})

	// Wildcard exists but has no AAAA records → signals NODATA (wc non-empty, rrs empty).
	wc, rrs := db.WildcardLookup("foo.example.com.", zone, rec.TypeAAAA)
	if wc != "*.example.com." {
		t.Errorf("wildcard = %q, want *.example.com.", wc)
	}

	if len(rrs) != 0 {
		t.Errorf("rrs = %d, want 0 (NODATA)", len(rrs))
	}
}

func TestWildcardLookup_deeperWildcardWins(t *testing.T) {
	zone := rec.Domain("example.com.")
	db := NewDB(zone, []*rec.RR{
		makeA("*.example.com.", "1.1.1.1"),
		makeA("*.sub.example.com.", "2.2.2.2"),
	})

	wc, rrs := db.WildcardLookup("foo.sub.example.com.", zone, rec.TypeA)
	if wc != "*.sub.example.com." {
		t.Errorf("wildcard = %q, want *.sub.example.com. (deeper wins)", wc)
	}

	if len(rrs) != 1 ||
		rrs[0].Opts.(*rec.RRoptsA).Target.String() != "2.2.2.2" {
		t.Errorf("unexpected rrs: %v", rrs)
	}
}

func TestWildcardLookup_blockedByENT(t *testing.T) {
	zone := rec.Domain("example.com.")
	// a.b.example.com. exists → b.example.com. is an empty non-terminal.
	db := NewDB(zone, []*rec.RR{
		makeA("*.example.com.", "1.2.3.4"),
		makeA("a.b.example.com.", "5.6.7.8"),
	})

	// x.b.example.com. — ENT b.example.com. blocks *.example.com.
	wc, rrs := db.WildcardLookup("x.b.example.com.", zone, rec.TypeA)
	if wc != "" || rrs != nil {
		t.Errorf(
			"expected no match (blocked by ENT), got wc=%q rrs=%v",
			wc,
			rrs,
		)
	}
}

// TestRRCount verifies that RRCount returns the cached record count.
func TestRRCount(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeA("a.example.com.", "1.2.3.4"),
		makeA("b.example.com.", "5.6.7.8"),
		makeNS("example.com.", "ns1.example.com."),
	}

	db := NewDB(zone, rrs)
	if got := db.RRCount(); got != 3 {
		t.Errorf("RRCount = %d, want 3", got)
	}
}

func TestRRCount_Empty(t *testing.T) {
	db := NewDB(rec.Domain("example.com."), nil)
	if got := db.RRCount(); got != 0 {
		t.Errorf("RRCount = %d, want 0", got)
	}
}

func TestRRCount_PreservedAfterJSONRoundTrip(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeA("a.example.com.", "1.2.3.4"),
		makeA("b.example.com.", "2.3.4.5"),
	}
	db := NewDB(zone, rrs)

	data, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}

	var db2 DB
	if err := json.Unmarshal(data, &db2); err != nil {
		t.Fatal(err)
	}

	if got := db2.RRCount(); got != 2 {
		t.Errorf("RRCount after round-trip = %d, want 2", got)
	}
}

func TestDBJSONRoundTrip(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeA("a.example.com.", "1.2.3.4"),
		makeNS("example.com.", "ns1.example.com."),
	}
	db := NewDB(zone, rrs)

	data, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}

	var db2 DB
	if err := json.Unmarshal(data, &db2); err != nil {
		t.Fatal(err)
	}

	if db2.Zone != db.Zone {
		t.Errorf("Zone: got %q, want %q", db2.Zone, db.Zone)
	}

	if len(db2.AllRecords()) != len(db.AllRecords()) {
		t.Errorf(
			"Record count: got %d, want %d",
			len(db2.AllRecords()),
			len(db.AllRecords()),
		)
	}
}
