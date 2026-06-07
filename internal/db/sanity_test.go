// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"errors"
	"net"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// baseZone builds a minimal valid zone (SOA + NS at apex pointing to mname + A for mname).
// SOA mname == NS nsdname == "ns1.example.com." (the nameserver hostname).
func baseZone() (rec.Domain, []*rec.RR) {
	zone := rec.Domain("example.com.")

	return zone, []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
	}
}

func TestSanityChecks_Valid(t *testing.T) {
	zone, rrs := baseZone()

	db := NewDB(zone, rrs)
	if err := SanityChecks(db); err != nil {
		t.Errorf("expected no error for valid zone, got: %v", err)
	}
}

func TestSanityChecks_NoSOA(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{makeA("a.example.com.", "1.2.3.4")}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanitySOAMissing) {
		t.Errorf("expected ErrSanitySOAMissing, got: %v", err)
	}
}

func TestSanityChecks_ZeroSerial(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		rec.NewRR(rec.Domain("example.com."), &rec.RRoptsSOA{
			Mname: "ns1.example.com.", Rname: "admin.example.com.",
			Serial: 0, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanitySOAZeroSerial) {
		t.Errorf("expected ErrSanitySOAZeroSerial, got: %v", err)
	}
}

func TestSanityChecks_MultipleSOA(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeSOA("example.com.", "example.com.", "admin2.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityMultipleSOAs) {
		t.Errorf("expected ErrSanityMultipleSOAs, got: %v", err)
	}
}

func TestSanityChecks_SOAMnameNoNS(t *testing.T) {
	zone := rec.Domain("example.com.")
	// SOA MNAME is ns1.example.com. but no NS record has nsdname ns1.example.com.
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns2.example.com."), // points to ns2, not ns1
		makeA("ns1.example.com.", "1.2.3.4"),
		makeA("ns2.example.com.", "5.6.7.8"),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanitySOAMnameNoNS) {
		t.Errorf("expected ErrSanitySOAMnameNoNS, got: %v", err)
	}
}

// TestSanityChecks_NSAtApex verifies that the conventional setup (NS records at
// the zone apex with nsdname == SOA mname) passes sanity checks.
func TestSanityChecks_NSAtApex(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS(
			"example.com.",
			"ns1.example.com.",
		), // NS at apex, nsdname == mname
		makeA("ns1.example.com.", "1.2.3.4"),
	}

	db := NewDB(zone, rrs)
	if err := SanityChecks(db); err != nil {
		t.Errorf("expected no error for NS at apex, got: %v", err)
	}
}

func TestSanityChecks_NSNoAddress(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		// no A/AAAA for ns1.example.com.
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityNSNoAddress) {
		t.Errorf("expected ErrSanityNSNoAddress, got: %v", err)
	}
}

func TestSanityChecks_CNAMEAtApex(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		rec.NewRR("example.com.", &rec.RRoptsCNAME{Cname: "other.com."}),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityCnameAtApex) {
		t.Errorf("expected ErrSanityCnameAtApex, got: %v", err)
	}
}

func TestSanityChecks_DuplicateCNAME(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "a.example.com."},
		),
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "b.example.com."},
		),
		makeA("a.example.com.", "1.2.3.4"),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityDuplicateCname) {
		t.Errorf("expected ErrSanityDuplicateCname, got: %v", err)
	}
}

func TestSanityChecks_CNAMESelfReference(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "www.example.com."},
		),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityCnameSelfReference) {
		t.Errorf("expected ErrSanityCnameSelfReference, got: %v", err)
	}
}

func TestSanityChecks_CNAMENoResolve(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		// CNAME points to nonexistent target
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "nowhere.example.com."},
		),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityCnameNoResolve) {
		t.Errorf("expected ErrSanityCnameNoResolve, got: %v", err)
	}
}

func TestSanityChecks_NSWithAAAAOnly(t *testing.T) {
	// NS target has an AAAA record but no A record — should pass check 3.
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeAAAA("ns1.example.com.", "2001:db8::1"),
	}

	db := NewDB(zone, rrs)
	if err := SanityChecks(db); err != nil {
		t.Errorf(
			"expected no error for NS with AAAA-only address, got: %v",
			err,
		)
	}
}

func TestSanityChecks_CNAMEResolvesToAAAA(t *testing.T) {
	// CNAME target has AAAA but no A — rule 7 must accept AAAA as resolution.
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeAAAA("ns1.example.com.", "2001:db8::1"),
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "ns1.example.com."},
		),
	}

	db := NewDB(zone, rrs)
	if err := SanityChecks(db); err != nil {
		t.Errorf("expected no error for CNAME resolving to AAAA, got: %v", err)
	}
}

func TestSanityChecks_CNAMEOutOfZone(t *testing.T) {
	// CNAME target is outside the zone — should pass without requiring A/AAAA.
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		rec.NewRR(
			"ext.example.com.",
			&rec.RRoptsCNAME{Cname: "target.other.zone."},
		),
	}

	db := NewDB(zone, rrs)
	if err := SanityChecks(db); err != nil {
		t.Errorf("expected no error for out-of-zone CNAME target, got: %v", err)
	}
}

func TestSanityChecks_CNAMECycle(t *testing.T) {
	// a → b → a: a 2-hop CNAME cycle that slips past the self-reference check.
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		rec.NewRR("a.example.com.", &rec.RRoptsCNAME{Cname: "b.example.com."}),
		rec.NewRR("b.example.com.", &rec.RRoptsCNAME{Cname: "a.example.com."}),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityCnameNoResolve) {
		t.Errorf(
			"expected ErrSanityCnameNoResolve for CNAME cycle, got: %v",
			err,
		)
	}
}

func TestSanityChecks_CNAMEWithOtherData(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "target.other.zone."},
		),
		makeA("www.example.com.", "5.6.7.8"),
	}
	db := NewDB(zone, rrs)

	err := SanityChecks(db)
	if !errors.Is(err, ErrSanityCnameHasOtherData) {
		t.Errorf("expected ErrSanityCnameHasOtherData, got: %v", err)
	}
}

func TestSanityChecks_CNAMEWithRRSIG(t *testing.T) {
	zone, rrs := baseZone()
	rrs = append(
		rrs,
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "target.other.zone."},
		),
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsRRSIG{TypeCovered: rec.RRtypeToWire[rec.TypeCNAME]},
		),
	)

	db := NewDB(zone, rrs)
	if err := SanityChecks(db); err != nil {
		t.Errorf("expected no error for CNAME with RRSIG, got: %v", err)
	}
}

func TestSanityChecks_CNAMEChainResolves(t *testing.T) {
	zone := rec.Domain("example.com.")
	rrs := []*rec.RR{
		makeSOA("example.com.", "ns1.example.com.", "admin.example.com."),
		makeNS("example.com.", "ns1.example.com."),
		makeA("ns1.example.com.", "1.2.3.4"),
		// chain: www → alias → real A
		rec.NewRR(
			"www.example.com.",
			&rec.RRoptsCNAME{Cname: "alias.example.com."},
		),
		rec.NewRR(
			"alias.example.com.",
			&rec.RRoptsCNAME{Cname: "real.example.com."},
		),
		{
			Name:   "real.example.com.",
			RRtype: rec.TypeA,
			TTL:    rec.DefaultTTL,
			Opts:   &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")},
		},
	}

	db := NewDB(zone, rrs)
	if err := SanityChecks(db); err != nil {
		t.Errorf("expected no error for valid CNAME chain, got: %v", err)
	}
}
