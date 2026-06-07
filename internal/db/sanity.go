// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"errors"
	"fmt"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

var (
	ErrSanitySOAMissing    = errors.New("no SOA record in zone")
	ErrSanityMultipleSOAs  = errors.New("multiple SOA records in zone")
	ErrSanitySOAZeroSerial = errors.New("SOA serial is zero")
	ErrSanitySOAMnameNoNS  = errors.New(
		"SOA MNAME has no corresponding NS record",
	)
	ErrSanityNSNoAddress = errors.New(
		"NS target has no A or AAAA record",
	)
	ErrSanityCnameAtApex        = errors.New("CNAME record at zone apex")
	ErrSanityDuplicateCname     = errors.New("duplicate CNAME owner name")
	ErrSanityCnameHasOtherData  = errors.New("CNAME owner has other data")
	ErrSanityCnameSelfReference = errors.New("CNAME self-reference")
	ErrSanityCnameNoResolve     = errors.New(
		"CNAME does not recursively resolve to A/AAAA",
	)
)

// cnameCompatibleRRtype reports whether rrtype may coexist with a CNAME at the
// same owner (RFC 1034 §3.6.2): only DNSSEC meta-types are permitted.
func cnameCompatibleRRtype(rrtype rec.RRtype) bool {
	switch rrtype {
	case rec.TypeCNAME, rec.TypeRRSIG, rec.TypeNSEC3, rec.TypeNSEC3PARAM:
		return true
	default:
		return false
	}
}

// SanityChecks validates zone consistency. Returns the first error found.
// Run by master after NewDB, before distributing to slaves.
func SanityChecks(db *DB) error {
	all := db.AllRecords()

	// 1. Exactly one SOA record.
	soaCount := 0

	for _, rr := range all {
		if rr.RRtype == rec.TypeSOA {
			soaCount++
		}
	}

	if soaCount == 0 {
		return ErrSanitySOAMissing
	}

	if soaCount > 1 {
		return ErrSanityMultipleSOAs
	}

	// Extract the SOA.
	soaRRs := db.LookupByType(db.Zone, rec.TypeSOA)
	if len(soaRRs) == 0 {
		// SOA exists but not at zone apex — still valid for our checks
		for _, rr := range all {
			if rr.RRtype == rec.TypeSOA {
				soaRRs = []*rec.RR{rr}
				break
			}
		}
	}

	soaOpts := soaRRs[0].Opts.(*rec.RRoptsSOA)

	// 2. SOA serial must be non-zero.
	if soaOpts.Serial == 0 {
		return ErrSanitySOAZeroSerial
	}

	// 3. SOA MNAME must appear as the nsdname of at least one NS record in the zone.
	allNS := db.ByType[rec.TypeNS]

	var nsRRs []*rec.RR

	for _, rr := range allNS {
		if rec.CompareDomain(rr.Opts.(*rec.RRoptsNS).Ns, soaOpts.Mname) == 0 {
			nsRRs = append(nsRRs, rr)
		}
	}

	if len(nsRRs) == 0 {
		return fmt.Errorf("%w: %s", ErrSanitySOAMnameNoNS, soaOpts.Mname)
	}

	// 4. Each NS record's target must have at least one A or AAAA record.
	for _, nsRR := range db.ByType[rec.TypeNS] {
		nsOpts := nsRR.Opts.(*rec.RRoptsNS)
		aRecs := db.LookupByType(nsOpts.Ns, rec.TypeA)
		aaaaRecs := db.LookupByType(nsOpts.Ns, rec.TypeAAAA)

		if len(aRecs) == 0 && len(aaaaRecs) == 0 {
			return fmt.Errorf("%w: %s", ErrSanityNSNoAddress, nsOpts.Ns)
		}
	}

	// 5. No CNAME record at the zone apex.
	if cnames := db.LookupByType(db.Zone, rec.TypeCNAME); len(cnames) > 0 {
		return fmt.Errorf("%w: %s", ErrSanityCnameAtApex, db.Zone)
	}

	// Collect all CNAMEs.
	allCnames := db.ByType[rec.TypeCNAME]

	// 6. No two CNAME records with the same owner name.
	seen := make(map[rec.Domain]bool)
	for _, rr := range allCnames {
		if seen[rr.Name] {
			return fmt.Errorf("%w: %s", ErrSanityDuplicateCname, rr.Name)
		}

		seen[rr.Name] = true
	}

	// 7. No CNAME owner that also carries ordinary (non-DNSSEC) data (RFC 1034 §3.6.2).
	for _, rr := range allCnames {
		for _, peer := range db.ByName[rr.Name] {
			if !cnameCompatibleRRtype(peer.RRtype) {
				return fmt.Errorf(
					"%w: %s has %s",
					ErrSanityCnameHasOtherData,
					rr.Name,
					peer.RRtype,
				)
			}
		}
	}

	// 8. No CNAME that references itself.
	for _, rr := range allCnames {
		opts := rr.Opts.(*rec.RRoptsCNAME)
		if rec.CompareDomain(rr.Name, opts.Cname) == 0 {
			return fmt.Errorf("%w: %s", ErrSanityCnameSelfReference, rr.Name)
		}
	}

	// 9. Every CNAME whose target is in-zone must recursively resolve to an A or AAAA record.
	// Out-of-zone targets (target does not end with the zone apex) are skipped — they
	// belong to a different zone this server has no authority over.
	inZone := func(target rec.Domain) bool {
		return strings.HasSuffix(string(target), string(db.Zone))
	}
	maxDepth := len(all)

	for _, rr := range allCnames {
		opts := rr.Opts.(*rec.RRoptsCNAME)

		target := opts.Cname
		if !inZone(target) {
			continue
		}

		for depth := 0; ; depth++ {
			if depth >= maxDepth {
				return fmt.Errorf(
					"%w: %s (cycle or unresolvable)",
					ErrSanityCnameNoResolve,
					rr.Name,
				)
			}

			if len(db.LookupByType(target, rec.TypeA)) > 0 {
				break
			}

			if len(db.LookupByType(target, rec.TypeAAAA)) > 0 {
				break
			}

			nextCnames := db.LookupByType(target, rec.TypeCNAME)
			if len(nextCnames) == 0 {
				return fmt.Errorf(
					"%w: %s (target %s has no A/AAAA/CNAME)",
					ErrSanityCnameNoResolve,
					rr.Name,
					target,
				)
			}

			target = nextCnames[0].Opts.(*rec.RRoptsCNAME).Cname
			if !inZone(target) {
				break
			}
		}
	}

	return nil
}
