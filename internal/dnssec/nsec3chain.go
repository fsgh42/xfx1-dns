// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// BuildNSEC3Chain constructs the full NSEC3 chain for a zone.
//
// Algorithm:
//  1. Collect all unique owner names in the DB (including the zone apex)
//  2. For each owner name, compute its NSEC3 hash
//  3. Sort hashes lexicographically
//  4. For each hash, collect the set of RRtypes present at that owner name
//     (add RRSIG to each set that has any records)
//  5. Build the linked ring: each NextHash points to the next in sorted order;
//     last entry wraps to first
//  6. Return the chain and the NSEC3PARAM RR (to be added to the DB)
func BuildNSEC3Chain(
	d *db.DB,
	params NSEC3PARAMRecord,
) (*NSEC3Chain, *rec.RR, error) {
	if len(d.ByName) == 0 {
		return nil, nil, fmt.Errorf("dnssec: BuildNSEC3Chain: empty DB")
	}

	// Use the SOA TTL for NSEC3 records; fall back to DefaultTTL
	nsec3TTL := rec.DefaultTTL
	if soas := d.ByType[rec.TypeSOA]; len(soas) > 0 {
		nsec3TTL = soas[0].TTL
	}

	// Collect unique names
	names := make([]rec.Domain, 0, len(d.ByName))
	for name := range d.ByName {
		names = append(names, name)
	}

	// Compute hashes for each name
	type nameHash struct {
		name rec.Domain
		hash []byte
	}

	hashes := make([]nameHash, 0, len(names))

	for _, name := range names {
		h := HashName(name, params.Iterations, params.Salt)
		hashes = append(hashes, nameHash{name: name, hash: h})
	}

	// Sort by hash bytes lexicographically
	slices.SortFunc(hashes, func(a, b nameHash) int {
		return bytes.Compare(a.hash, b.hash)
	})

	// Build byHash index and NSEC3 records
	byHash := make(map[string]*NSEC3Record, len(hashes))
	nsec3Records := make([]*NSEC3Record, len(hashes))
	nsec3RRs := make([]*rec.RR, len(hashes))

	for i, nh := range hashes {
		// Collect RRtypes at this name
		rrs := d.ByName[nh.name]
		typeSet := make(map[uint16]struct{})

		for _, rr := range rrs {
			if wt, ok := rec.RRtypeToWire[rr.RRtype]; ok {
				typeSet[wt] = struct{}{}
			}
		}
		// Add RRSIG type if there are any records
		if len(typeSet) > 0 {
			typeSet[rec.RRtypeToWire[rec.TypeRRSIG]] = struct{}{}
		}
		// Sort types
		types := make([]uint16, 0, len(typeSet))
		for t := range typeSet {
			types = append(types, t)
		}

		slices.Sort(types)

		// NextHash will be filled in the next pass
		nsec3Records[i] = &NSEC3Record{
			HashAlgorithm: params.HashAlgorithm,
			Flags:         params.Flags,
			Iterations:    params.Iterations,
			Salt:          params.Salt,
			Types:         types,
		}
	}

	// Fill NextHash: each entry points to the next; last wraps to first
	for i := range nsec3Records {
		next := (i + 1) % len(hashes)
		nsec3Records[i].NextHash = hashes[next].hash
	}

	// Build RRs and byHash map
	for i, nh := range hashes {
		nr := nsec3Records[i]
		rr := nr.AsRR(nh.hash, d.Zone, nsec3TTL)
		nsec3RRs[i] = rr

		hashStr := strings.ToUpper(nsec3Encoding.EncodeToString(nh.hash))
		byHash[strings.ToLower(hashStr)] = nr
	}

	chain := &NSEC3Chain{
		Params:  params,
		Records: nsec3RRs,
		byHash:  byHash,
	}
	nsec3paramRR := params.AsRR(d.Zone, nsec3TTL)

	return chain, nsec3paramRR, nil
}

// RebuildNSEC3Chain reconstructs an NSEC3Chain from the NSEC3 records already
// present in the DB. Called by slave once after each DB swap, if DNSSECEnabled.
//
// Because RRoptsNSEC3 stores structured fields (not opaque wire), no wire parsing
// is needed — just type-assert and copy.
func RebuildNSEC3Chain(d *db.DB) (*NSEC3Chain, error) {
	nsec3RRs := d.ByType[rec.TypeNSEC3]
	nsec3paramRRs := d.ByType[rec.TypeNSEC3PARAM]

	var params NSEC3PARAMRecord

	if len(nsec3paramRRs) > 0 {
		p, ok := nsec3paramRRs[0].Opts.(*rec.RRoptsNSEC3PARAM)
		if !ok {
			return nil, fmt.Errorf(
				"dnssec: RebuildNSEC3Chain: NSEC3PARAM opts wrong type",
			)
		}

		params = NSEC3PARAMRecord{
			HashAlgorithm: p.HashAlgorithm,
			Flags:         p.Flags,
			Iterations:    p.Iterations,
			Salt:          p.Salt,
		}
	} else {
		params = DefaultNSEC3PARAMRecord()
	}

	// Sort NSEC3 RRs by owner name
	sorted := make([]*rec.RR, len(nsec3RRs))
	copy(sorted, nsec3RRs)
	slices.SortFunc(sorted, func(a, b *rec.RR) int {
		return strings.Compare(string(a.Name), string(b.Name))
	})

	byHash := make(map[string]*NSEC3Record, len(sorted))

	for _, rr := range sorted {
		opts, ok := rr.Opts.(*rec.RRoptsNSEC3)
		if !ok {
			return nil, fmt.Errorf(
				"dnssec: RebuildNSEC3Chain: NSEC3 RR opts wrong type for %s",
				rr.Name,
			)
		}
		// Owner name is "<base32hash>.<zone>." — extract the hash prefix
		ownerStr := string(rr.Name)
		dotIdx := strings.Index(ownerStr, ".")

		if dotIdx < 0 {
			return nil, fmt.Errorf(
				"dnssec: RebuildNSEC3Chain: bad NSEC3 owner name %q",
				ownerStr,
			)
		}

		hashPrefix := ownerStr[:dotIdx] // already lowercase
		nr := &NSEC3Record{
			HashAlgorithm: opts.HashAlgorithm,
			Flags:         opts.Flags,
			Iterations:    opts.Iterations,
			Salt:          opts.Salt,
			NextHash:      opts.NextHash,
			Types:         opts.Types,
		}
		byHash[hashPrefix] = nr
	}

	return &NSEC3Chain{
		Params:  params,
		Records: sorted,
		byHash:  byHash,
	}, nil
}
