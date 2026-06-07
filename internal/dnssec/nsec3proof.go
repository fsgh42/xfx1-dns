// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"bytes"
	"fmt"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// EncloserProof holds the three NSEC3 records needed for an NXDOMAIN response.
type EncloserProof struct {
	ClosestEncloser *rec.RR // proves CE exists
	NextCloser      *rec.RR // proves name between CE and queried does not exist
	WildcardAtCE    *rec.RR // proves *.CE does not exist (or covers it)
}

// ClosestEncloserProof computes the three-record NSEC3 closest-encloser proof
// for a queried name that does not exist in the zone.
//
// Algorithm (RFC 5155 §8.3):
//  1. Walk up labels from the queried name to find the Closest Encloser (CE)
//  2. Next Closer is the child of CE that the queried name descends through
//  3. Wildcard at CE is "*.CE" — find the NSEC3 that covers it
func (c *NSEC3Chain) ClosestEncloserProof(
	queried rec.Domain,
	zone rec.Domain,
	d *db.DB,
) (*EncloserProof, error) {
	if len(c.byHash) == 0 {
		return nil, fmt.Errorf("dnssec: ClosestEncloserProof: empty chain")
	}

	queriedStr := string(queried)
	zoneStr := string(zone)

	// queried must be strictly below the zone
	if queriedStr == zoneStr {
		return nil, fmt.Errorf(
			"dnssec: ClosestEncloserProof: queried name is zone apex",
		)
	}

	if !strings.HasSuffix(queriedStr, "."+zoneStr) && queriedStr != zoneStr {
		return nil, fmt.Errorf(
			"dnssec: ClosestEncloserProof: %s is not in zone %s",
			queried,
			zone,
		)
	}

	// Build label list from queried name up to zone
	// e.g. "foo.bar.example.com." in zone "example.com." → ["foo.bar.example.com.", "bar.example.com."]
	candidates := buildCandidates(queriedStr, zoneStr)
	if len(candidates) == 0 {
		return nil, fmt.Errorf(
			"dnssec: ClosestEncloserProof: no candidates for %s in %s",
			queried,
			zone,
		)
	}

	// Find Closest Encloser: first candidate whose hash exists in byHash
	ceIdx := -1

	for i, cand := range candidates {
		h := HashName(rec.Domain(cand), c.Params.Iterations, c.Params.Salt)

		hashStr := strings.ToLower(nsec3Encoding.EncodeToString(h))
		if _, ok := c.byHash[hashStr]; ok {
			ceIdx = i
			break
		}
	}

	if ceIdx < 0 {
		// Fall back to zone apex as CE
		h := HashName(zone, c.Params.Iterations, c.Params.Salt)

		hashStr := strings.ToLower(nsec3Encoding.EncodeToString(h))
		if _, ok := c.byHash[hashStr]; !ok {
			return nil, fmt.Errorf(
				"dnssec: ClosestEncloserProof: cannot find closest encloser for %s",
				queried,
			)
		}

		ceIdx = len(candidates) // signals zone apex
	}

	var ceName rec.Domain

	var ncName rec.Domain

	if ceIdx == len(candidates) {
		// CE is the zone apex
		ceName = zone

		if len(candidates) > 0 {
			ncName = rec.Domain(candidates[len(candidates)-1])
		} else {
			return nil, fmt.Errorf("dnssec: ClosestEncloserProof: queried name has no next closer")
		}
	} else {
		ceName = rec.Domain(candidates[ceIdx])

		if ceIdx == 0 {
			// The queried name itself is the CE — this means it exists, not NXDOMAIN territory
			return nil, fmt.Errorf("dnssec: ClosestEncloserProof: queried name exists in chain")
		}

		ncName = rec.Domain(candidates[ceIdx-1])
	}

	// NSEC3 for Closest Encloser: the record whose owner hash == hash(CE)
	ceHash := HashName(ceName, c.Params.Iterations, c.Params.Salt)
	ceHashStr := strings.ToLower(nsec3Encoding.EncodeToString(ceHash))
	ceOwner := rec.Domain(ceHashStr + "." + string(zone))

	ceRR := d.LookupByType(ceOwner, rec.TypeNSEC3)
	if len(ceRR) == 0 {
		return nil, fmt.Errorf(
			"dnssec: ClosestEncloserProof: no NSEC3 for CE %s (hash %s)",
			ceName,
			ceHashStr,
		)
	}

	// NSEC3 for Next Closer: the record that covers hash(NC)
	ncHash := HashName(ncName, c.Params.Iterations, c.Params.Salt)

	ncRR, err := c.findCovering(ncHash)
	if err != nil {
		return nil, fmt.Errorf(
			"dnssec: ClosestEncloserProof: NC %s: %w",
			ncName,
			err,
		)
	}

	// NSEC3 for Wildcard at CE: covers hash("*.CE")
	wildcardName := rec.Domain("*." + string(ceName))
	wildcardHash := HashName(wildcardName, c.Params.Iterations, c.Params.Salt)

	wildcardRR, err := c.findCovering(wildcardHash)
	if err != nil {
		return nil, fmt.Errorf(
			"dnssec: ClosestEncloserProof: wildcard *.%s: %w",
			ceName,
			err,
		)
	}

	return &EncloserProof{
		ClosestEncloser: ceRR[0],
		NextCloser:      ncRR,
		WildcardAtCE:    wildcardRR,
	}, nil
}

// buildCandidates returns the ancestor names from queried down to (but not including) zone,
// ordered from most-specific to least-specific.
// e.g. "foo.bar.example.com." in "example.com." → ["foo.bar.example.com.", "bar.example.com."]
func buildCandidates(queried, zone string) []string {
	// Strip the zone suffix and trailing dot from the queried name
	rel := strings.TrimSuffix(queried, "."+zone)
	rel = strings.TrimSuffix(rel, ".")

	if rel == "" || rel == zone {
		return nil
	}

	labels := strings.Split(rel, ".")
	candidates := make([]string, 0, len(labels))

	for i := range labels {
		sub := strings.Join(labels[i:], ".") + "." + zone
		candidates = append(candidates, sub)
	}

	return candidates
}

// covers reports whether the NSEC3 with ownerHash covers targetHash in the ring.
// In a sorted ring, (ownerHash, nextHash) covers targetHash if:
//
//	ownerHash < targetHash < nextHash  (normal case)
//	OR ownerHash > nextHash AND (targetHash > ownerHash OR targetHash < nextHash)  (wrap case)
func covers(ownerHash, nextHash, targetHash []byte) bool {
	ownCmp := bytes.Compare(ownerHash, targetHash)
	nextCmp := bytes.Compare(targetHash, nextHash)

	if bytes.Compare(ownerHash, nextHash) < 0 {
		// Normal (non-wrapping) case
		return ownCmp < 0 && nextCmp < 0
	}
	// Wrap-around case: ownerHash > nextHash
	return ownCmp < 0 || nextCmp < 0
}

// findCovering iterates the sorted chain and returns the *rec.RR of the NSEC3
// record whose (ownerHash, NextHash) range covers the given targetHash.
func (c *NSEC3Chain) findCovering(targetHash []byte) (*rec.RR, error) {
	for _, rr := range c.Records {
		opts, ok := rr.Opts.(*rec.RRoptsNSEC3)
		if !ok {
			continue
		}
		// Decode owner hash from owner name
		ownerStr := string(rr.Name)

		dotIdx := strings.Index(ownerStr, ".")
		if dotIdx < 0 {
			continue
		}

		hashPrefix := ownerStr[:dotIdx]

		ownerHash, err := nsec3Encoding.DecodeString(
			strings.ToUpper(hashPrefix),
		)
		if err != nil {
			continue
		}

		if covers(ownerHash, opts.NextHash, targetHash) {
			return rr, nil
		}
	}

	return nil, fmt.Errorf("no covering NSEC3 found for hash %x", targetHash)
}
