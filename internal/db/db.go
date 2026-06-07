// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package db

import (
	"encoding/json"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// DB is the complete in-memory DNS database for one zone.
// Two indexes over the same *RR pointers provide efficient lookup by type or
// by name without duplicating records in memory.
//
// Wire format (JSON) is a flat []*RR slice. Both indexes are rebuilt on
// deserialisation via NewDB. This is also how the DB is built from CRDs.
type DB struct {
	Zone   rec.Domain
	ByType map[rec.RRtype][]*rec.RR // O(1) by type, then linear scan by name
	ByName map[rec.Domain][]*rec.RR // O(1) by name, then linear scan by type

	// DNSSECEnabled is true when the DB was built with DNSSEC signing.
	// Slaves use this to decide whether to include DNSSEC records in responses.
	DNSSECEnabled bool

	count int // cached record count; set once in NewDB, never changes
}

// NewDB builds a DB from a flat slice of RRs, constructing both indexes.
// Used by master (from CRD records) and by slave (from received JSON payload).
// Does NOT run sanity checks — call SanityChecks separately.
func NewDB(zone rec.Domain, records []*rec.RR) *DB {
	db := &DB{
		Zone:   zone,
		ByType: make(map[rec.RRtype][]*rec.RR),
		ByName: make(map[rec.Domain][]*rec.RR),
		count:  len(records),
	}
	for _, rr := range records {
		db.ByType[rr.RRtype] = append(db.ByType[rr.RRtype], rr)
		db.ByName[rr.Name] = append(db.ByName[rr.Name], rr)
	}

	return db
}

// LookupByType returns all RRs of the given type, then filters by name.
func (db *DB) LookupByType(name rec.Domain, rrtype rec.RRtype) []*rec.RR {
	var result []*rec.RR

	for _, rr := range db.ByType[rrtype] {
		if rec.CompareDomain(rr.Name, name) == 0 {
			result = append(result, rr)
		}
	}

	return result
}

// LookupByName returns all RRs with the given name, then filters by type.
func (db *DB) LookupByName(name rec.Domain, rrtype rec.RRtype) []*rec.RR {
	var result []*rec.RR

	for _, rr := range db.ByName[name] {
		if rr.RRtype == rrtype {
			result = append(result, rr)
		}
	}

	return result
}

// WildcardLookup implements RFC 1034 §4.3.3 wildcard matching.
// It walks up the label tree from name toward zone looking for a wildcard owner name.
//
// Return semantics:
//   - ("", nil):        no wildcard found → NXDOMAIN
//   - (wc, non-empty):  wildcard match with data → synthesise answer
//   - (wc, nil/empty):  wildcard name exists, wrong type → NODATA
func (db *DB) WildcardLookup(
	name rec.Domain,
	zone rec.Domain,
	rrtype rec.RRtype,
) (wildcard rec.Domain, rrs []*rec.RR) {
	// Wildcards never apply to the zone apex itself.
	if name == zone {
		return "", nil
	}

	nameStr := string(name)
	zoneStr := string(zone)

	current := nameStr

	for {
		dot := strings.Index(current, ".")
		if dot < 0 {
			break
		}

		parent := current[dot+1:]

		wc := rec.Domain("*." + parent)
		if _, exists := db.ByName[wc]; exists {
			// Wildcard name exists. Check for intermediate node blocking.
			blocked := false
			intermediate := nameStr

			for {
				idot := strings.Index(intermediate, ".")
				if idot < 0 {
					break
				}

				iparent := intermediate[idot+1:]
				if iparent == parent {
					break // reached the wildcard parent, no more intermediates
				}

				c := rec.Domain(iparent)
				// Exact node blocks the wildcard.
				if _, exists := db.ByName[c]; exists {
					blocked = true
					break
				}
				// Empty non-terminal also blocks: any key in ByName that is a
				// subdomain of c (ends with ".<c>") makes c an ENT.
				suffix := "." + iparent
				for key := range db.ByName {
					if strings.HasSuffix(string(key), suffix) {
						blocked = true
						break
					}
				}

				if blocked {
					break
				}

				intermediate = iparent
			}

			if blocked {
				return "", nil
			}

			return wc, db.LookupByName(wc, rrtype)
		}

		// Stop after checking *.zone.
		if parent == zoneStr {
			break
		}

		current = parent
	}

	return "", nil
}

// LookupAdditional returns A/AAAA records for names referenced in the answer
// section, for use in the DNS additional section.
// Applicable to CNAME, MX, NS, SRV records.
func (db *DB) LookupAdditional(answers []*rec.RR, qtype rec.RRtype) []*rec.RR {
	seen := make(map[rec.Domain]bool)

	var result []*rec.RR

	for _, rr := range answers {
		var target rec.Domain
		switch opts := rr.Opts.(type) {
		case *rec.RRoptsCNAME:
			target = opts.Cname
		case *rec.RRoptsMX:
			target = opts.Mx
		case *rec.RRoptsNS:
			target = opts.Ns
		case *rec.RRoptsSRV:
			target = opts.Target
		default:
			continue
		}

		if seen[target] {
			continue
		}

		seen[target] = true

		result = append(result, db.LookupByType(target, rec.TypeA)...)
		result = append(result, db.LookupByType(target, rec.TypeAAAA)...)
	}

	return result
}

// AllRecords returns a flat []*RR of all records (from the ByType index).
func (db *DB) AllRecords() []*rec.RR {
	seen := make(map[*rec.RR]bool)

	var result []*rec.RR

	for _, rrs := range db.ByType {
		for _, rr := range rrs {
			if !seen[rr] {
				seen[rr] = true

				result = append(result, rr)
			}
		}
	}

	return result
}

// dbWire is the JSON wire format — a flat struct with no indexes.
type dbWire struct {
	Zone          rec.Domain `json:"zone"`
	Records       []*rec.RR  `json:"records"`
	DNSSECEnabled bool       `json:"dnssecEnabled"`
}

func (db *DB) MarshalJSON() ([]byte, error) {
	return json.Marshal(dbWire{
		Zone:          db.Zone,
		Records:       db.AllRecords(),
		DNSSECEnabled: db.DNSSECEnabled,
	})
}

func (db *DB) UnmarshalJSON(data []byte) error {
	var w dbWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}

	*db = *NewDB(w.Zone, w.Records)
	db.DNSSECEnabled = w.DNSSECEnabled

	return nil
}
