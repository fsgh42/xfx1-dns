// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// lookupRRset resolves name/rrtype against currDB and returns the rcode,
// answer and additional RRs, and the effective owner — name for direct hits,
// wildcardOwner for wildcard expansions. effectiveOwner is the correct key
// for RRSIG lookups on the returned answers.
func lookupRRset(currDB *db.DB, name rec.Domain, rrtype rec.RRtype) (
	rcode uint16, answers, additional []*rec.RR, effectiveOwner rec.Domain,
) {
	answers = currDB.LookupByType(name, rrtype)
	if len(answers) > 0 {
		additional = currDB.LookupAdditional(answers, rrtype)

		return response.RcodeNoError, answers, additional, name
	}

	// RFC 1034 §4.3.2: if the node has a CNAME and the query is not for CNAME,
	// return the CNAME. For off-zone targets there is no local data to continue
	// with, so the CNAME alone is the correct authoritative answer.
	if rrtype != rec.TypeCNAME {
		answers = currDB.LookupByType(name, rec.TypeCNAME)
		if len(answers) > 0 {
			additional = currDB.LookupAdditional(answers, rec.TypeCNAME)

			return response.RcodeNoError, answers, additional, name
		}
	}

	// NODATA: name exists with other record types.
	if _, exists := currDB.ByName[name]; exists {
		return response.RcodeNoError, nil, nil, name
	}

	// Wildcard expansion (RFC 1034 §4.3.3).
	wildcardOwner, wildcardRRs := currDB.WildcardLookup(
		name,
		currDB.Zone,
		rrtype,
	)
	if wildcardOwner == "" {
		return response.RcodeNXDomain, nil, nil, name
	}

	if len(wildcardRRs) == 0 {
		if rrtype != rec.TypeCNAME {
			cnames := currDB.LookupByName(wildcardOwner, rec.TypeCNAME)
			if len(cnames) > 0 {
				answers = synthesiseAnswers(cnames, name)
				additional = currDB.LookupAdditional(answers, rec.TypeCNAME)

				return response.RcodeNoError, answers, additional, wildcardOwner
			}
		}

		// Wildcard exists but no records of the queried type → NODATA.
		return response.RcodeNoError, nil, nil, wildcardOwner
	}

	answers = synthesiseAnswers(wildcardRRs, name)
	additional = currDB.LookupAdditional(answers, rrtype)

	return response.RcodeNoError, answers, additional, wildcardOwner
}

// appendDNSSEC attaches DNSSEC records to answers and authority.
// effectiveOwner is the RRSIG lookup key for answers (differs from name only
// for wildcard expansions). Returns an error only when NSEC3 proof generation
// fails; the caller decides whether to log or drop the response.
func appendDNSSEC(
	currDB *db.DB,
	chain *dnssec.NSEC3Chain,
	name, effectiveOwner rec.Domain,
	qtype uint16,
	rcode uint16,
	answers, authority []*rec.RR,
	doBit bool,
) ([]*rec.RR, []*rec.RR, error) {
	if !doBit || !currDB.DNSSECEnabled {
		return answers, authority, nil
	}

	switch rcode {
	case response.RcodeNoError:
		if len(answers) > 0 {
			typeCovered := qtype

			for _, answer := range answers {
				if answer.RRtype == rec.TypeRRSIG {
					continue
				}

				if wireType, ok := rec.RRtypeToWire[answer.RRtype]; ok {
					typeCovered = wireType
				}

				break
			}

			rrsigs := currDB.LookupByType(effectiveOwner, rec.TypeRRSIG)
			for _, rrsigRR := range rrsigs {
				opts, ok := rrsigRR.Opts.(*rec.RRoptsRRSIG)
				if ok && opts.TypeCovered == typeCovered {
					answers = append(answers, rrsigRR)
				}
			}
		}
	case response.RcodeNXDomain:
		if chain == nil {
			break
		}

		proof, err := chain.ClosestEncloserProof(name, currDB.Zone, currDB)
		if err != nil {
			return answers, authority, err
		}
		// Deduplicate: NextCloser and WildcardAtCE may be the same record
		// in small zones with only 2 NSEC3 entries.
		seen := make(map[rec.Domain]bool)

		var proofRRs []*rec.RR

		for _, rr := range []*rec.RR{proof.ClosestEncloser, proof.NextCloser, proof.WildcardAtCE} {
			if !seen[rr.Name] {
				seen[rr.Name] = true

				proofRRs = append(proofRRs, rr)
			}
		}

		authority = append(authority, proofRRs...)

		for _, proofRR := range proofRRs {
			rrsigs := currDB.LookupByType(proofRR.Name, rec.TypeRRSIG)
			for _, rrsigRR := range rrsigs {
				opts, ok := rrsigRR.Opts.(*rec.RRoptsRRSIG)
				if ok && opts.TypeCovered == rec.RRtypeToWire[rec.TypeNSEC3] {
					authority = append(authority, rrsigRR)
				}
			}
		}
	}

	return answers, authority, nil
}

// appendNegativeAuthority appends SOA (and its RRSIG when DNSSEC is active)
// to authority for NXDOMAIN and NODATA responses (RFC 2308).
func appendNegativeAuthority(
	currDB *db.DB,
	rcode uint16,
	answers, authority []*rec.RR,
	doBit bool,
) []*rec.RR {
	if rcode != response.RcodeNXDomain &&
		!(rcode == response.RcodeNoError && len(answers) == 0) {
		return authority
	}

	soaRRs := currDB.LookupByType(currDB.Zone, rec.TypeSOA)
	authority = append(authority, soaRRs...)

	if doBit && currDB.DNSSECEnabled {
		rrsigs := currDB.LookupByType(currDB.Zone, rec.TypeRRSIG)
		for _, rrsigRR := range rrsigs {
			opts, ok := rrsigRR.Opts.(*rec.RRoptsRRSIG)
			if ok && opts.TypeCovered == rec.RRtypeToWire[rec.TypeSOA] {
				authority = append(authority, rrsigRR)
			}
		}
	}

	return authority
}
