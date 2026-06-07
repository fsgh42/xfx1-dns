// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"

	gocrypto "crypto"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// RRSIGOpts controls RRSIG generation parameters.
type RRSIGOpts struct {
	Inception  uint32 // Unix timestamp, seconds
	Expiration uint32 // Unix timestamp, seconds
	// OrigTTL is taken from the RRset being signed — no need to set here.
}

// DefaultRRSIGOpts returns opts with Inception = now and Expiration = now + window.
// If window is 0, defaults to 7 days.
func DefaultRRSIGOpts(window time.Duration) RRSIGOpts {
	if window <= 0 {
		window = 7 * 24 * time.Hour
	}

	now := uint32(time.Now().UTC().Unix())

	return RRSIGOpts{
		Inception:  now,
		Expiration: now + uint32(window.Seconds()),
	}
}

// RRSIGRecord holds the fields of a produced RRSIG, ready for inclusion in the DB.
type RRSIGRecord struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string // FQDN with trailing dot
	Signature   []byte
}

// AsRR converts this RRSIGRecord into a *rec.RR with an *rec.RRoptsRRSIG payload.
func (r *RRSIGRecord) AsRR(ownerName rec.Domain, ttl rec.RRttl) *rec.RR {
	return &rec.RR{
		Name:   ownerName,
		RRtype: rec.TypeRRSIG,
		TTL:    ttl,
		Opts: &rec.RRoptsRRSIG{
			TypeCovered: r.TypeCovered,
			Algorithm:   r.Algorithm,
			Labels:      r.Labels,
			OrigTTL:     r.OrigTTL,
			Expiration:  r.Expiration,
			Inception:   r.Inception,
			KeyTag:      r.KeyTag,
			SignerName:  r.SignerName,
			Signature:   r.Signature,
		},
	}
}

// SignRRset signs one RRset (all RRs with the same owner name and type) with one key.
// Returns a single RRSIG record for that RRset+key combination.
// The caller is responsible for signing each RRset with each applicable key.
func SignRRset(
	rrset []*rec.RR,
	key *SigningKey,
	opts RRSIGOpts,
) (*RRSIGRecord, error) {
	if len(rrset) == 0 {
		return nil, fmt.Errorf("dnssec: SignRRset: empty RRset")
	}

	// All RRs in the set must have the same owner and type.
	owner := rrset[0].Name
	rrtype := rrset[0].RRtype
	ttl := rrset[0].TTL

	wireType, ok := rec.RRtypeToWire[rrtype]
	if !ok {
		return nil, fmt.Errorf("dnssec: SignRRset: unknown RRtype %s", rrtype)
	}

	labels := countLabels(owner)
	signerName := strings.ToLower(key.DNSKEY.Owner)
	keyTag := key.DNSKEY.KeyTag()

	// Build RRSIG RDATA without signature (RFC 4034 §6.2)
	var rrsigRdata bytes.Buffer

	binary.Write(&rrsigRdata, binary.BigEndian, wireType)
	rrsigRdata.WriteByte(key.DNSKEY.Algorithm)
	rrsigRdata.WriteByte(labels)
	binary.Write(&rrsigRdata, binary.BigEndian, uint32(ttl))
	binary.Write(&rrsigRdata, binary.BigEndian, opts.Expiration)
	binary.Write(&rrsigRdata, binary.BigEndian, opts.Inception)
	binary.Write(&rrsigRdata, binary.BigEndian, keyTag)

	signerDomain := rec.Domain(signerName)
	if err := signerDomain.Write(&rrsigRdata); err != nil {
		return nil, fmt.Errorf("dnssec: SignRRset: write signer name: %w", err)
	}

	// Sort RRs in canonical order: by RDATA bytes lexicographically (RFC 4034 §6.3)
	sorted := make([]*rec.RR, len(rrset))
	copy(sorted, rrset)
	slices.SortFunc(sorted, func(a, b *rec.RR) int {
		return bytes.Compare(a.Opts.Payload(), b.Opts.Payload())
	})

	// Append each RR in wire format (RFC 4034 §6.2)
	for _, rr := range sorted {
		var rrWire bytes.Buffer
		// owner name: lowercase, uncompressed
		ownerLower := rec.Domain(strings.ToLower(string(rr.Name)))
		if err := ownerLower.Write(&rrWire); err != nil {
			return nil, fmt.Errorf("dnssec: SignRRset: write owner: %w", err)
		}

		binary.Write(&rrWire, binary.BigEndian, wireType)
		binary.Write(&rrWire, binary.BigEndian, uint16(1)) // class IN
		binary.Write(&rrWire, binary.BigEndian, uint32(ttl))

		payload := rr.Opts.Payload()
		binary.Write(&rrWire, binary.BigEndian, uint16(len(payload)))
		rrWire.Write(payload)
		rrsigRdata.Write(rrWire.Bytes())
	}

	// Sign the assembled data
	toSign := rrsigRdata.Bytes()

	// ED25519 uses crypto.Hash(0) — pure signing, no pre-hashing.
	// ECDSA/RSA use a hash algorithm; the crypto.Signer.Sign method handles it.
	var hashOpt gocrypto.Hash

	switch key.DNSKEY.Algorithm {
	case 15: // ED25519
		hashOpt = gocrypto.Hash(0)
	case 13, 14: // ECDSAP256SHA256, ECDSAP384SHA384
		if key.DNSKEY.Algorithm == 13 {
			hashOpt = gocrypto.SHA256
		} else {
			hashOpt = gocrypto.SHA384
		}
		// For ECDSA, Sign expects the hash of the data, not the data itself
		h := hashOpt.New()
		h.Write(toSign)
		toSign = h.Sum(nil)
	case 8: // RSASHA256
		hashOpt = gocrypto.SHA256
		h := hashOpt.New()
		h.Write(toSign)
		toSign = h.Sum(nil)
	default:
		return nil, fmt.Errorf(
			"dnssec: SignRRset: unsupported algorithm %d",
			key.DNSKEY.Algorithm,
		)
	}

	sig, err := key.PrivateKey.Key.Sign(nil, toSign, hashOpt)
	if err != nil {
		return nil, fmt.Errorf("dnssec: SignRRset: sign: %w", err)
	}

	// ECDSA: crypto.Signer.Sign returns ASN.1 DER-encoded signatures,
	// but DNS RRSIG requires fixed-size R || S encoding (RFC 6605 §4).
	if key.DNSKEY.Algorithm == 13 || key.DNSKEY.Algorithm == 14 {
		sig, err = ecdsaDERToFixedSize(sig, key.DNSKEY.Algorithm)
		if err != nil {
			return nil, fmt.Errorf(
				"dnssec: SignRRset: convert ECDSA sig: %w",
				err,
			)
		}
	}

	return &RRSIGRecord{
		TypeCovered: wireType,
		Algorithm:   key.DNSKEY.Algorithm,
		Labels:      labels,
		OrigTTL:     uint32(ttl),
		Expiration:  opts.Expiration,
		Inception:   opts.Inception,
		KeyTag:      keyTag,
		SignerName:  signerName,
		Signature:   sig,
	}, nil
}

// SignDB signs all RRsets in a DB and returns a flat slice of RRSIG *rec.RR records
// to be appended to the DB before distribution.
//
// Prerequisite: DNSKEY RRs must already be in the DB before calling SignDB.
// The caller (master) is responsible for injecting them (see master integration).
//
// Signing rules:
//   - DNSKEY RRset: signed by KSK keys only
//   - All other RRsets: signed by ZSK keys only
//   - If no KSK: DNSKEY RRset is signed by ZSK (single-key setup)
//   - RRSIG records already in the DB are skipped (not signed again)
//   - Each RRset is grouped by (owner name, RRtype)
//
// Uses DefaultRRSIGOpts(window) for timestamps.
func SignDB(
	d *db.DB,
	keys []*SigningKey,
	window time.Duration,
) ([]*rec.RR, error) {
	opts := DefaultRRSIGOpts(window)

	var ksks, zsks []*SigningKey

	for _, k := range keys {
		if k.IsKSK() {
			ksks = append(ksks, k)
		} else {
			zsks = append(zsks, k)
		}
	}
	// Single-key setup: if only one role is present, that key signs everything.
	if len(ksks) == 0 {
		ksks = zsks
	}

	if len(zsks) == 0 {
		zsks = ksks
	}

	// Group RRs into RRsets by (owner, type)
	type rrsetKey struct {
		name   rec.Domain
		rrtype rec.RRtype
	}

	rrsets := make(map[rrsetKey][]*rec.RR)
	order := make([]rrsetKey, 0)

	for _, rrs := range d.ByType {
		for _, rr := range rrs {
			// Skip RRSIG records — do not sign signatures
			if rr.RRtype == rec.TypeRRSIG {
				continue
			}

			k := rrsetKey{name: rr.Name, rrtype: rr.RRtype}
			if _, exists := rrsets[k]; !exists {
				order = append(order, k)
			}

			rrsets[k] = append(rrsets[k], rr)
		}
	}

	var result []*rec.RR

	for _, k := range order {
		rrset := rrsets[k]

		var signers []*SigningKey
		if k.rrtype == rec.TypeDNSKEY {
			signers = ksks
		} else {
			signers = zsks
		}

		for _, signer := range signers {
			rrsig, err := SignRRset(rrset, signer, opts)
			if err != nil {
				return nil, fmt.Errorf("sign %s %s: %w", k.name, k.rrtype, err)
			}

			result = append(result, rrsig.AsRR(k.name, rrset[0].TTL))
		}
	}

	return result, nil
}

// countLabels returns the number of labels in name per RFC 4034 §3.1.3.
// The root label (trailing dot) is excluded. The wildcard label (*) is also excluded.
// e.g. "www.example.com." → 3, "*.example.com." → 2
func countLabels(name rec.Domain) uint8 {
	s := strings.TrimSuffix(string(name), ".")
	labels := strings.Split(s, ".")
	n := len(labels)

	if n > 0 && labels[0] == "*" {
		n--
	}

	return uint8(n)
}
