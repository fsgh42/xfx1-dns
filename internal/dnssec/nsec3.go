// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by RFC 5155 §5; use is unavoidable for NSEC3
	"encoding/base32"
	"fmt"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// nsec3Encoding is the base32 Extended Hex encoding without padding.
// RFC 5155 §1.3 specifies Extended Hex alphabet (0-9A-V), no padding.
var nsec3Encoding = base32.HexEncoding.WithPadding(base32.NoPadding)

// HashName computes the NSEC3 hash of a domain name per RFC 5155 §5.
// iterations is the number of ADDITIONAL hash rounds (0 = one round total).
// salt may be nil or empty — DefaultNSEC3PARAMRecord uses empty salt (RFC 9276).
func HashName(name rec.Domain, iterations uint16, salt []byte) []byte {
	// Encode name in uncompressed lowercase wire format
	var buf bytes.Buffer
	if err := name.Write(&buf); err != nil {
		panic(fmt.Sprintf("dnssec: HashName: write domain: %v", err))
	}

	x := buf.Bytes()

	// First round (always performed): SHA-1(x_wire || salt)
	h := sha1.New() //nolint:gosec
	h.Write(x)
	h.Write(salt)
	digest := h.Sum(nil)

	// Additional rounds: SHA-1(digest || salt) repeated `iterations` times
	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(nil)
	}

	return digest
}

// NSEC3PARAMRecord holds the NSEC3PARAM fields.
type NSEC3PARAMRecord struct {
	HashAlgorithm uint8  // always 1 (SHA-1)
	Flags         uint8  // always 0
	Iterations    uint16 // recommended 0 (RFC 9276 deprecates high counts)
	Salt          []byte // may be empty; recommend empty (RFC 9276)
}

// DefaultNSEC3PARAMRecord returns safe defaults: algorithm=1, flags=0,
// iterations=0, salt=empty.
func DefaultNSEC3PARAMRecord() NSEC3PARAMRecord {
	return NSEC3PARAMRecord{
		HashAlgorithm: 1,
		Flags:         0,
		Iterations:    0,
		Salt:          nil,
	}
}

// AsRR returns the NSEC3PARAM as a *rec.RR at the zone apex.
func (p *NSEC3PARAMRecord) AsRR(zone rec.Domain, ttl rec.RRttl) *rec.RR {
	return &rec.RR{
		Name:   zone,
		RRtype: rec.TypeNSEC3PARAM,
		TTL:    ttl,
		Opts: &rec.RRoptsNSEC3PARAM{
			HashAlgorithm: p.HashAlgorithm,
			Flags:         p.Flags,
			Iterations:    p.Iterations,
			Salt:          p.Salt,
		},
	}
}

// NSEC3Record holds the fields of one NSEC3 record.
type NSEC3Record struct {
	HashAlgorithm uint8
	Flags         uint8 // 0 = opt-out off (full coverage)
	Iterations    uint16
	Salt          []byte
	NextHash      []byte   // raw hash bytes of next owner (not base32-encoded)
	Types         []uint16 // sorted ascending
}

// AsRR returns the NSEC3 as a *rec.RR.
// The owner name is the base32-extended encoding of nameHash, followed by zone.
// e.g. "<BASE32HASH>.xfx1.de."
func (n *NSEC3Record) AsRR(
	nameHash []byte,
	zone rec.Domain,
	ttl rec.RRttl,
) *rec.RR {
	hashStr := strings.ToUpper(nsec3Encoding.EncodeToString(nameHash))
	ownerStr := hashStr + "." + string(zone)
	owner := rec.Domain(strings.ToLower(ownerStr))

	return &rec.RR{
		Name:   owner,
		RRtype: rec.TypeNSEC3,
		TTL:    ttl,
		Opts: &rec.RRoptsNSEC3{
			HashAlgorithm: n.HashAlgorithm,
			Flags:         n.Flags,
			Iterations:    n.Iterations,
			Salt:          n.Salt,
			NextHash:      n.NextHash,
			Types:         n.Types,
		},
	}
}

// NSEC3Chain is the complete pre-built NSEC3 chain for a zone, indexed by hash.
type NSEC3Chain struct {
	Params  NSEC3PARAMRecord
	Records []*rec.RR // all NSEC3 RRs, sorted by owner name (hash)

	// byHash maps base32-encoded hash (owner name prefix) → NSEC3Record.
	// Used for closest-encloser proof.
	byHash map[string]*NSEC3Record
}
