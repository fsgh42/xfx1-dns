// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

// RRtype is the DNS record type as a human-readable string.
// Canonical values are upper-case standard DNS type names.
//
// NOTE: RRtype is string (not uint16) for readable JSON serialisation
// and to allow use as map keys without custom marshalling.
// For DNS wire format, use RRtypeToWire[t] to get the uint16 value.
type RRtype string

const (
	TypeA          RRtype = "A"
	TypeAAAA       RRtype = "AAAA"
	TypeNS         RRtype = "NS"
	TypeCNAME      RRtype = "CNAME"
	TypeSOA        RRtype = "SOA"
	TypePTR        RRtype = "PTR"
	TypeMX         RRtype = "MX"
	TypeTXT        RRtype = "TXT"
	TypeSRV        RRtype = "SRV"
	TypeCAA        RRtype = "CAA"
	TypeDS         RRtype = "DS"
	TypeRRSIG      RRtype = "RRSIG"
	TypeNSEC3      RRtype = "NSEC3"
	TypeNSEC3PARAM RRtype = "NSEC3PARAM"
	TypeDNSKEY     RRtype = "DNSKEY"
)

// RRtypeToWire maps RRtype string values to their uint16 DNS wire format values.
var RRtypeToWire = map[RRtype]uint16{
	TypeA:          1,
	TypeAAAA:       28,
	TypeNS:         2,
	TypeCNAME:      5,
	TypeSOA:        6,
	TypePTR:        12,
	TypeMX:         15,
	TypeTXT:        16,
	TypeSRV:        33,
	TypeCAA:        257,
	TypeDS:         43,
	TypeRRSIG:      46,
	TypeDNSKEY:     48,
	TypeNSEC3:      50,
	TypeNSEC3PARAM: 51,
}

// RRtypeFromWire maps uint16 wire values back to RRtype strings.
// Used when parsing incoming DNS queries.
var RRtypeFromWire map[uint16]RRtype

func init() {
	RRtypeFromWire = make(map[uint16]RRtype, len(RRtypeToWire))
	for k, v := range RRtypeToWire {
		RRtypeFromWire[v] = k
	}
}
