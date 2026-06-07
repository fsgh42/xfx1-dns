// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"encoding/binary"
	"fmt"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

type (
	// queryInfo carries per-query metadata for logging and metrics.
	queryInfo struct {
		qname     string
		rrtype    rec.RRtype
		rcode     uint16
		dnssec    bool   // true if DNSSEC is enabled in the current DB
		udpSize   uint16 // client's EDNS UDP payload size; 0 if no EDNS
		supported bool   // true when rrtype resolves via RRtypeFromWire
	}

	// ednsInfo holds parsed EDNS(0) information from a query's OPT record.
	ednsInfo struct {
		present bool   // true if an OPT record was found
		do      bool   // DO (DNSSEC OK) bit
		version uint8  // EDNS version (must be 0)
		udpSize uint16 // client's advertised UDP payload size
	}
)

const (
	// maxTCPResponseSize is the maximum DNS response size over TCP.
	// Chosen to comfortably fit any realistic authoritative response including
	// DNSSEC proofs while bounding memory usage per connection.
	maxTCPResponseSize = 8 * 1024

	// tcpConnTimeout is the per-connection read/write deadline for TCP DNS connections.
	tcpConnTimeout = 5 * time.Second

	// maxUDPMsgSize is the maximum size in bytes that a UDP based response can have.
	maxUDPMsgSize = 4096

	// DNS opcodes and query types for filtering.
	opcodeQuery = 0
	qtypeAXFR   = 252
	qtypeIXFR   = 251
)

var rcodeNames = map[uint16]string{
	0: "NOERROR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	5: "REFUSED",
}

func rcodeName(rcode uint16) string {
	if name, ok := rcodeNames[rcode]; ok {
		return name
	}

	return fmt.Sprintf("RCODE%d", rcode)
}

// parseOPT scans the additional section of a DNS message for an OPT record
// (type 41) and extracts EDNS(0) information. pos must point to the first
// byte after the question section.
func parseOPT(msg []byte, pos int) ednsInfo {
	if len(msg) < 12 {
		return ednsInfo{}
	}

	// Header layout: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))

	// Skip answer + authority RRs.
	skipRRs := anCount + nsCount
	for i := 0; i < skipRRs && pos < len(msg); i++ {
		pos = skipName(msg, pos)
		if pos+10 > len(msg) {
			return ednsInfo{}
		}

		rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10 + rdlen
	}

	// Scan additional RRs for OPT (type 41).
	for i := 0; i < arCount && pos < len(msg); i++ {
		pos = skipName(msg, pos)
		if pos+10 > len(msg) {
			return ednsInfo{}
		}

		rrtype := binary.BigEndian.Uint16(msg[pos : pos+2])
		if rrtype == 41 {
			if pos+10 > len(msg) {
				return ednsInfo{}
			}

			// OPT fixed fields after name:
			//   type(2) class(2) TTL(4) RDLENGTH(2)
			// class = UDP payload size
			// TTL byte 0 = extended RCODE high bits
			// TTL byte 1 = EDNS version
			// TTL bytes 2-3 = flags (bit 15 = DO)
			udpSize := binary.BigEndian.Uint16(msg[pos+2 : pos+4])
			version := msg[pos+5]
			extFlags := binary.BigEndian.Uint16(msg[pos+6 : pos+8])

			return ednsInfo{
				present: true,
				do:      extFlags&dnssec.EDNSDOBit != 0,
				version: version,
				udpSize: udpSize,
			}
		}

		rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10 + rdlen
	}

	return ednsInfo{}
}

// skipName advances past a DNS wire-format name at msg[pos] and returns the new pos.
func skipName(msg []byte, pos int) int {
	for pos < len(msg) {
		length := int(msg[pos])
		if length == 0 {
			return pos + 1
		}

		if length&0xc0 == 0xc0 {
			return pos + 2 // pointer: always 2 bytes
		}

		pos += 1 + length
	}

	return pos
}
