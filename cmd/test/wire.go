// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	dnsHeaderLen = 12
	optRRType    = 41   // OPT pseudo-RR
	ednsUDPSize  = 4096 // advertised UDP payload size
	ednsVersion  = 0

	rcodeNoError  = 0
	rcodeNXDomain = 3

	flagTC = uint16(1 << 9) // truncated bit in response flags
)

// buildQuery constructs a DNS wire-format query message.
// If edns is true an OPT pseudo-RR is appended; do sets the DNSSEC OK bit.
func buildQuery(id uint16, qname string, qtype uint16, edns, do bool) []byte {
	arcount := uint16(0)
	if edns {
		arcount = 1
	}

	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100) // flags: RD=1
	buf = binary.BigEndian.AppendUint16(buf, 1)      // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, arcount)

	// QNAME: strip trailing dot, encode labels
	name := strings.TrimSuffix(qname, ".")
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}

	buf = append(buf, 0x00) // root label

	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, 1) // QCLASS = IN

	if edns {
		// OPT pseudo-RR (RFC 6891 §6.1.2): root name + type 41 + UDP size + TTL + RDLENGTH
		buf = append(buf, 0x00) // root name
		buf = binary.BigEndian.AppendUint16(buf, optRRType)
		buf = binary.BigEndian.AppendUint16(buf, ednsUDPSize)

		// TTL: [0]=ext-rcode [1]=version [2:4]=flags
		var ednsFlags uint16
		if do {
			ednsFlags = 0x8000 // DO bit
		}

		buf = append(buf, 0, ednsVersion)
		buf = binary.BigEndian.AppendUint16(buf, ednsFlags)
		buf = binary.BigEndian.AppendUint16(buf, 0) // RDLENGTH
	}

	return buf
}

// parsedRR holds one resource record parsed from a DNS response.
type parsedRR struct {
	name  string
	rtype uint16
	ttl   uint32
	rdata []byte
}

// dnsMsg is a parsed DNS response.
type dnsMsg struct {
	id         uint16
	flags      uint16
	rcode      uint16
	answers    []parsedRR
	authority  []parsedRR
	additional []parsedRR // non-OPT records
	hasOPT     bool       // OPT record present in additional
	doBit      bool       // DO bit set in OPT response
}

var (
	errMsgTooShort = errors.New("message too short")
	errBadName     = errors.New("malformed domain name")
)

// parseResponse parses a DNS wire-format response message.
func parseResponse(msg []byte) (*dnsMsg, error) {
	if len(msg) < dnsHeaderLen {
		return nil, errMsgTooShort
	}

	flags := binary.BigEndian.Uint16(msg[2:4])
	m := &dnsMsg{
		id:    binary.BigEndian.Uint16(msg[0:2]),
		flags: flags,
		rcode: flags & 0xf,
	}

	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	nscount := int(binary.BigEndian.Uint16(msg[8:10]))
	arcount := int(binary.BigEndian.Uint16(msg[10:12]))

	off := dnsHeaderLen

	// Skip question section.
	for i := 0; i < qdcount; i++ {
		_, newOff, err := parseName(msg, off)
		if err != nil {
			return nil, fmt.Errorf("question: %w", err)
		}

		off = newOff + 4 // skip QTYPE + QCLASS

		if off > len(msg) {
			return nil, errMsgTooShort
		}
	}

	parseSection := func(count, startOff int) ([]parsedRR, int, error) {
		off := startOff
		rrs := make([]parsedRR, 0, count)

		for i := 0; i < count; i++ {
			name, newOff, err := parseName(msg, off)
			if err != nil {
				return nil, off, fmt.Errorf("RR name: %w", err)
			}

			off = newOff

			if off+10 > len(msg) {
				return nil, off, errMsgTooShort
			}

			rtype := binary.BigEndian.Uint16(msg[off : off+2])
			ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
			rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
			off += 10

			if off+rdlen > len(msg) {
				return nil, off, errMsgTooShort
			}

			rdata := make([]byte, rdlen)
			copy(rdata, msg[off:off+rdlen])
			off += rdlen

			rrs = append(
				rrs,
				parsedRR{name: name, rtype: rtype, ttl: ttl, rdata: rdata},
			)
		}

		return rrs, off, nil
	}

	var err error

	m.answers, off, err = parseSection(ancount, off)
	if err != nil {
		return nil, fmt.Errorf("answers: %w", err)
	}

	m.authority, off, err = parseSection(nscount, off)
	if err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}

	additional, _, err := parseSection(arcount, off)
	if err != nil {
		return nil, fmt.Errorf("additional: %w", err)
	}

	for _, rr := range additional {
		if rr.rtype == optRRType {
			m.hasOPT = true
			// OPT TTL layout: [0]=ext-rcode [1]=version [2:4]=flags; DO bit = 0x8000 of flags
			if rr.ttl&0x00008000 != 0 {
				m.doBit = true
			}
		} else {
			m.additional = append(m.additional, rr)
		}
	}

	return m, nil
}

// parseName parses a wire-format domain name starting at msg[off].
// Handles RFC 1035 §4.1.4 compression pointers.
// Returns the FQDN (with trailing dot) and the offset just past the name
// at the original position (not following pointer jumps).
func parseName(msg []byte, off int) (string, int, error) {
	var labels []string

	origOff := -1   // position after the first compression pointer, if any
	maxJumps := 128 // guard against pointer loops
	visited := make(map[int]bool)

	for {
		if off >= len(msg) {
			return "", 0, errBadName
		}

		b := msg[off]

		if b == 0 {
			off++
			break
		}

		if b&0xC0 == 0xC0 {
			// Compression pointer: 2-byte offset into message.
			if off+1 >= len(msg) {
				return "", 0, errBadName
			}

			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)

			if origOff == -1 {
				origOff = off + 2 // save position after pointer for caller
			}

			if visited[ptr] || maxJumps == 0 {
				return "", 0, errBadName
			}

			visited[ptr] = true
			maxJumps--
			off = ptr

			continue
		}

		if b&0xC0 != 0 {
			return "", 0, errBadName // reserved
		}

		labelLen := int(b)
		off++

		if off+labelLen > len(msg) {
			return "", 0, errBadName
		}

		labels = append(labels, string(msg[off:off+labelLen]))
		off += labelLen
	}

	if origOff != -1 {
		off = origOff
	}

	if len(labels) == 0 {
		return ".", off, nil
	}

	return strings.Join(labels, ".") + ".", off, nil
}

// parseUncompressedDomain parses a domain from a standalone byte slice (e.g. RDATA).
// Compression pointers are not expected and cause an error.
func parseUncompressedDomain(data []byte, off int) (string, int, error) {
	var labels []string

	for off < len(data) {
		b := data[off]

		if b == 0 {
			off++
			break
		}

		if b&0xC0 == 0xC0 {
			return "", 0, errors.New("unexpected compression pointer in RDATA")
		}

		labelLen := int(b)
		off++

		if off+labelLen > len(data) {
			return "", 0, errors.New("label extends beyond data")
		}

		labels = append(labels, string(data[off:off+labelLen]))
		off += labelLen
	}

	if len(labels) == 0 {
		return ".", off, nil
	}

	return strings.Join(labels, ".") + ".", off, nil
}
