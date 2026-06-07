// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"bytes"
	"encoding/binary"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/query"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// buildOptQuery builds a DNS query with an OPT record in the additional section.
// doSet controls the DO bit, version sets the EDNS version, udpSize sets the
// advertised UDP payload size. Returns the full message and pos (offset after question).
func buildOptQuery(
	name string,
	qtype uint16,
	doSet bool,
	version uint8,
	udpSize uint16,
) ([]byte, int) {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, uint16(1)) // ID
	binary.Write(&buf, binary.BigEndian, uint16(0)) // flags
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QDCOUNT=1
	binary.Write(&buf, binary.BigEndian, uint16(0)) // ANCOUNT=0
	binary.Write(&buf, binary.BigEndian, uint16(0)) // NSCOUNT=0
	binary.Write(&buf, binary.BigEndian, uint16(1)) // ARCOUNT=1 (OPT)

	qname := wireName(name)
	buf.Write(qname)
	binary.Write(&buf, binary.BigEndian, qtype)
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS=IN

	pos := 12 + len(qname) + 4 // offset immediately after question section
	// OPT RR (RFC 6891): root name + type 41 + class + TTL(extended) + RDLENGTH
	buf.WriteByte(0)                                 // name: root label (0x00)
	binary.Write(&buf, binary.BigEndian, uint16(41)) // type OPT
	binary.Write(&buf, binary.BigEndian, udpSize)    // class = UDP payload size
	binary.Write(
		&buf,
		binary.BigEndian,
		uint8(0),
	) // TTL byte 0: extended RCODE high
	binary.Write(&buf, binary.BigEndian, version) // TTL byte 1: EDNS version

	var extFlags uint16
	if doSet {
		extFlags = dnssec.EDNSDOBit
	}

	binary.Write(
		&buf,
		binary.BigEndian,
		extFlags,
	) // TTL bytes 2-3: flags (DO bit)
	binary.Write(&buf, binary.BigEndian, uint16(0)) // RDLENGTH=0

	return buf.Bytes(), pos
}

func TestParseOPT_NoOPT(t *testing.T) {
	msg := wireQuery(1, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA])
	qname := wireName("ns1.xfx1.de.")
	pos := 12 + len(qname) + 4

	edns := parseOPT(msg, pos)
	if edns.present {
		t.Error("present = true, want false (no OPT record)")
	}
}

func TestParseOPT_WithoutDO(t *testing.T) {
	msg, pos := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		0,
		4096,
	)

	edns := parseOPT(msg, pos)
	if !edns.present {
		t.Fatal("present = false, want true")
	}

	if edns.do {
		t.Error("do = true, want false")
	}

	if edns.version != 0 {
		t.Errorf("version = %d, want 0", edns.version)
	}

	if edns.udpSize != 4096 {
		t.Errorf("udpSize = %d, want 4096", edns.udpSize)
	}
}

func TestParseOPT_WithDO(t *testing.T) {
	msg, pos := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		true,
		0,
		4096,
	)

	edns := parseOPT(msg, pos)
	if !edns.present {
		t.Fatal("present = false, want true")
	}

	if !edns.do {
		t.Error("do = false, want true")
	}

	if edns.udpSize != 4096 {
		t.Errorf("udpSize = %d, want 4096", edns.udpSize)
	}
}

func TestParseOPT_Version1(t *testing.T) {
	msg, pos := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		1,
		4096,
	)

	edns := parseOPT(msg, pos)
	if !edns.present {
		t.Fatal("present = false, want true")
	}

	if edns.version != 1 {
		t.Errorf("version = %d, want 1", edns.version)
	}
}

func TestParseOPT_SmallUDPSize(t *testing.T) {
	msg, pos := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		0,
		512,
	)

	edns := parseOPT(msg, pos)
	if !edns.present {
		t.Fatal("present = false, want true")
	}

	if edns.udpSize != 512 {
		t.Errorf("udpSize = %d, want 512", edns.udpSize)
	}
}

func TestParseOPT_PointerCompressed(t *testing.T) {
	// Build a message with ARCOUNT=2: first additional RR uses a pointer-compressed
	// name (exercises skipName's 0xC0 branch), second is an OPT with DO bit set.
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, uint16(1)) // ID
	binary.Write(&buf, binary.BigEndian, uint16(0)) // FLAGS
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QDCOUNT=1
	binary.Write(&buf, binary.BigEndian, uint16(0)) // ANCOUNT=0
	binary.Write(&buf, binary.BigEndian, uint16(0)) // NSCOUNT=0
	binary.Write(&buf, binary.BigEndian, uint16(2)) // ARCOUNT=2

	// Question: ns1.xfx1.de. A IN
	qname := wireName("ns1.xfx1.de.")
	buf.Write(qname)
	binary.Write(&buf, binary.BigEndian, rec.RRtypeToWire[rec.TypeA])
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS=IN

	pos := 12 + len(qname) + 4 // start of additional section

	// Pointer to the root label at the end of qname (offset 12+len(qname)-1).
	rootOffset := byte(12 + len(qname) - 1)

	buf.WriteByte(0xC0)                              // pointer high byte
	buf.WriteByte(rootOffset)                        // pointer low byte
	binary.Write(&buf, binary.BigEndian, uint16(28)) // AAAA type (not OPT)
	binary.Write(&buf, binary.BigEndian, uint16(1))  // CLASS=IN
	binary.Write(&buf, binary.BigEndian, uint32(0))  // TTL
	binary.Write(&buf, binary.BigEndian, uint16(16)) // RDLENGTH=16
	buf.Write(make([]byte, 16))                      // fake AAAA rdata

	// OPT RR with DO bit set.
	buf.WriteByte(0)                                   // name: root label
	binary.Write(&buf, binary.BigEndian, uint16(41))   // type OPT
	binary.Write(&buf, binary.BigEndian, uint16(4096)) // UDP payload size
	binary.Write(
		&buf,
		binary.BigEndian,
		uint16(0),
	) // TTL upper: ext-rcode=0, version=0
	binary.Write(
		&buf,
		binary.BigEndian,
		uint16(dnssec.EDNSDOBit),
	) // TTL lower: DO bit
	binary.Write(&buf, binary.BigEndian, uint16(0)) // RDLENGTH=0

	edns := parseOPT(buf.Bytes(), pos)
	if !edns.present {
		t.Fatal("present = false, want true")
	}

	if !edns.do {
		t.Error(
			"do = false, want true (pointer-compressed additional + OPT with DO bit)",
		)
	}

	if edns.version != 0 {
		t.Errorf("version = %d, want 0", edns.version)
	}

	if edns.udpSize != 4096 {
		t.Errorf("udpSize = %d, want 4096", edns.udpSize)
	}
}

// FuzzParseOPT mirrors the live call chain: parse the input as a query first
// and only feed parseOPT a pos that query.New approved. This is exactly the
// flow in slave.handleDNS, so any panic the fuzzer finds is reachable from a
// public UDP/TCP/DoH client.
//
// Run ad-hoc with `task fuzz`. Under plain `go test` only the seed corpus runs.
func FuzzParseOPT(f *testing.F) {
	seed, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		true,
		0,
		4096,
	)
	f.Add(seed)

	seedNoOPT, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		0,
		512,
	)
	f.Add(seedNoOPT)

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := query.New(data)
		if err != nil {
			return
		}

		opt := parseOPT(data, req.QuestionEnd())
		t.Logf("parseOPT(%x, %d) = %+v", data, req.QuestionEnd(), opt)
	})
}
