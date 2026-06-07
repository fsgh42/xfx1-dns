// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildUpdateMessage constructs a minimal DNS UPDATE wire message.
// zone: zone FQDN with trailing dot
// updates: slice of pre-encoded RR wire bytes for the NS/update section
func buildUpdateMessage(id uint16, zone string, updates [][]byte) []byte {
	var buf []byte

	// Encode zone question: name + qtype(SOA=6) + qclass(IN=1)
	zoneWire := encodeName(zone)
	zoneWire = append(zoneWire, 0, 6) // QTYPE = SOA
	zoneWire = append(zoneWire, 0, 1) // QCLASS = IN

	// Header
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)

	var flags uint16 = OpcodeUpdate << 11

	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)                     // QDCOUNT=1
	binary.BigEndian.PutUint16(hdr[6:8], 0)                     // ANCOUNT=0
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(updates))) // NSCOUNT
	binary.BigEndian.PutUint16(hdr[10:12], 0)                   // ARCOUNT=0

	buf = append(buf, hdr...)
	buf = append(buf, zoneWire...)

	for _, u := range updates {
		buf = append(buf, u...)
	}

	return buf
}

// buildRRWire builds an RR wire record (for update section).
func buildRRWire(
	name string,
	rrtype, class uint16,
	ttl uint32,
	rdata []byte,
) []byte {
	var out []byte
	out = append(out, encodeName(name)...)
	out = append(out, 0, 0)
	binary.BigEndian.PutUint16(out[len(out)-2:], rrtype)
	out = append(out, 0, 0)
	binary.BigEndian.PutUint16(out[len(out)-2:], class)
	out = append(out, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[len(out)-4:], ttl)
	out = append(out, 0, 0)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(rdata)))
	out = append(out, rdata...)

	return out
}

func TestParseMessage_Valid(t *testing.T) {
	msg := buildUpdateMessage(0x1234, "example.com.", nil)

	m, err := ParseMessage(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Header.ID != 0x1234 {
		t.Errorf("ID: got %04x want 1234", m.Header.ID)
	}

	if m.Header.Opcode != OpcodeUpdate {
		t.Errorf("Opcode: got %d want %d", m.Header.Opcode, OpcodeUpdate)
	}

	if m.Zone == nil {
		t.Fatal("zone is nil")
	}

	if m.Zone.Name != "example.com." {
		t.Errorf("zone name: got %q want %q", m.Zone.Name, "example.com.")
	}
}

func TestParseMessage_WithUpdates(t *testing.T) {
	rr1 := buildRRWire(
		"host.example.com.",
		1, /*A*/
		ClassIN,
		60,
		[]byte{1, 2, 3, 4},
	)
	rr2 := buildRRWire(
		"host.example.com.",
		1, /*A*/
		ClassIN,
		60,
		[]byte{5, 6, 7, 8},
	)
	msg := buildUpdateMessage(1, "example.com.", [][]byte{rr1, rr2})

	m, err := ParseMessage(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(m.Updates) != 2 {
		t.Errorf("expected 2 update RRs, got %d", len(m.Updates))
	}
}

func TestParseMessage_WrongOpcode(t *testing.T) {
	msg := buildUpdateMessage(1, "example.com.", nil)
	// overwrite opcode bits to QUERY (0)
	flags := binary.BigEndian.Uint16(msg[2:4])
	flags &^= 0x7800 // clear opcode bits
	binary.BigEndian.PutUint16(msg[2:4], flags)

	m, err := ParseMessage(msg)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if m.Header.Opcode != OpcodeQuery {
		t.Errorf("expected opcode query, got %d", m.Header.Opcode)
	}
}

func TestParseMessage_Truncated(t *testing.T) {
	_, err := ParseMessage([]byte{0, 1, 2, 3, 4})
	if err == nil {
		t.Fatal("expected error on truncated message")
	}
}

func TestBuildResponse_RoundTrip(t *testing.T) {
	req := buildUpdateMessage(0xABCD, "example.com.", nil)
	m, _ := ParseMessage(req)
	resp := BuildResponse(m, RcodeNoError)

	rm, err := ParseMessage(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	if rm.Header.ID != 0xABCD {
		t.Errorf("ID mismatch: got %04x", rm.Header.ID)
	}

	if !rm.Header.QR {
		t.Error("QR bit not set in response")
	}

	if rm.Header.Rcode != RcodeNoError {
		t.Errorf("rcode: got %d", rm.Header.Rcode)
	}
}

func TestBuildResponse_RCODE(t *testing.T) {
	req := buildUpdateMessage(1, "example.com.", nil)
	m, _ := ParseMessage(req)
	resp := BuildResponse(m, RcodeRefused)

	rm, _ := ParseMessage(resp)
	if rm.Header.Rcode != RcodeRefused {
		t.Errorf("expected REFUSED(%d), got %d", RcodeRefused, rm.Header.Rcode)
	}
}

// TestParseMessage_PointerLoop verifies SEC-01: a self-referencing name pointer
// must return an error, not spin forever.
func TestParseMessage_PointerLoop(t *testing.T) {
	// Header (12 bytes) + self-referencing pointer at offset 12 → 0xC0 0x0C
	data := make([]byte, 14)
	binary.BigEndian.PutUint16(data[0:2], 0x1234)
	binary.BigEndian.PutUint16(data[2:4], OpcodeUpdate<<11)
	binary.BigEndian.PutUint16(data[4:6], 1) // QDCOUNT=1
	data[12] = 0xC0
	data[13] = 0x0C // points back to offset 12

	done := make(chan error, 1)
	go func() {
		_, err := ParseMessage(data)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error on pointer loop, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ParseMessage hung on pointer loop (SEC-01 regression)")
	}
}

func TestParseMessage_PrerequisiteSection(t *testing.T) {
	prereq := buildRRWire("host.example.com.", 1, ClassANY, 0, nil)

	// Build manually with ANCOUNT=1
	zone := encodeName("example.com.")
	zone = append(zone, 0, 6, 0, 1) // SOA, IN

	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 99)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(OpcodeUpdate<<11))
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QD
	binary.BigEndian.PutUint16(hdr[6:8], 1) // AN
	binary.BigEndian.PutUint16(hdr[8:10], 0)
	binary.BigEndian.PutUint16(hdr[10:12], 0)

	var raw []byte
	raw = append(raw, hdr...)
	raw = append(raw, zone...)
	raw = append(raw, prereq...)

	m, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(m.Prerequisites) != 1 {
		t.Errorf("expected 1 prerequisite, got %d", len(m.Prerequisites))
	}
}
