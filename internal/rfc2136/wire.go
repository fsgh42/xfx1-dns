// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

// Package rfc2136 implements parsing and response building for RFC 2136
// DNS UPDATE messages, TSIG authentication, CR naming, and the translation
// of UPDATE operations to Kubernetes DNSRecord CRD operations.
package rfc2136

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// DNS opcodes
const (
	OpcodeQuery  = 0
	OpcodeUpdate = 5
)

// DNS RCODEs
const (
	RcodeNoError  = 0
	RcodeServFail = 2
	RcodeNotimp   = 4
	RcodeRefused  = 5
	RcodeNotZone  = 10
)

// DNS classes
const (
	ClassIN   = 1
	ClassANY  = 255
	ClassNONE = 254
)

// Wire type for TSIG (RFC 2845)
const TypeTSIG = 250

// Header is a parsed DNS message header (12 bytes).
type Header struct {
	ID      uint16
	QR      bool  // 0=query, 1=response
	Opcode  uint8 // 4 bits
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8 // 3 bits
	Rcode   uint8 // 4 bits
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// RR is a parsed DNS resource record (generic, wire-level).
type RR struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	Rdlength uint16
	Rdata    []byte
}

// Message is a parsed DNS UPDATE message.
// Zone section = QD section (one entry).
// Prerequisite section = AN section.
// Update section = NS section.
// Additional section = AR section (may contain TSIG).
type Message struct {
	Header        Header
	Zone          *RR   // first QD entry
	Prerequisites []*RR // AN section
	Updates       []*RR // NS section
	Additional    []*RR // AR section (excluding TSIG)
	TSIG          *RR   // last AR entry if type=TSIG, nil otherwise
	// Raw holds the original bytes with the TSIG RR stripped, used for MAC computation.
	Raw []byte
}

// ParseMessage parses a DNS UPDATE wire-format message.
// Returns an error if the message is too short or malformed.
// The caller should check msg.Header.Opcode == OpcodeUpdate.
func ParseMessage(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, errors.New("message too short")
	}

	var hdr Header

	hdr.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	hdr.QR = (flags>>15)&1 == 1
	hdr.Opcode = uint8((flags >> 11) & 0xf)
	hdr.AA = (flags>>10)&1 == 1
	hdr.TC = (flags>>9)&1 == 1
	hdr.RD = (flags>>8)&1 == 1
	hdr.RA = (flags>>7)&1 == 1
	hdr.Z = uint8((flags >> 4) & 0x7)
	hdr.Rcode = uint8(flags & 0xf)
	hdr.QDCount = binary.BigEndian.Uint16(data[4:6])
	hdr.ANCount = binary.BigEndian.Uint16(data[6:8])
	hdr.NSCount = binary.BigEndian.Uint16(data[8:10])
	hdr.ARCount = binary.BigEndian.Uint16(data[10:12])

	msg := &Message{
		Header: hdr,
		Raw:    data,
	}

	offset := 12

	// Parse Zone section (QD records — for UPDATE, these are "zone" entries)
	for i := 0; i < int(hdr.QDCount); i++ {
		rr, n, err := parseQuestion(data, offset)
		if err != nil {
			return nil, fmt.Errorf("zone section: %w", err)
		}

		offset += n

		if i == 0 {
			msg.Zone = rr
		}
	}

	// Parse Prerequisite section (AN records)
	for i := 0; i < int(hdr.ANCount); i++ {
		rr, n, err := parseRR(data, offset)
		if err != nil {
			return nil, fmt.Errorf("prerequisite section: %w", err)
		}

		offset += n

		msg.Prerequisites = append(msg.Prerequisites, rr)
	}

	// Parse Update section (NS records)
	for i := 0; i < int(hdr.NSCount); i++ {
		rr, n, err := parseRR(data, offset)
		if err != nil {
			return nil, fmt.Errorf("update section: %w", err)
		}

		offset += n

		msg.Updates = append(msg.Updates, rr)
	}

	// Parse Additional section (AR records)
	// The last record may be a TSIG.
	for i := 0; i < int(hdr.ARCount); i++ {
		rr, n, err := parseRR(data, offset)
		if err != nil {
			return nil, fmt.Errorf("additional section: %w", err)
		}

		offset += n

		if rr.Type == TypeTSIG && i == int(hdr.ARCount)-1 {
			msg.TSIG = rr
			// Raw = message bytes before the TSIG RR, with ARCOUNT decremented by 1.
			// Per RFC 2845 §3.4.2: MAC is over message with TSIG stripped and ARCOUNT -= 1.
			raw := make([]byte, offset-n)
			copy(raw, data[:offset-n])

			arcount := binary.BigEndian.Uint16(raw[10:12])
			if arcount > 0 {
				binary.BigEndian.PutUint16(raw[10:12], arcount-1)
			}

			msg.Raw = raw
		} else {
			msg.Additional = append(msg.Additional, rr)
		}
	}

	return msg, nil
}

// BuildResponse builds a DNS UPDATE response for the given request message with the given RCODE.
// The response mirrors the request ID and opcode, sets QR=1.
func BuildResponse(msg *Message, rcode uint8) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], msg.Header.ID)

	var flags uint16

	flags |= 1 << 15 // QR = response
	flags |= uint16(msg.Header.Opcode) << 11
	flags |= uint16(rcode) & 0xf
	binary.BigEndian.PutUint16(buf[2:4], flags)

	// all counts zero — no records in response
	return buf
}

// parseQuestion parses a DNS question entry (name + type + class) at data[offset].
// Returns the parsed RR (with zero TTL/rdata) and bytes consumed.
func parseQuestion(data []byte, offset int) (*RR, int, error) {
	start := offset

	name, n, err := parseName(data, offset)
	if err != nil {
		return nil, 0, err
	}

	offset += n
	if offset+4 > len(data) {
		return nil, 0, errors.New("question truncated")
	}

	qtype := binary.BigEndian.Uint16(data[offset : offset+2])
	qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4

	rr := &RR{
		Name:  name,
		Type:  qtype,
		Class: qclass,
	}

	return rr, offset - start, nil
}

// parseRR parses a full DNS RR (name + type + class + ttl + rdlength + rdata) at data[offset].
// Returns the parsed RR and bytes consumed.
func parseRR(data []byte, offset int) (*RR, int, error) {
	start := offset

	name, n, err := parseName(data, offset)
	if err != nil {
		return nil, 0, err
	}

	offset += n
	if offset+10 > len(data) {
		return nil, 0, errors.New("RR header truncated")
	}

	rrtype := binary.BigEndian.Uint16(data[offset : offset+2])
	class := binary.BigEndian.Uint16(data[offset+2 : offset+4])
	ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
	rdlength := binary.BigEndian.Uint16(data[offset+8 : offset+10])

	offset += 10
	if offset+int(rdlength) > len(data) {
		return nil, 0, errors.New("RR rdata truncated")
	}

	rdata := make([]byte, rdlength)
	copy(rdata, data[offset:offset+int(rdlength)])
	offset += int(rdlength)

	rr := &RR{
		Name:     name,
		Type:     rrtype,
		Class:    class,
		TTL:      ttl,
		Rdlength: rdlength,
		Rdata:    rdata,
	}

	return rr, offset - start, nil
}

// encodeName encodes a FQDN (with trailing dot) into DNS label wire format.
func encodeName(fqdn string) []byte {
	if fqdn == "." || fqdn == "" {
		return []byte{0}
	}

	// strip trailing dot
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '.' {
		fqdn = fqdn[:len(fqdn)-1]
	}

	var out []byte

	start := 0

	for i := 0; i <= len(fqdn); i++ {
		if i == len(fqdn) || fqdn[i] == '.' {
			label := fqdn[start:i]
			out = append(out, byte(len(label)))
			out = append(out, []byte(label)...)
			start = i + 1
		}
	}

	out = append(out, 0)

	return out
}

// parseName parses a DNS name (label encoding, with pointer compression support)
// starting at data[offset]. Returns the name as a dot-separated string with
// a trailing dot, and the number of bytes consumed at offset (not following pointers).
func parseName(data []byte, offset int) (string, int, error) {
	name := ""
	consumed := 0
	visited := offset
	seen := make(map[int]bool) // guard against pointer cycles

	for {
		if visited >= len(data) {
			return "", 0, errors.New("name parse overrun")
		}

		length := int(data[visited])

		if length == 0 {
			if consumed == 0 {
				consumed = 1
			} else if offset+consumed <= visited {
				consumed = visited - offset + 1
			}

			break
		}

		// Pointer compression: top two bits = 11
		if length&0xc0 == 0xc0 {
			if visited+1 >= len(data) {
				return "", 0, errors.New("pointer truncated")
			}

			ptr := int(
				binary.BigEndian.Uint16(data[visited:visited+2]) & 0x3fff,
			)
			if seen[ptr] {
				return "", 0, errors.New("pointer loop")
			}

			seen[ptr] = true

			if consumed == 0 {
				consumed = visited - offset + 2
			}

			visited = ptr

			continue
		}

		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("invalid label length byte: %02x", length)
		}

		start := visited + 1

		end := start + length
		if end > len(data) {
			return "", 0, errors.New("label overrun")
		}

		if name != "" {
			name += "."
		}

		name += string(data[start:end])

		if consumed == 0 || offset+consumed <= visited+1+length {
			consumed = visited + 1 + length - offset + 1
		}

		visited = end
	}

	if name == "" {
		name = "."
	} else {
		name += "."
	}

	return name, consumed, nil
}
