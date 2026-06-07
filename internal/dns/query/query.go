// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"encoding/binary"
	"errors"
	"strings"
)

const (
	dnsHeaderLen         = 12   // fixed header size per RFC 1035 §4.1.1
	maxLabelLen          = 63   // max single label length per RFC 1035 §2.3.4
	maxQNameWireLen      = 255  // max qname wire length per RFC 1035 §2.3.4
	dnsCompressionMarker = 0xc0 // top-2-bit pattern marking a compression pointer per RFC 1035 §4.1.4
)

var (
	ErrTooShort           = errors.New("message too short")
	ErrNoQuestion         = errors.New("no question")
	ErrMultipleQuestions  = errors.New("multiple questions")
	ErrCompressionPointer = errors.New("compression pointer in question")
	ErrLabelTooLong       = errors.New("label too long")
	ErrQNameTooLong       = errors.New("qname too long")
	ErrLabelBeyondMessage = errors.New("label extends beyond message")
	ErrTruncated          = errors.New("question section truncated")
)

// Request holds the parsed first question from a DNS query message.
// The original wire bytes are retained unchanged for forwarding.
type Request struct {
	raw         []byte
	questionEnd int // byte offset immediately after qtype+qclass
	Opcode      uint8
	QName       string // FQDN with trailing dot, e.g. "example.com."
	QType       uint16
}

// New parses msg and returns its question. Messages with zero or more than one
// question are rejected — real resolvers send exactly one, and anything else is
// either malformed or probing. Returns an error if the message is structurally
// malformed.
//
// Wire format: RFC 1035 §4.1 (message), §4.1.1 (header), §4.1.2 (question section).
func New(msg []byte) (*Request, error) {
	if len(msg) < dnsHeaderLen {
		return nil, ErrTooShort
	}

	flags := binary.BigEndian.Uint16(msg[2:4])
	opcode := uint8((flags >> 11) & 0xf)

	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount == 0 {
		return nil, ErrNoQuestion
	}
	// Real resolvers always send exactly one question; multiple questions are
	// not used in practice and are a sign of a malformed or malicious message.
	if qdcount > 1 {
		return nil, ErrMultipleQuestions
	}

	pos := dnsHeaderLen

	var name strings.Builder

	wireLen := 0 // wire bytes consumed so far

	for pos < len(msg) {
		labelByte := int(msg[pos])

		// A zero-length label is the root label, which terminates the qname in wire format.
		if labelByte == 0 {
			wireLen++
			if wireLen > maxQNameWireLen {
				return nil, ErrQNameTooLong
			}

			pos++

			break
		}

		// Compression pointers (RFC 1035 §4.1.4) are only valid in responses;
		// no legitimate resolver sends them in a query, reject query if set.
		if labelByte&dnsCompressionMarker == dnsCompressionMarker {
			return nil, ErrCompressionPointer
		}

		// Not a terminator or pointer — labelByte is the length of the next label.
		labelLen := labelByte
		if labelLen > maxLabelLen {
			return nil, ErrLabelTooLong
		}

		wireLen += 1 + labelLen
		if wireLen > maxQNameWireLen {
			return nil, ErrQNameTooLong
		}

		pos++
		if pos+labelLen > len(msg) {
			return nil, ErrLabelBeyondMessage
		}

		// Separate labels with a dot, but not before the first one.
		if name.Len() > 0 {
			name.WriteByte('.')
		}

		name.Write(msg[pos : pos+labelLen])
		pos += labelLen
	}

	// Need 4 bytes: 2 for qtype + 2 for qclass.
	if pos+4 > len(msg) {
		return nil, ErrTruncated
	}

	qtype := binary.BigEndian.Uint16(msg[pos : pos+2])

	return &Request{
		raw:         msg,
		questionEnd: pos + 4,
		Opcode:      opcode,
		QName:       name.String() + ".",
		QType:       qtype,
	}, nil
}

// Bytes returns the original wire-format message for forwarding.
func (r *Request) Bytes() []byte { return r.raw }

// ID returns the DNS transaction ID from the message header.
func (r *Request) ID() uint16 { return binary.BigEndian.Uint16(r.raw[0:2]) }

// Flags returns the full flags word from the message header.
func (r *Request) Flags() uint16 { return binary.BigEndian.Uint16(r.raw[2:4]) }

// QuestionEnd returns the byte offset immediately after the question section
// (past qtype and qclass). Use this as the starting position for parsing the
// additional section, e.g. for EDNS OPT records.
func (r *Request) QuestionEnd() int { return r.questionEnd }
