// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

// Package response provides shared DNS wire-format response building primitives
// used across the slave, router, and rfc2136 packages.
package response

import (
	"bytes"
	"encoding/binary"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

const (
	// DNS header flag bits (RFC 1035 §4.1.1).
	FlagQR uint16 = 1 << 15 // query/response: 1 = response
	FlagAA uint16 = 1 << 10 // authoritative answer
	FlagTC uint16 = 1 << 9  // truncated
	FlagRD uint16 = 1 << 8  // recursion desired (copied from query)

	// Standard DNS RCODEs (RFC 1035 §4.1.1).
	RcodeNoError  uint16 = 0
	RcodeServFail uint16 = 2
	RcodeNXDomain uint16 = 3
	RcodeRefused  uint16 = 5

	// EDNS OPT record constants (RFC 6891).
	optType     uint16 = 41   // OPT pseudo-RR type
	optUDPSize  uint16 = 4096 // UDP payload size we advertise
	ednsVersion        = 0    // EDNS version 0
)

// BuildResponse constructs a DNS response message.
func BuildResponse(
	txid, queryFlags uint16,
	question []byte,
	answers, additional, authority []*rec.RR,
	rcode uint16,
) []byte {
	var buf []byte

	// ID
	buf = binary.BigEndian.AppendUint16(buf, txid)

	// Flags: QR=1, AA=1, RD copied from query, rcode
	rd := queryFlags & FlagRD
	respFlags := FlagQR | FlagAA | rd | (rcode & 0xf)
	buf = binary.BigEndian.AppendUint16(buf, respFlags)

	// QDCOUNT
	qdCount := uint16(0)
	if question != nil {
		qdCount = 1
	}

	buf = binary.BigEndian.AppendUint16(buf, qdCount)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(answers)))    // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(authority)))  // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(additional))) // ARCOUNT

	// Question section (copied verbatim from query).
	buf = append(buf, question...)

	// Answer section.
	for _, rr := range answers {
		b := bytes.NewBuffer(nil)

		if err := rr.BinaryWrite(b); err != nil {
			panic(err)
		}

		buf = append(buf, b.Bytes()...)
	}

	// Authority section.
	for _, rr := range authority {
		b := bytes.NewBuffer(nil)

		if err := rr.BinaryWrite(b); err != nil {
			panic(err)
		}

		buf = append(buf, b.Bytes()...)
	}

	// Additional section.
	for _, rr := range additional {
		b := bytes.NewBuffer(nil)

		if err := rr.BinaryWrite(b); err != nil {
			panic(err)
		}

		buf = append(buf, b.Bytes()...)
	}

	return buf
}

// RefusedResponse builds a minimal REFUSED response.
func RefusedResponse(txid, queryFlags uint16) []byte {
	return BuildResponse(txid, queryFlags, nil, nil, nil, nil, RcodeRefused)
}

// ServfailResponse builds a minimal SERVFAIL response.
func ServfailResponse(txid, queryFlags uint16) []byte {
	return BuildResponse(txid, queryFlags, nil, nil, nil, nil, RcodeServFail)
}

// TruncatedResponse builds a minimal TC=1 response. Set aa to true for
// authoritative servers truncating an oversized UDP response.
func TruncatedResponse(txid, queryFlags uint16, aa bool) []byte {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], txid)

	rd := queryFlags & FlagRD

	flags := FlagQR | FlagTC | rd
	if aa {
		flags |= FlagAA
	}

	binary.BigEndian.PutUint16(resp[2:4], flags)

	return resp
}

// AppendOPT appends an OPT record to a DNS response message and increments
// ARCOUNT by 1. It advertises a 4096-byte UDP payload size.
//
// Parameters:
//   - msg: the response built so far (must have a 12-byte header)
//   - do: whether to set the DO bit in the response
//   - extRcodeHigh: upper 8 bits of extended RCODE (0 for normal, 1 for BADVERS)
func AppendOPT(msg []byte, do bool, extRcodeHigh uint8) []byte {
	if len(msg) < 12 {
		return msg
	}

	// Increment ARCOUNT.
	arCount := binary.BigEndian.Uint16(msg[10:12])
	binary.BigEndian.PutUint16(msg[10:12], arCount+1)

	var flags uint16

	if do {
		flags = dnssec.EDNSDOBit
	}

	// OPT RR wire format (RFC 6891 §6.1.2): 11 bytes total.
	msg = append(msg, 0x00)                           // name: root
	msg = binary.BigEndian.AppendUint16(msg, optType) // type: OPT
	msg = binary.BigEndian.AppendUint16(
		msg,
		optUDPSize,
	) // class: UDP payload size
	msg = append(
		msg,
		extRcodeHigh,
		ednsVersion,
	) // TTL[0:1]: extended RCODE, EDNS version
	msg = binary.BigEndian.AppendUint16(
		msg,
		flags,
	) // TTL[2:3]: flags (DO bit)
	msg = binary.BigEndian.AppendUint16(msg, 0) // RDLENGTH: 0

	return msg
}
