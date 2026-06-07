// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// RR is a single DNS resource record.
//
// NOTE: Class is intentionally absent. DNS class is always IN (internet,
// value 1) for all records in this server. Wire format writers must insert
// class IN (uint16 = 1) unconditionally when serialising an RR.
type RR struct {
	Name   Domain `json:"name"`
	RRtype RRtype `json:"rrtype"`
	TTL    RRttl  `json:"ttl"`
	Opts   RRopts `json:"payload"`
}

// NewRR constructs an RR with TTL set to DefaultTTL.
// Callers that need a specific TTL should set rr.TTL after construction.
func NewRR(name Domain, opts RRopts) *RR {
	return &RR{
		Name:   name,
		RRtype: opts.RRtype(),
		TTL:    DefaultTTL,
		Opts:   opts,
	}
}

// UnmarshalJSON implements custom unmarshalling.
// It reads "rrtype" first, then dispatches to the correct concrete RRopts type.
func (rr *RR) UnmarshalJSON(data []byte) error {
	type alias RR

	s := struct {
		*alias
		Payload json.RawMessage `json:"payload"`
	}{
		alias: (*alias)(rr),
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	opts, err := rroptsUnmarshalJSON(s.RRtype, s.Payload)
	if err != nil {
		return fmt.Errorf("unmarshalling RRopts: %w", err)
	}

	*rr = RR{
		Name:   s.Name,
		RRtype: s.RRtype,
		TTL:    s.TTL,
		Opts:   opts,
	}

	return nil
}

// BinaryWrite writes the full DNS wire format of this RR to buf.
// Class IN (uint16 = 1) is inserted unconditionally — DNS class is always IN for this server.
func (rr *RR) BinaryWrite(buf *bytes.Buffer) error {
	if err := rr.Name.Write(buf); err != nil {
		return err
	}
	// RRtype as uint16 big-endian; use RRtypeToWire for the wire value
	wireType, ok := RRtypeToWire[rr.RRtype]
	if !ok {
		return fmt.Errorf("unknown RRtype for wire encoding: %s", rr.RRtype)
	}

	if err := binary.Write(buf, binary.BigEndian, wireType); err != nil {
		return err
	}
	// Class IN = 1, always inserted unconditionally
	if err := binary.Write(buf, binary.BigEndian, uint16(1)); err != nil {
		return err
	}

	if err := binary.Write(buf, binary.BigEndian, rr.TTL); err != nil {
		return err
	}

	payload := rr.Opts.Payload()
	if err := binary.Write(buf, binary.BigEndian, uint16(len(payload))); err != nil {
		return err
	}

	if err := binary.Write(buf, binary.BigEndian, payload); err != nil {
		return err
	}

	return nil
}
