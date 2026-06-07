// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package response_test

import (
	"encoding/binary"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
)

func TestAppendOPT(t *testing.T) {
	// Start with a minimal 12-byte DNS header with ARCOUNT=0.
	baseMsg := func() []byte {
		var buf [12]byte

		return buf[:]
	}

	tests := []struct {
		name         string
		do           bool
		extRcodeHigh uint8
		wantDO       bool
		wantExtRcode uint8
	}{
		{"basic no DO", false, 0, false, 0},
		{"with DO", true, 0, true, 0},
		{"BADVERS", false, 1, false, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := baseMsg()
			msg = response.AppendOPT(msg, tt.do, tt.extRcodeHigh)

			// ARCOUNT should be 1.
			arCount := binary.BigEndian.Uint16(msg[10:12])
			if arCount != 1 {
				t.Errorf("ARCOUNT = %d, want 1", arCount)
			}

			// OPT RR starts at offset 12 and is 11 bytes.
			if len(msg) != 23 {
				t.Fatalf("len(msg) = %d, want 23", len(msg))
			}

			opt := msg[12:]
			if opt[0] != 0x00 {
				t.Errorf("OPT name = %d, want 0 (root)", opt[0])
			}

			if binary.BigEndian.Uint16(opt[1:3]) != 41 {
				t.Errorf(
					"OPT type = %d, want 41",
					binary.BigEndian.Uint16(opt[1:3]),
				)
			}

			if binary.BigEndian.Uint16(opt[3:5]) != 4096 {
				t.Errorf(
					"OPT class (UDP size) = %d, want 4096",
					binary.BigEndian.Uint16(opt[3:5]),
				)
			}

			if opt[5] != tt.wantExtRcode {
				t.Errorf(
					"OPT ext-rcode high = %d, want %d",
					opt[5],
					tt.wantExtRcode,
				)
			}

			if opt[6] != 0 {
				t.Errorf("OPT version = %d, want 0", opt[6])
			}

			gotDO := binary.BigEndian.Uint16(opt[7:9])&dnssec.EDNSDOBit != 0
			if gotDO != tt.wantDO {
				t.Errorf("OPT DO = %v, want %v", gotDO, tt.wantDO)
			}

			if binary.BigEndian.Uint16(opt[9:11]) != 0 {
				t.Errorf(
					"OPT RDLENGTH = %d, want 0",
					binary.BigEndian.Uint16(opt[9:11]),
				)
			}
		})
	}
}
