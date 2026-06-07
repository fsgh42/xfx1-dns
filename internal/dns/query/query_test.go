// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package query_test

import (
	"bytes"
	"errors"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/query"
)

// hdr builds a 12-byte DNS header with the given qdcount; all other fields zero.
func hdr(qdcount uint16) []byte {
	h := make([]byte, 12)
	h[4] = byte(qdcount >> 8)
	h[5] = byte(qdcount)

	return h
}

// hdrWithFlags builds a header with custom flags word (bytes 2-3) and qdcount=1.
func hdrWithFlags(flags uint16) []byte {
	h := hdr(1)
	h[2] = byte(flags >> 8)
	h[3] = byte(flags)

	return h
}

// lbl encodes one DNS label: length byte + data.
func lbl(s string) []byte {
	b := make([]byte, 1+len(s))
	b[0] = byte(len(s))
	copy(b[1:], s)

	return b
}

// qtypeClass encodes a 2-byte qtype followed by qclass IN (0x0001).
func qtypeClass(t uint16) []byte {
	return []byte{byte(t >> 8), byte(t), 0x00, 0x01}
}

// msg assembles a complete DNS query: header(qdcount=1) + encoded labels + root + qtype/qclass.
func msg(labels []string, qt uint16) []byte {
	b := hdr(1)
	for _, l := range labels {
		b = append(b, lbl(l)...)
	}

	b = append(b, 0x00) // root label terminator
	b = append(b, qtypeClass(qt)...)

	return b
}

func TestNew_errors(t *testing.T) {
	tests := []struct {
		name    string
		msg     []byte
		wantErr error
	}{
		{
			name:    "empty message",
			msg:     []byte{},
			wantErr: query.ErrTooShort,
		},
		{
			name:    "header truncated at 11 bytes",
			msg:     make([]byte, 11),
			wantErr: query.ErrTooShort,
		},
		{
			name: "qdcount zero",
			msg: append(
				hdr(0),
				0x00,
				0x00,
				0x01,
				0x00,
				0x01,
			), // root + qtype/class
			wantErr: query.ErrNoQuestion,
		},
		{
			name:    "qdcount two",
			msg:     append(hdr(2), lbl("example")...),
			wantErr: query.ErrMultipleQuestions,
		},
		{
			name:    "compression pointer as first label",
			msg:     append(hdr(1), 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01),
			wantErr: query.ErrCompressionPointer,
		},
		{
			name: "compression pointer after valid label",
			msg: func() []byte {
				b := hdr(1)
				b = append(b, lbl("example")...)
				b = append(
					b,
					0xc0,
					0x0c,
				) // pointer instead of next label or terminator
				b = append(b, qtypeClass(1)...)
				return b
			}(),
			wantErr: query.ErrCompressionPointer,
		},
		{
			name: "label length 64 exceeds maximum",
			msg: func() []byte {
				b := hdr(1)
				b = append(b, 64)
				b = append(b, bytes.Repeat([]byte{'a'}, 64)...)
				b = append(b, 0x00)
				b = append(b, qtypeClass(1)...)
				return b
			}(),
			wantErr: query.ErrLabelTooLong,
		},
		{
			name: "qname wire length exceeds 255 bytes",
			msg: func() []byte {
				// 4 labels of 63 bytes each: 4 * (1+63) = 256 wire bytes → over limit
				b := hdr(1)
				for range 4 {
					b = append(b, 63)
					b = append(b, bytes.Repeat([]byte{'a'}, 63)...)
				}
				b = append(b, 0x00)
				b = append(b, qtypeClass(1)...)
				return b
			}(),
			wantErr: query.ErrQNameTooLong,
		},
		{
			name: "qname exactly 255 from labels, terminator pushes to 256",
			msg: func() []byte {
				// 3 labels of 63 (=192) + 1 label of 62 (=63) = 255 wire bytes from labels.
				// Adding the root terminator brings total to 256 — caught by the
				// terminator-branch overflow check, not the per-label one.
				b := hdr(1)
				for range 3 {
					b = append(b, 63)
					b = append(b, bytes.Repeat([]byte{'a'}, 63)...)
				}
				b = append(b, 62)
				b = append(b, bytes.Repeat([]byte{'b'}, 62)...)
				b = append(b, 0x00)
				b = append(b, qtypeClass(1)...)
				return b
			}(),
			wantErr: query.ErrQNameTooLong,
		},
		{
			name: "label extends beyond end of message",
			msg: func() []byte {
				b := hdr(1)
				b = append(b, 10)       // claims 10 bytes
				b = append(b, 'a', 'b') // only 2 bytes available
				return b
			}(),
			wantErr: query.ErrLabelBeyondMessage,
		},
		{
			name:    "no qtype after qname",
			msg:     append(hdr(1), 0x00), // root label only, nothing after
			wantErr: query.ErrTruncated,
		},
		{
			name: "qtype present but qclass missing",
			msg: append(
				hdr(1),
				0x00,
				0x00,
				0x01,
			), // root + 2 bytes (need 4)
			wantErr: query.ErrTruncated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := query.New(tt.msg)
			if r != nil {
				t.Errorf("expected nil Request, got non-nil")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got error %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew_valid(t *testing.T) {
	t.Run("single label", func(t *testing.T) {
		r, err := query.New(msg([]string{"com"}, 1))
		if err != nil {
			t.Fatal(err)
		}

		if r.QName != "com." {
			t.Errorf("QName = %q, want %q", r.QName, "com.")
		}

		if r.QType != 1 {
			t.Errorf("QType = %d, want 1", r.QType)
		}
	})

	t.Run("multi-label", func(t *testing.T) {
		r, err := query.New(msg([]string{"example", "com"}, 28))
		if err != nil {
			t.Fatal(err)
		}

		if r.QName != "example.com." {
			t.Errorf("QName = %q, want %q", r.QName, "example.com.")
		}

		if r.QType != 28 {
			t.Errorf("QType = %d, want 28", r.QType)
		}
	})

	t.Run("root query", func(t *testing.T) {
		r, err := query.New(msg(nil, 1))
		if err != nil {
			t.Fatal(err)
		}

		if r.QName != "." {
			t.Errorf("QName = %q, want %q for root", r.QName, ".")
		}
	})

	t.Run("punycode label", func(t *testing.T) {
		r, err := query.New(msg([]string{"xn--mnchen-3ya", "de"}, 1))
		if err != nil {
			t.Fatal(err)
		}

		if r.QName != "xn--mnchen-3ya.de." {
			t.Errorf("QName = %q, want %q", r.QName, "xn--mnchen-3ya.de.")
		}
	})

	t.Run("opcode extracted from flags", func(t *testing.T) {
		// opcode 4 sits in flags bits 14:11 → 4 << 11 = 0x2000
		b := hdrWithFlags(0x2000)
		b = append(b, msg([]string{"example", "com"}, 1)[12:]...)

		r, err := query.New(b)
		if err != nil {
			t.Fatal(err)
		}

		if r.Opcode != 4 {
			t.Errorf("Opcode = %d, want 4", r.Opcode)
		}
	})

	t.Run("qname at exact 255-byte boundary succeeds", func(t *testing.T) {
		// 3 labels of 63 (=192) + 1 label of 61 (=62) = 254 wire bytes from labels.
		// Plus root terminator (1 byte) = 255 total, exactly at the RFC limit.
		b := hdr(1)
		for range 3 {
			b = append(b, 63)
			b = append(b, bytes.Repeat([]byte{'a'}, 63)...)
		}

		b = append(b, 61)
		b = append(b, bytes.Repeat([]byte{'b'}, 61)...)
		b = append(b, 0x00)
		b = append(b, qtypeClass(1)...)

		r, err := query.New(b)
		if err != nil {
			t.Fatal(err)
		}

		if r.QName == "" {
			t.Errorf("expected non-empty QName at 255-byte boundary")
		}
	})

	t.Run("Bytes returns original slice", func(t *testing.T) {
		raw := msg([]string{"example", "com"}, 1)

		r, err := query.New(raw)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(r.Bytes(), raw) {
			t.Errorf("Bytes() does not match original message")
		}
	})
}

// FuzzNew exercises query.New with arbitrary bytes — the wire-format input is
// fully attacker-controlled on the public UDP/TCP/DoH paths, so the parser
// must never panic and must never report a question end past its input.
//
// Run ad-hoc with `task fuzz` (or `go test -fuzz=FuzzNew -fuzztime=30s ./...`).
// Under plain `go test` only the seed corpus runs.
func FuzzNew(f *testing.F) {
	f.Add(msg([]string{"com"}, 1))
	f.Add(msg([]string{"example", "com"}, 1))
	f.Add(msg(nil, 1))
	f.Add([]byte{})
	f.Add(make([]byte, 11))
	f.Add(append(hdr(1), 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01))
	f.Add(append(hdr(1), 10, 'a', 'b'))

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := query.New(data)
		t.Logf("New(%x) = %v, err=%v", data, r, err)

		if err != nil {
			if r != nil {
				t.Fatalf("err=%v but Request=%v (must be nil on error)", err, r)
			}

			return
		}

		if r.QuestionEnd() > len(data) {
			t.Fatalf(
				"QuestionEnd=%d > len(data)=%d",
				r.QuestionEnd(),
				len(data),
			)
		}

		if r.QuestionEnd() < 12 {
			t.Fatalf("QuestionEnd=%d < dnsHeaderLen=12", r.QuestionEnd())
		}

		_ = r.ID()
		_ = r.Flags()

		if !bytes.Equal(r.Bytes(), data) {
			t.Fatal("Bytes() must return the original input slice")
		}
	})
}
