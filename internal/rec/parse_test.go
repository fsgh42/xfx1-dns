// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

import (
	"bytes"
	"testing"
)

// encodeNameWire returns the DNS wire encoding of an FQDN using Domain.Write.
func encodeNameWire(fqdn string) []byte {
	var buf bytes.Buffer

	d := Domain(fqdn)
	if err := d.Write(&buf); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func TestParseRdata_A_Valid(t *testing.T) {
	opts, err := ParseRdata(TypeA, []byte{192, 168, 1, 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_A_WrongLength(t *testing.T) {
	_, err := ParseRdata(TypeA, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for 3-byte A rdata")
	}
}

func TestParseRdata_AAAA_Valid(t *testing.T) {
	rdata := make([]byte, 16)
	for i := range rdata {
		rdata[i] = byte(i)
	}

	opts, err := ParseRdata(TypeAAAA, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_AAAA_WrongLength(t *testing.T) {
	_, err := ParseRdata(TypeAAAA, []byte{1, 2, 3, 4})
	if err == nil {
		t.Fatal("expected error for 4-byte AAAA rdata")
	}
}

func TestParseRdata_TXT_Valid(t *testing.T) {
	rdata := append([]byte{5}, []byte("hello")...)

	opts, err := ParseRdata(TypeTXT, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_TXT_MultipleSegments(t *testing.T) {
	rdata := append([]byte{3}, []byte("foo")...)
	rdata = append(rdata, byte(3))
	rdata = append(rdata, []byte("bar")...)

	opts, err := ParseRdata(TypeTXT, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_TXT_Truncated(t *testing.T) {
	rdata := append([]byte{10}, []byte("abc")...)

	_, err := ParseRdata(TypeTXT, rdata)
	if err == nil {
		t.Fatal("expected error for truncated TXT rdata")
	}
}

func TestParseRdata_CNAME(t *testing.T) {
	rdata := encodeNameWire("target.example.com.")

	opts, err := ParseRdata(TypeCNAME, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_NS(t *testing.T) {
	rdata := encodeNameWire("ns1.example.com.")

	opts, err := ParseRdata(TypeNS, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_PTR(t *testing.T) {
	rdata := encodeNameWire("host.example.com.")

	opts, err := ParseRdata(TypePTR, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_MX(t *testing.T) {
	rdata := append([]byte{0, 10}, encodeNameWire("mail.example.com.")...)

	opts, err := ParseRdata(TypeMX, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_SRV(t *testing.T) {
	rdata := append(
		[]byte{0, 10, 0, 20, 0, 80},
		encodeNameWire("svc.example.com.")...)

	opts, err := ParseRdata(TypeSRV, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_CAA(t *testing.T) {
	tag := "issue"
	val := "letsencrypt.org"
	rdata := append(
		[]byte{0, byte(len(tag))},
		append([]byte(tag), []byte(val)...)...)

	opts, err := ParseRdata(TypeCAA, rdata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
}

func TestParseRdata_UnsupportedType(t *testing.T) {
	_, err := ParseRdata(TypeSOA, []byte("somedata"))
	if err == nil {
		t.Fatal("expected error for unsupported type SOA")
	}
}

func TestParseCNAME_MalformedRdata(t *testing.T) {
	_, err := ParseRdata(TypeCNAME, []byte{})
	if err == nil {
		t.Fatal("expected error for empty CNAME rdata")
	}
}

func TestParseNS_MalformedRdata(t *testing.T) {
	_, err := ParseRdata(TypeNS, []byte{})
	if err == nil {
		t.Fatal("expected error for empty NS rdata")
	}
}

func TestParsePTR_MalformedRdata(t *testing.T) {
	_, err := ParseRdata(TypePTR, []byte{})
	if err == nil {
		t.Fatal("expected error for empty PTR rdata")
	}
}

func TestParseMX_MalformedName(t *testing.T) {
	// Valid 2-byte preference but empty name — triggers parseDNSName overrun.
	_, err := ParseRdata(TypeMX, []byte{0, 10})
	if err == nil {
		t.Fatal("expected error for MX with missing name")
	}
}

func TestParseSRV_MalformedName(t *testing.T) {
	// Valid 6-byte header but empty name — triggers parseDNSName overrun.
	_, err := ParseRdata(TypeSRV, []byte{0, 10, 0, 20, 0, 80})
	if err == nil {
		t.Fatal("expected error for SRV with missing name")
	}
}

func TestParseCAA_TruncatedTag(t *testing.T) {
	// tagLen=10 but only one byte of tag data follows.
	_, err := ParseRdata(TypeCAA, []byte{0, 10, 'a'})
	if err == nil {
		t.Fatal("expected error for CAA with truncated tag")
	}
}

func TestParseDNSName_Root(t *testing.T) {
	// Single zero byte encodes the root name ".".
	opts, err := ParseRdata(TypeCNAME, []byte{0x00})
	if err != nil {
		t.Fatalf("unexpected error for root CNAME: %v", err)
	}

	got := opts.(*RRoptsCNAME).Cname
	if got != "." {
		t.Fatalf("expected root domain \".\", got %q", got)
	}
}

func TestParseDNSName_InvalidLabelByte(t *testing.T) {
	// 0x80 has top two bits set but is not a valid compression pointer (0xC0).
	_, err := ParseRdata(TypeCNAME, []byte{0x80})
	if err == nil {
		t.Fatal("expected error for invalid label length byte")
	}
}

func TestParseDNSName_LabelOverrun(t *testing.T) {
	// Label claims 10 bytes but only 3 follow.
	_, err := ParseRdata(TypeCNAME, []byte{0x0A, 'a', 'b', 'c'})
	if err == nil {
		t.Fatal("expected error for label overrun")
	}
}

func TestParseMX_InvalidName(t *testing.T) {
	// Valid 2-byte preference, then an invalid label byte — triggers parseDNSName error.
	_, err := ParseRdata(TypeMX, []byte{0, 10, 0x80})
	if err == nil {
		t.Fatal("expected error for MX with invalid name byte")
	}
}

func TestParseSRV_InvalidName(t *testing.T) {
	// Valid 6-byte header, then an invalid label byte — triggers parseDNSName error.
	_, err := ParseRdata(TypeSRV, []byte{0, 10, 0, 20, 0, 80, 0x80})
	if err == nil {
		t.Fatal("expected error for SRV with invalid name byte")
	}
}

func TestParseCAA_TooShort(t *testing.T) {
	_, err := ParseRdata(TypeCAA, []byte{0})
	if err == nil {
		t.Fatal("expected error for 1-byte CAA rdata")
	}
}
