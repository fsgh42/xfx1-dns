// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

import (
	"bytes"
	"encoding/binary"
	"net"
	"slices"
	"strings"
)

// RRopts carries the RDATA for a specific DNS record type.
// Payload() returns the RDATA encoded in DNS wire format.
// Payload() may panic on encoding errors — these represent programmer errors
// (bad data in a struct that should have been validated earlier), not runtime failures.
type RRopts interface {
	RRtype() RRtype
	Payload() []byte
}

// RRoptsA is a DNS record of type A (IPv4 address).
// https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1
type RRoptsA struct {
	Target net.IP `json:"address"`
}

// RRoptsAAAA is a DNS record of type AAAA (IPv6 address).
// https://www.rfc-editor.org/rfc/rfc3596.html#section-2.2
type RRoptsAAAA struct {
	Target net.IP `json:"address"`
}

// RRoptsNS is a DNS record of type NS.
// https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.11
type RRoptsNS struct {
	Ns Domain `json:"nsdname"`
}

// RRoptsCNAME is a DNS record of type CNAME.
// https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.1
type RRoptsCNAME struct {
	Cname Domain `json:"cname"`
}

// RRoptsSOA is a DNS record of type SOA.
// https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13
type RRoptsSOA struct {
	Mname   Domain `json:"mname"`
	Rname   Domain `json:"rname"`
	Serial  uint32 `json:"serial"` // set automatically by master from Unix timestamp; overwritten on every rebuild
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// RRoptsPTR is a DNS record of type PTR.
// https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.12
type RRoptsPTR struct {
	Ptr Domain `json:"ptrdname"`
}

// RRoptsMX is a DNS record of type MX.
// https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.9
type RRoptsMX struct {
	Preference uint16 `json:"preference"`
	Mx         Domain `json:"exchange"`
}

// RRoptsTXT is a DNS record of type TXT.
// https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.14
type RRoptsTXT struct {
	Txt string `json:"txtdata"`
}

// RRoptsSRV is a DNS record of type SRV.
// https://www.rfc-editor.org/rfc/rfc2782
type RRoptsSRV struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   Domain `json:"target"`
}

// RRoptsCAA is a DNS record of type CAA (Certification Authority Authorization).
// https://www.rfc-editor.org/rfc/rfc8659
type RRoptsCAA struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`   // e.g. "issue", "issuewild", "iodef"
	Value string `json:"value"` // e.g. "letsencrypt.org"
}

func (opts RRoptsA) RRtype() RRtype  { return TypeA }
func (opts RRoptsA) Payload() []byte { return opts.Target.To4() }

func (opts RRoptsAAAA) RRtype() RRtype  { return TypeAAAA }
func (opts RRoptsAAAA) Payload() []byte { return opts.Target.To16() }

func (opts RRoptsNS) RRtype() RRtype { return TypeNS }
func (opts RRoptsNS) Payload() []byte {
	var buf bytes.Buffer
	if err := opts.Ns.Write(&buf); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func (opts RRoptsCNAME) RRtype() RRtype { return TypeCNAME }
func (opts RRoptsCNAME) Payload() []byte {
	var buf bytes.Buffer
	if err := opts.Cname.Write(&buf); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func (opts RRoptsSOA) RRtype() RRtype { return TypeSOA }
func (opts RRoptsSOA) Payload() []byte {
	var buf bytes.Buffer
	if err := opts.Mname.Write(&buf); err != nil {
		panic(err)
	}

	if err := opts.Rname.Write(&buf); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Serial); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Refresh); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Retry); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Expire); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Minimum); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func (opts RRoptsPTR) RRtype() RRtype { return TypePTR }
func (opts RRoptsPTR) Payload() []byte {
	var buf bytes.Buffer
	if err := opts.Ptr.Write(&buf); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func (opts RRoptsMX) RRtype() RRtype { return TypeMX }
func (opts RRoptsMX) Payload() []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, opts.Preference); err != nil {
		panic(err)
	}

	if err := opts.Mx.Write(&buf); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func (opts RRoptsTXT) RRtype() RRtype { return TypeTXT }
func (opts RRoptsTXT) Payload() []byte {
	// RFC 1035 §3.3.14: TXT RDATA is one or more <character-string>s, each
	// up to 255 bytes, prefixed by a 1-byte length. Split long values into
	// 255-byte chunks so DKIM keys and other long TXT records are encoded correctly.
	var buf bytes.Buffer

	s := opts.Txt
	for len(s) > 0 {
		chunk := s
		if len(chunk) > 255 {
			chunk = s[:255]
		}

		buf.WriteByte(byte(len(chunk)))
		buf.WriteString(chunk)
		s = s[len(chunk):]
	}

	return buf.Bytes()
}

func (opts RRoptsSRV) RRtype() RRtype { return TypeSRV }
func (opts RRoptsSRV) Payload() []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, opts.Priority); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Weight); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Port); err != nil {
		panic(err)
	}

	if err := opts.Target.Write(&buf); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func (opts RRoptsCAA) RRtype() RRtype { return TypeCAA }
func (opts RRoptsCAA) Payload() []byte {
	// RFC 8659 §4: flags (1) + tag-length (1) + tag + value
	var buf bytes.Buffer

	buf.WriteByte(opts.Flags)
	buf.WriteByte(byte(len(opts.Tag)))
	buf.WriteString(opts.Tag)
	buf.WriteString(opts.Value)

	return buf.Bytes()
}

// RRoptsRRSIG is a DNSSEC RRSIG record (RFC 4034 §3).
// Payload() encodes all fields into DNS wire format on each call.
// https://www.rfc-editor.org/rfc/rfc4034#section-3
type RRoptsRRSIG struct {
	TypeCovered uint16 `json:"typeCovered"` // wire type of the covered RRset
	Algorithm   uint8  `json:"algorithm"`
	Labels      uint8  `json:"labels"`
	OrigTTL     uint32 `json:"origTTL"`
	Expiration  uint32 `json:"expiration"` // Unix seconds
	Inception   uint32 `json:"inception"`  // Unix seconds
	KeyTag      uint16 `json:"keyTag"`
	SignerName  string `json:"signerName"` // FQDN with trailing dot
	Signature   []byte `json:"signature"`  // raw signature bytes
}

// RRoptsDNSKEY is a DNSSEC DNSKEY record (RFC 4034 §2).
// https://www.rfc-editor.org/rfc/rfc4034#section-2
type RRoptsDNSKEY struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey []byte `json:"publicKey"` // raw bytes, stored base64 in JSON
}

// RRoptsDS is a DNSSEC DS record (RFC 4034 §5).
// https://www.rfc-editor.org/rfc/rfc4034#section-5
type RRoptsDS struct {
	KeyTag     uint16 `json:"keyTag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digestType"`
	Digest     []byte `json:"digest"` // raw bytes, stored base64 in JSON
}

// RRoptsNSEC3 is a DNSSEC NSEC3 record (RFC 5155 §3).
// Structured fields (not opaque wire bytes) enable RebuildNSEC3Chain
// to reconstruct the chain without parsing wire data.
// https://www.rfc-editor.org/rfc/rfc5155#section-3
type RRoptsNSEC3 struct {
	HashAlgorithm uint8    `json:"hashAlgorithm"`
	Flags         uint8    `json:"flags"`
	Iterations    uint16   `json:"iterations"`
	Salt          []byte   `json:"salt"`     // may be empty
	NextHash      []byte   `json:"nextHash"` // raw hash bytes of next owner
	Types         []uint16 `json:"types"`    // sorted ascending RR type numbers
}

// RRoptsNSEC3PARAM is a DNSSEC NSEC3PARAM record (RFC 5155 §4).
// https://www.rfc-editor.org/rfc/rfc5155#section-4
type RRoptsNSEC3PARAM struct {
	HashAlgorithm uint8  `json:"hashAlgorithm"`
	Flags         uint8  `json:"flags"`
	Iterations    uint16 `json:"iterations"`
	Salt          []byte `json:"salt"` // may be empty; stored base64 in JSON
}

func (opts *RRoptsRRSIG) RRtype() RRtype { return TypeRRSIG }
func (opts *RRoptsRRSIG) Payload() []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, opts.TypeCovered); err != nil {
		panic(err)
	}

	buf.WriteByte(opts.Algorithm)
	buf.WriteByte(opts.Labels)

	if err := binary.Write(&buf, binary.BigEndian, opts.OrigTTL); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Expiration); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.Inception); err != nil {
		panic(err)
	}

	if err := binary.Write(&buf, binary.BigEndian, opts.KeyTag); err != nil {
		panic(err)
	}
	// Signer name in wire format: lowercase, uncompressed (RFC 4034 §6.2)
	signer := Domain(strings.ToLower(opts.SignerName))
	if err := signer.Write(&buf); err != nil {
		panic(err)
	}

	buf.Write(opts.Signature)

	return buf.Bytes()
}

func (opts *RRoptsDNSKEY) RRtype() RRtype { return TypeDNSKEY }
func (opts *RRoptsDNSKEY) Payload() []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, opts.Flags); err != nil {
		panic(err)
	}

	buf.WriteByte(opts.Protocol)
	buf.WriteByte(opts.Algorithm)
	buf.Write(opts.PublicKey)

	return buf.Bytes()
}

func (opts *RRoptsDS) RRtype() RRtype { return TypeDS }
func (opts *RRoptsDS) Payload() []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, opts.KeyTag); err != nil {
		panic(err)
	}

	buf.WriteByte(opts.Algorithm)
	buf.WriteByte(opts.DigestType)
	buf.Write(opts.Digest)

	return buf.Bytes()
}

func (opts *RRoptsNSEC3) RRtype() RRtype { return TypeNSEC3 }
func (opts *RRoptsNSEC3) Payload() []byte {
	var buf bytes.Buffer

	buf.WriteByte(opts.HashAlgorithm)
	buf.WriteByte(opts.Flags)

	if err := binary.Write(&buf, binary.BigEndian, opts.Iterations); err != nil {
		panic(err)
	}

	buf.WriteByte(uint8(len(opts.Salt)))
	buf.Write(opts.Salt)
	buf.WriteByte(uint8(len(opts.NextHash)))
	buf.Write(opts.NextHash)
	// Type bitmap — Types must be sorted ascending
	sorted := make([]uint16, len(opts.Types))
	copy(sorted, opts.Types)
	slices.Sort(sorted)
	buf.Write(TypeBitmap(sorted))

	return buf.Bytes()
}

func (opts *RRoptsNSEC3PARAM) RRtype() RRtype { return TypeNSEC3PARAM }
func (opts *RRoptsNSEC3PARAM) Payload() []byte {
	var buf bytes.Buffer

	buf.WriteByte(opts.HashAlgorithm)
	buf.WriteByte(opts.Flags)

	if err := binary.Write(&buf, binary.BigEndian, opts.Iterations); err != nil {
		panic(err)
	}

	buf.WriteByte(uint8(len(opts.Salt)))
	buf.Write(opts.Salt)

	return buf.Bytes()
}

// TypeBitmap builds the NSEC3/NSEC type bitmap wire bytes from a sorted list of uint16 type values.
// Types must be sorted ascending before calling.
// RFC 4034 §4.1.2 / RFC 5155 §3.2.1.
func TypeBitmap(types []uint16) []byte {
	if len(types) == 0 {
		return nil
	}

	var buf bytes.Buffer
	// Group types by window (high byte of type number)
	i := 0
	for i < len(types) {
		window := types[i] >> 8
		// Collect all types in this window
		bitmap := [32]byte{}

		for i < len(types) && types[i]>>8 == window {
			t := types[i] & 0xff
			bitmap[t/8] |= 1 << (7 - t%8)
			i++
		}
		// Find last non-zero byte
		bitmapLen := 32
		for bitmapLen > 0 && bitmap[bitmapLen-1] == 0 {
			bitmapLen--
		}

		buf.WriteByte(uint8(window))
		buf.WriteByte(uint8(bitmapLen))
		buf.Write(bitmap[:bitmapLen])
	}

	return buf.Bytes()
}
