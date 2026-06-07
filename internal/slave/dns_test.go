// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newTestSlave creates a Slave with the example zone pre-loaded.
func newTestSlave(t testing.TB) *Slave {
	t.Helper()

	s := New(crd.DNSConfigSpec{}, log.New[log.Null, log.Logfmt]("test"))
	s.swapDB(exampleDB())

	return s
}

// exampleDB builds a representative xfx1.de zone used across the slave tests.
func exampleDB() *db.DB {
	zone := rec.Domain("xfx1.de.")
	records := []*rec.RR{
		rec.NewRR("xfx1.de.", &rec.RRoptsSOA{
			Mname: "ns1.xfx1.de.", Rname: "hostmaster.xfx1.de.",
			Serial: 2026031201, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
		rec.NewRR("xfx1.de.", &rec.RRoptsNS{Ns: "ns1.xfx1.de."}),
		rec.NewRR("ns1.xfx1.de.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
		rec.NewRR(
			"ns1.xfx1.de.",
			&rec.RRoptsAAAA{Target: net.ParseIP("2001:db8::1")},
		),
		rec.NewRR("www.xfx1.de.", &rec.RRoptsCNAME{Cname: "ns1.xfx1.de."}),
		rec.NewRR(
			"xfx1.de.",
			&rec.RRoptsMX{Preference: 10, Mx: "ns1.xfx1.de."},
		),
		rec.NewRR("xfx1.de.", &rec.RRoptsTXT{Txt: "v=spf1 mx -all"}),
		rec.NewRR("1.3.2.1.in-addr.arpa.", &rec.RRoptsPTR{Ptr: "ns1.xfx1.de."}),
		rec.NewRR(
			"_https._tcp.xfx1.de.",
			&rec.RRoptsSRV{
				Priority: 10,
				Weight:   20,
				Port:     443,
				Target:   "ns1.xfx1.de.",
			},
		),
		// Two A records on the same name — tests multi-answer responses.
		rec.NewRR(
			"multi.xfx1.de.",
			&rec.RRoptsA{Target: net.ParseIP("10.0.0.1")},
		),
		rec.NewRR(
			"multi.xfx1.de.",
			&rec.RRoptsA{Target: net.ParseIP("10.0.0.2")},
		),
		// Two AAAA records on the same name.
		rec.NewRR(
			"multi6.xfx1.de.",
			&rec.RRoptsAAAA{Target: net.ParseIP("2001:db8::1")},
		),
		rec.NewRR(
			"multi6.xfx1.de.",
			&rec.RRoptsAAAA{Target: net.ParseIP("2001:db8::2")},
		),
		// Off-zone CNAME — used to test type-mismatch CNAME fallback.
		rec.NewRR(
			"external.xfx1.de.",
			&rec.RRoptsCNAME{Cname: "foo.internal.invalid."},
		),
		// Wildcard records — catch-all for names under xfx1.de. with no exact match.
		rec.NewRR("*.xfx1.de.", &rec.RRoptsA{Target: net.ParseIP("10.99.0.1")}),
		rec.NewRR(
			"*.xfx1.de.",
			&rec.RRoptsAAAA{Target: net.ParseIP("2001:db8::99")},
		),
	}

	return db.NewDB(zone, records)
}

// wireQuery builds a minimal DNS query message.
func wireQuery(id uint16, name string, qtype uint16) []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, id) // ID
	binary.Write(
		&buf,
		binary.BigEndian,
		uint16(0),
	) // flags: standard query, RD=0
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QDCOUNT=1
	binary.Write(&buf, binary.BigEndian, uint16(0)) // ANCOUNT=0
	binary.Write(&buf, binary.BigEndian, uint16(0)) // NSCOUNT=0
	binary.Write(&buf, binary.BigEndian, uint16(0)) // ARCOUNT=0
	buf.Write(wireName(name))
	binary.Write(&buf, binary.BigEndian, qtype)     // QTYPE
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS=IN

	return buf.Bytes()
}

// wireName encodes a domain name in DNS wire format (length-prefixed labels + root 0).
func wireName(fqdn string) []byte {
	var buf bytes.Buffer

	name := strings.TrimSuffix(fqdn, ".")
	if name == "" {
		buf.WriteByte(0)
		return buf.Bytes()
	}

	for _, label := range strings.Split(name, ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}

	buf.WriteByte(0)

	return buf.Bytes()
}

// respHeader is the decoded DNS response header (12 bytes).
type respHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func parseRespHeader(data []byte) respHeader {
	if len(data) < 12 {
		return respHeader{}
	}

	return respHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}
}

func getRcode(flags uint16) uint16 { return flags & 0xf }
func isAA(flags uint16) bool       { return flags&response.FlagAA != 0 }
func isQR(flags uint16) bool       { return flags&response.FlagQR != 0 }

// ── handleDNS tests ───────────────────────────────────────────────────────────

func TestHandleDNS_A(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(42, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if !isQR(h.Flags) {
		t.Error("QR bit not set in response")
	}

	if !isAA(h.Flags) {
		t.Error("AA bit not set")
	}

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", getRcode(h.Flags))
	}

	if h.ANCount != 1 {
		t.Errorf("ANCOUNT = %d, want 1", h.ANCount)
	}
}

func TestHandleDNS_MultipleA(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "multi.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", getRcode(h.Flags))
	}

	if h.ANCount != 2 {
		t.Errorf("ANCOUNT = %d, want 2 (two A records)", h.ANCount)
	}
}

func TestHandleDNS_AAAA(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeAAAA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", getRcode(h.Flags))
	}

	if h.ANCount != 1 {
		t.Errorf("ANCOUNT = %d, want 1", h.ANCount)
	}
}

func TestHandleDNS_MultipleAAAA(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "multi6.xfx1.de.", rec.RRtypeToWire[rec.TypeAAAA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", getRcode(h.Flags))
	}

	if h.ANCount != 2 {
		t.Errorf("ANCOUNT = %d, want 2 (two AAAA records)", h.ANCount)
	}
}

func TestHandleDNS_CNAME_WithAdditional(t *testing.T) {
	s := newTestSlave(t)
	// www.xfx1.de. is a CNAME to ns1.xfx1.de., which has both A and AAAA records.
	_, resp, _ := s.handleDNS(
		wireQuery(1, "www.xfx1.de.", rec.RRtypeToWire[rec.TypeCNAME]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", getRcode(h.Flags))
	}

	if h.ANCount != 1 {
		t.Errorf("ANCOUNT = %d, want 1 (the CNAME)", h.ANCount)
	}
	// ns1.xfx1.de. has one A + one AAAA → 2 additional records.
	if h.ARCount != 2 {
		t.Errorf(
			"ARCOUNT = %d, want 2 (A + AAAA glue for CNAME target)",
			h.ARCount,
		)
	}
}

func TestHandleDNS_AQueryForOffZoneCNAME(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "external.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", getRcode(h.Flags))
	}

	if h.ANCount != 1 {
		t.Fatalf("ANCOUNT = %d, want 1 (the CNAME)", h.ANCount)
	}

	if h.ARCount != 0 {
		t.Errorf("ARCOUNT = %d, want 0 for off-zone CNAME target", h.ARCount)
	}
}

func TestHandleDNS_MX_WithAdditional(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "xfx1.de.", rec.RRtypeToWire[rec.TypeMX]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR", getRcode(h.Flags))
	}

	if h.ANCount != 1 {
		t.Errorf("ANCOUNT = %d, want 1 (MX record)", h.ANCount)
	}

	if h.ARCount == 0 {
		t.Error("ARCOUNT = 0, want >0 (A/AAAA glue for MX target)")
	}
}

func TestHandleDNS_NXDOMAIN(t *testing.T) {
	// nonexistent.xfx1.de. would now match the *.xfx1.de. wildcard, so use a
	// name blocked by an intermediate node: sub.ns1.xfx1.de. where ns1.xfx1.de.
	// exists → wildcard expansion is blocked → NXDOMAIN.
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "sub.ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNXDomain {
		t.Errorf(
			"rcode = %d, want NXDOMAIN (%d)",
			getRcode(h.Flags),
			response.RcodeNXDomain,
		)
	}

	if h.ANCount != 0 {
		t.Errorf("ANCOUNT = %d, want 0", h.ANCount)
	}
	// SOA must be in the authority section (RFC 2308).
	if h.NSCount == 0 {
		t.Error("NSCOUNT = 0, want SOA in authority for NXDOMAIN")
	}
}

func TestHandleDNS_NODATA(t *testing.T) {
	// ns1.xfx1.de. exists but has no MX record → NOERROR with 0 answers.
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeMX]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR (NODATA)", getRcode(h.Flags))
	}

	if h.ANCount != 0 {
		t.Errorf("ANCOUNT = %d, want 0 (no MX for this name)", h.ANCount)
	}
	// SOA must be in authority for NODATA (RFC 2308).
	if h.NSCount == 0 {
		t.Error("NSCOUNT = 0, want SOA in authority for NODATA")
	}
}

func TestHandleDNS_AXFR_Refused(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(wireQuery(1, "xfx1.de.", qtypeAXFR))
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeRefused {
		t.Errorf("rcode = %d, want REFUSED for AXFR", getRcode(h.Flags))
	}
}

func TestHandleDNS_IXFR_Refused(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(wireQuery(1, "xfx1.de.", qtypeIXFR))
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeRefused {
		t.Errorf("rcode = %d, want REFUSED for IXFR", getRcode(h.Flags))
	}
}

func TestHandleDNS_NonQueryOpcode_Refused(t *testing.T) {
	// Build a query with opcode=5 (UPDATE). Bits 14:11 of flags = opcode.
	const opcodeUpdate = 5

	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, uint16(1)) // ID
	binary.Write(
		&buf,
		binary.BigEndian,
		uint16(opcodeUpdate<<11),
	) // flags: opcode=UPDATE
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QDCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	buf.Write(wireName("xfx1.de."))
	binary.Write(&buf, binary.BigEndian, rec.RRtypeToWire[rec.TypeA])
	binary.Write(&buf, binary.BigEndian, uint16(1))

	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(buf.Bytes())
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeRefused {
		t.Errorf(
			"rcode = %d, want REFUSED for UPDATE opcode",
			getRcode(h.Flags),
		)
	}
}

func TestHandleDNS_UnknownType_NOERROR(t *testing.T) {
	// qtype 65535 is not in RRtypeFromWire → NOERROR, 0 answers.
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(wireQuery(1, "xfx1.de.", 65535))
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf(
			"rcode = %d, want NOERROR for unknown qtype",
			getRcode(h.Flags),
		)
	}

	if h.ANCount != 0 {
		t.Errorf("ANCOUNT = %d, want 0", h.ANCount)
	}
}

// ── queryInfo.supported tests ─────────────────────────────────────────────────

func TestHandleDNS_KnownType_Supported(t *testing.T) {
	s := newTestSlave(t)
	_, _, qi := s.handleDNS(
		wireQuery(1, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)

	if !qi.supported {
		t.Error("qi.supported = false for known RR type, want true")
	}
}

func TestHandleDNS_UnknownType_NotSupported(t *testing.T) {
	s := newTestSlave(t)
	_, _, qi := s.handleDNS(wireQuery(1, "xfx1.de.", 65535))

	if qi.supported {
		t.Error("qi.supported = true for unknown wire type, want false")
	}
}

func TestHandleDNS_AXFR_NotSupported(t *testing.T) {
	s := newTestSlave(t)
	_, _, qi := s.handleDNS(wireQuery(1, "xfx1.de.", qtypeAXFR))

	if qi.supported {
		t.Error("qi.supported = true for AXFR, want false")
	}
}

func TestHandleDNS_BADVERS_Supported(t *testing.T) {
	s := newTestSlave(t)
	msg, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		1,
		512,
	)
	_, _, qi := s.handleDNS(msg)

	if !qi.supported {
		t.Error(
			"qi.supported = false for BADVERS (known type, bad EDNS version), want true",
		)
	}
}

func TestHandleDNS_IDEchoed(t *testing.T) {
	const id = uint16(0xABCD)

	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(id, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if h.ID != id {
		t.Errorf("response ID = 0x%04X, want 0x%04X", h.ID, id)
	}
}

func TestHandleDNS_NoDatabase_Refused(t *testing.T) {
	// Slave with no DB loaded must return REFUSED.
	s := New(crd.DNSConfigSpec{}, log.New[log.Null, log.Logfmt]("test"))
	_, resp, _ := s.handleDNS(
		wireQuery(1, "xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeRefused {
		t.Errorf(
			"rcode = %d, want REFUSED when no DB loaded",
			getRcode(h.Flags),
		)
	}
}

// TestHandleDNS_QNameFormatMatchesDB verifies that the FQDN produced by
// query.New (trailing-dot form, e.g. "a.example.test.") matches the Domain
// keys stored in the DB. A silent format mismatch would make every lookup
// return NXDOMAIN with no error.
func TestHandleDNS_QNameFormatMatchesDB(t *testing.T) {
	zone := rec.Domain("example.test.")
	records := []*rec.RR{
		rec.NewRR("example.test.", &rec.RRoptsSOA{
			Mname: "ns1.example.test.", Rname: "hostmaster.example.test.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
		rec.NewRR(
			"a.example.test.",
			&rec.RRoptsA{Target: net.ParseIP("192.0.2.1")},
		),
	}
	s := New(crd.DNSConfigSpec{}, log.New[log.Null, log.Logfmt]("test"))
	s.swapDB(db.NewDB(zone, records))

	raw := wireQuery(1, "a.example.test.", rec.RRtypeToWire[rec.TypeA])
	_, resp, _ := s.handleDNS(raw)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Fatalf(
			"rcode = %d, want NOERROR — QName from wire format does not match DB keys",
			getRcode(h.Flags),
		)
	}

	if h.ANCount != 1 {
		t.Errorf(
			"ANCOUNT = %d, want 1 — lookup returned no answers despite record existing",
			h.ANCount,
		)
	}
}

// TestHandleDNS_QNameNormalizedFromJSON verifies that a record whose name lacks
// a trailing dot in the JSON payload (e.g. a hand-authored CRD) is normalised
// by Domain.UnmarshalJSON and remains findable. The realistic path is:
// master JSON → slave handleDBPush → json.Unmarshal → db.DB → lookup.
func TestHandleDNS_QNameNormalizedFromJSON(t *testing.T) {
	zone := rec.Domain("example.test.")
	records := []*rec.RR{
		rec.NewRR("example.test.", &rec.RRoptsSOA{
			Mname: "ns1.example.test.", Rname: "hostmaster.example.test.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
		rec.NewRR(
			"a.example.test.",
			&rec.RRoptsA{Target: net.ParseIP("192.0.2.1")},
		),
	}

	data, err := json.Marshal(db.NewDB(zone, records))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Simulate a CRD authored without a trailing dot on the record name.
	data = []byte(
		strings.Replace(
			string(data),
			`"a.example.test."`,
			`"a.example.test"`,
			1,
		),
	)

	var newDB db.DB
	if err := json.Unmarshal(data, &newDB); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	s := New(crd.DNSConfigSpec{}, log.New[log.Null, log.Logfmt]("test"))
	s.swapDB(&newDB)

	_, resp, _ := s.handleDNS(
		wireQuery(1, "a.example.test.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Fatalf(
			"rcode = %d, want NOERROR — no-dot name in CRD JSON was not normalised",
			getRcode(h.Flags),
		)
	}

	if h.ANCount != 1 {
		t.Errorf(
			"ANCOUNT = %d, want 1 — record not found despite name normalisation",
			h.ANCount,
		)
	}
}

func TestHandleDNS_TooShort(t *testing.T) {
	s := newTestSlave(t)
	// Fewer than 12 bytes → nil (not a crash).
	_, resp, _ := s.handleDNS([]byte{0x00, 0x01})
	if resp != nil {
		t.Errorf("expected nil for too-short message, got %d bytes", len(resp))
	}
}

func TestHandleDNS_QDCountZero(t *testing.T) {
	// A query with QDCOUNT=0 goes through noerrorResponse — no question, no answers.
	s := newTestSlave(t)

	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, uint16(7)) // ID=7
	binary.Write(&buf, binary.BigEndian, uint16(0)) // flags
	binary.Write(&buf, binary.BigEndian, uint16(0)) // QDCOUNT=0
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	_, resp, _ := s.handleDNS(buf.Bytes())
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR for QDCOUNT=0", getRcode(h.Flags))
	}

	if h.ANCount != 0 {
		t.Errorf("ANCOUNT = %d, want 0", h.ANCount)
	}

	if h.QDCount != 0 {
		t.Errorf("QDCOUNT = %d, want 0 (no question echoed)", h.QDCount)
	}
}

// ── handleDNS EDNS integration tests ─────────────────────────────────────────

// findOPTInResponse scans a DNS response for an OPT record (type 41) in the
// additional section. Returns the OPT fixed fields (10 bytes after the root
// name byte) and true if found.
func findOPTInResponse(resp []byte) (optFields []byte, found bool) {
	if len(resp) < 12 {
		return nil, false
	}

	h := parseRespHeader(resp)
	pos := 12
	// Skip question section.
	for i := 0; i < int(h.QDCount); i++ {
		pos = skipName(resp, pos)
		pos += 4 // QTYPE + QCLASS
	}
	// Skip answer section.
	for i := 0; i < int(h.ANCount); i++ {
		pos = skipName(resp, pos)
		if pos+10 > len(resp) {
			return nil, false
		}

		rdlen := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		pos += 10 + rdlen
	}
	// Skip authority section.
	for i := 0; i < int(h.NSCount); i++ {
		pos = skipName(resp, pos)
		if pos+10 > len(resp) {
			return nil, false
		}

		rdlen := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		pos += 10 + rdlen
	}
	// Scan additional section.
	for i := 0; i < int(h.ARCount); i++ {
		pos = skipName(resp, pos)
		if pos+10 > len(resp) {
			return nil, false
		}

		rrtype := binary.BigEndian.Uint16(resp[pos : pos+2])
		if rrtype == 41 {
			return resp[pos : pos+10], true
		}

		rdlen := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		pos += 10 + rdlen
	}

	return nil, false
}

func TestHandleDNS_EDNS_ResponseIncludesOPT(t *testing.T) {
	s := newTestSlave(t)
	msg, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		0,
		4096,
	)
	_, resp, _ := s.handleDNS(msg)

	optFields, found := findOPTInResponse(resp)
	if !found {
		t.Fatal("OPT record not found in response")
	}
	// type=41
	if binary.BigEndian.Uint16(optFields[0:2]) != 41 {
		t.Errorf(
			"OPT type = %d, want 41",
			binary.BigEndian.Uint16(optFields[0:2]),
		)
	}
	// class=4096 (server UDP payload size)
	if binary.BigEndian.Uint16(optFields[2:4]) != 4096 {
		t.Errorf(
			"OPT class = %d, want 4096",
			binary.BigEndian.Uint16(optFields[2:4]),
		)
	}
	// DO bit should NOT be set (query had DO=false)
	if binary.BigEndian.Uint16(optFields[6:8])&dnssec.EDNSDOBit != 0 {
		t.Error("OPT DO bit set, want false (query had DO=false)")
	}
}

func TestHandleDNS_EDNS_DOEcho(t *testing.T) {
	s := newTestSlave(t)
	msg, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		true,
		0,
		4096,
	)
	_, resp, _ := s.handleDNS(msg)

	optFields, found := findOPTInResponse(resp)
	if !found {
		t.Fatal("OPT record not found in response")
	}
	// DO bit should be set (echoed from query)
	if binary.BigEndian.Uint16(optFields[6:8])&dnssec.EDNSDOBit == 0 {
		t.Error("OPT DO bit not set, want true (query had DO=true)")
	}
}

func TestHandleDNS_EDNS_BADVERS(t *testing.T) {
	s := newTestSlave(t)
	msg, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		1,
		4096,
	)
	_, resp, qi := s.handleDNS(msg)

	// qi.rcode should be 16 (BADVERS)
	if qi.rcode != 16 {
		t.Errorf("qi.rcode = %d, want 16 (BADVERS)", qi.rcode)
	}

	h := parseRespHeader(resp)
	// Header RCODE should be 0 (lower 4 bits of extended RCODE 16)
	if getRcode(h.Flags) != 0 {
		t.Errorf("header RCODE = %d, want 0", getRcode(h.Flags))
	}
	// ANCOUNT should be 0 (no answers for BADVERS)
	if h.ANCount != 0 {
		t.Errorf("ANCOUNT = %d, want 0", h.ANCount)
	}

	// OPT record must be present with ext-rcode high = 1
	optFields, found := findOPTInResponse(resp)
	if !found {
		t.Fatal("OPT record not found in BADVERS response")
	}
	// TTL byte 0 = extended RCODE high bits = 1
	if optFields[4] != 1 {
		t.Errorf("OPT ext-rcode high = %d, want 1 (BADVERS)", optFields[4])
	}
}

func TestHandleDNS_NoEDNS_NoOPTInResponse(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)

	_, found := findOPTInResponse(resp)
	if found {
		t.Error("OPT record found in response to non-EDNS query, want none")
	}
}

// ── wildcard tests ────────────────────────────────────────────────────────────

func TestQuery_wildcard_basic(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "anything.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR (wildcard A)", getRcode(h.Flags))
	}

	if h.ANCount != 1 {
		t.Errorf(
			"ANCOUNT = %d, want 1 (synthesised wildcard answer)",
			h.ANCount,
		)
	}
}

func TestQuery_wildcard_AAAA(t *testing.T) {
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "anything.xfx1.de.", rec.RRtypeToWire[rec.TypeAAAA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf("rcode = %d, want NOERROR (wildcard AAAA)", getRcode(h.Flags))
	}

	if h.ANCount != 1 {
		t.Errorf("ANCOUNT = %d, want 1", h.ANCount)
	}
}

func TestQuery_wildcard_blocked_by_exact(t *testing.T) {
	// ns1.xfx1.de. exists as an exact node → *.xfx1.de. must not fire for sub.ns1.xfx1.de.
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "sub.ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNXDomain {
		t.Errorf(
			"rcode = %d, want NXDOMAIN (wildcard blocked by intermediate node)",
			getRcode(h.Flags),
		)
	}
}

func TestQuery_wildcard_NODATA(t *testing.T) {
	// *.xfx1.de. has A and AAAA but no MX → wildcard NODATA (NOERROR, empty answer, SOA in authority).
	s := newTestSlave(t)
	_, resp, _ := s.handleDNS(
		wireQuery(1, "anything.xfx1.de.", rec.RRtypeToWire[rec.TypeMX]),
	)
	h := parseRespHeader(resp)

	if getRcode(h.Flags) != response.RcodeNoError {
		t.Errorf(
			"rcode = %d, want NOERROR (wildcard NODATA)",
			getRcode(h.Flags),
		)
	}

	if h.ANCount != 0 {
		t.Errorf("ANCOUNT = %d, want 0 (no MX in wildcard)", h.ANCount)
	}

	if h.NSCount == 0 {
		t.Error(
			"NSCOUNT = 0, want SOA in authority for wildcard NODATA (RFC 2308)",
		)
	}
}

// ── benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkHandleDNS_Hit(b *testing.B) {
	s := newTestSlave(b)
	q := wireQuery(1, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA])

	b.ResetTimer()

	for b.Loop() {
		_, _, _ = s.handleDNS(q)
	}
}

func BenchmarkHandleDNS_NXDOMAIN(b *testing.B) {
	s := newTestSlave(b)
	q := wireQuery(1, "sub.ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA])

	b.ResetTimer()

	for b.Loop() {
		_, _, _ = s.handleDNS(q)
	}
}

func BenchmarkHandleDNS_Wildcard(b *testing.B) {
	s := newTestSlave(b)
	q := wireQuery(1, "anything.xfx1.de.", rec.RRtypeToWire[rec.TypeA])

	b.ResetTimer()

	for b.Loop() {
		_, _, _ = s.handleDNS(q)
	}
}

// ── security regression tests ─────────────────────────────────────────────────

// FuzzHandleDNS_NoDB feeds arbitrary bytes through the slave's full public
// query pipeline (query.New → parseOPT → checkReject → BuildResponse →
// AppendOPT) using the cold-start state every slave actually serves until the
// master's first DB push lands. With currDB=nil the lookup short-circuits to
// REFUSED, so we never touch the DB layer — but every wire-format parser on
// the public path is exercised together, exactly as an outside UDP/TCP/DoH
// client would drive them.
//
// Run with `task fuzz`. Under plain `go test` only the seed corpus runs.
func FuzzHandleDNS_NoDB(f *testing.F) {
	f.Add(wireQuery(1, "ns1.xfx1.de.", rec.RRtypeToWire[rec.TypeA]))
	f.Add(wireQuery(1, ".", rec.RRtypeToWire[rec.TypeA]))
	f.Add(wireQuery(1, "xfx1.de.", qtypeAXFR))

	optMsg, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		true,
		0,
		4096,
	)
	f.Add(optMsg)

	optBadVers, _ := buildOptQuery(
		"ns1.xfx1.de.",
		rec.RRtypeToWire[rec.TypeA],
		false,
		1,
		512,
	)
	f.Add(optBadVers)
	f.Add([]byte{})
	f.Add(make([]byte, 11))

	s := New(crd.DNSConfigSpec{}, log.New[log.Null, log.Logfmt]("fuzz"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, resp, _ := s.handleDNS(data)
		t.Logf("handleDNS(%x) = resp %x", data, resp)

		if resp == nil {
			return
		}

		if len(resp) < 12 {
			t.Fatalf("response too short: %d bytes (must be ≥12)", len(resp))
		}

		if !isQR(binary.BigEndian.Uint16(resp[2:4])) {
			t.Fatal("response missing QR bit")
		}
		// ID must echo the query when query.New accepted it. handleDNS only
		// emits a response when query.New succeeded (or when len(data) >= 12
		// and the message was malformed in a way that still produced a
		// header-only reply via the top-of-function paths) — in either case
		// the ID is read from data[0:2].
		if len(data) >= 2 {
			wantID := binary.BigEndian.Uint16(data[0:2])
			gotID := binary.BigEndian.Uint16(resp[0:2])

			if gotID != wantID {
				t.Fatalf("response ID = 0x%04x, want 0x%04x", gotID, wantID)
			}
		}
	})
}

// TestSlave_TCPDeadline verifies SEC-05: connections that send a length prefix
// but never deliver the body are closed after the configured timeout.
func TestSlave_TCPDeadline(t *testing.T) {
	s := newTestSlave(t)

	server, client := net.Pipe()
	defer client.Close()

	const timeout = 100 * time.Millisecond

	done := make(chan struct{})

	go func() {
		defer close(done)
		s.handleTCPConn(server, timeout)
	}()

	// Send 2-byte length prefix claiming 500 bytes but nothing more.
	binary.Write(client, binary.BigEndian, uint16(500))

	select {
	case <-done:
		// server-side goroutine exited — deadline worked
	case <-time.After(3 * time.Second):
		t.Fatal(
			"handleTCPConn did not close connection after deadline (SEC-05)",
		)
	}
}

// TestSlave_TCPOversizedResponse_TC verifies SEC-06: when a DNS response exceeds
// maxTCPResponseSize the slave returns a clean TC=1 response, not a truncated wire message.
func TestSlave_TCPOversizedResponse_TC(t *testing.T) {
	// Build a zone with enough TXT records to exceed maxTCPResponseSize (8 KB).
	// Each 200-byte TXT record is ~230 bytes on the wire; 40 records ≈ 9.2 KB.
	zone := rec.Domain("xfx1.de.")
	records := []*rec.RR{
		rec.NewRR("xfx1.de.", &rec.RRoptsSOA{
			Mname: "ns1.xfx1.de.", Rname: "hostmaster.xfx1.de.",
			Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
		}),
	}
	bigText := strings.Repeat("x", 200)

	for range 40 {
		records = append(
			records,
			rec.NewRR("big.xfx1.de.", &rec.RRoptsTXT{Txt: bigText}),
		)
	}

	s := New(crd.DNSConfigSpec{}, log.New[log.Null, log.Logfmt]("test"))
	s.swapDB(db.NewDB(zone, records))

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleTCPConn(server, tcpConnTimeout)
	}()

	// Write TCP DNS query (2-byte length prefix + query bytes).
	query := wireQuery(0x1234, "big.xfx1.de.", rec.RRtypeToWire[rec.TypeTXT])
	binary.Write(client, binary.BigEndian, uint16(len(query)))
	client.Write(query)

	// Read response: 2-byte length prefix + response bytes.
	var respLen uint16
	if err := binary.Read(client, binary.BigEndian, &respLen); err != nil {
		t.Fatalf("read response length: %v", err)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read response body: %v", err)
	}

	client.Close()
	<-done

	// Expect a clean 12-byte TC=1 response, not a truncated wire blob.
	if len(resp) != 12 {
		t.Errorf("expected 12-byte TC response, got %d bytes", len(resp))
		return
	}

	id := binary.BigEndian.Uint16(resp[0:2])
	if id != 0x1234 {
		t.Errorf("ID = 0x%04x, want 0x1234", id)
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&response.FlagTC == 0 {
		t.Errorf("TC bit not set (flags=0x%04x)", flags)
	}

	if flags&response.FlagQR == 0 {
		t.Errorf("QR bit not set (flags=0x%04x)", flags)
	}
}
