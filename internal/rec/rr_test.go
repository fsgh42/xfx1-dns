// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestRRoptsPayloads(t *testing.T) {
	// A record: 4 bytes IPv4
	a := RRoptsA{Target: net.ParseIP("1.2.3.4")}
	if got := a.Payload(); len(got) != 4 {
		t.Errorf("RRoptsA.Payload() len = %d, want 4", len(got))
	}

	// AAAA record: 16 bytes IPv6
	aaaa := RRoptsAAAA{Target: net.ParseIP("::1")}
	if got := aaaa.Payload(); len(got) != 16 {
		t.Errorf("RRoptsAAAA.Payload() len = %d, want 16", len(got))
	}

	// NS record: wire-encoded domain
	ns := RRoptsNS{Ns: "ns1.example.com."}

	nsPayload := ns.Payload()
	if len(nsPayload) == 0 {
		t.Error("RRoptsNS.Payload() is empty")
	}
	// first byte = 3 (len of "ns1")
	if nsPayload[0] != 3 {
		t.Errorf("RRoptsNS.Payload()[0] = %d, want 3", nsPayload[0])
	}

	// SOA record: non-empty
	soa := RRoptsSOA{
		Mname:   "ns1.example.com.",
		Rname:   "admin.example.com.",
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minimum: 300,
	}
	if got := soa.Payload(); len(got) == 0 {
		t.Error("RRoptsSOA.Payload() is empty")
	}

	// TXT record: 1-byte length prefix + string
	txt := RRoptsTXT{Txt: "hello"}
	if got := txt.Payload(); got[0] != 5 || string(got[1:]) != "hello" {
		t.Errorf("RRoptsTXT.Payload() = %v, want [5 h e l l o]", got)
	}

	// Long TXT (>255 bytes) must be split into 255-byte chunks.
	long := RRoptsTXT{Txt: strings.Repeat("a", 300)}

	longPayload := long.Payload()
	if longPayload[0] != 255 {
		t.Errorf("long TXT first chunk length = %d, want 255", longPayload[0])
	}

	if longPayload[256] != 45 {
		t.Errorf("long TXT second chunk length = %d, want 45", longPayload[256])
	}

	if len(longPayload) != 2+300 {
		t.Errorf(
			"long TXT payload length = %d, want %d",
			len(longPayload),
			2+300,
		)
	}

	// SRV record: 6 bytes header + domain
	srv := RRoptsSRV{
		Priority: 10,
		Weight:   20,
		Port:     80,
		Target:   "svc.example.com.",
	}

	srvPayload := srv.Payload()
	if len(srvPayload) < 6 {
		t.Errorf("RRoptsSRV.Payload() too short: %d", len(srvPayload))
	}

	// MX record: 2-byte preference + domain
	mx := RRoptsMX{Preference: 10, Mx: "mail.example.com."}

	mxPayload := mx.Payload()
	if len(mxPayload) < 2 {
		t.Errorf("RRoptsMX.Payload() too short: %d", len(mxPayload))
	}

	// CNAME record: wire-encoded target domain
	cname := RRoptsCNAME{Cname: "target.example.com."}

	cnamePayload := cname.Payload()
	if len(cnamePayload) == 0 {
		t.Error("RRoptsCNAME.Payload() is empty")
	}
	// first byte = 6 (len of "target")
	if cnamePayload[0] != 6 {
		t.Errorf("RRoptsCNAME.Payload()[0] = %d, want 6", cnamePayload[0])
	}

	// PTR record: wire-encoded pointer name
	ptr := RRoptsPTR{Ptr: "ns1.example.com."}

	ptrPayload := ptr.Payload()
	if len(ptrPayload) == 0 {
		t.Error("RRoptsPTR.Payload() is empty")
	}
	// first byte = 3 (len of "ns1")
	if ptrPayload[0] != 3 {
		t.Errorf("RRoptsPTR.Payload()[0] = %d, want 3", ptrPayload[0])
	}

	// CAA record: flags(1) + tag-len(1) + tag + value
	caa := RRoptsCAA{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}
	caaPayload := caa.Payload()
	// expected: 0x00, 0x05, 'i','s','s','u','e', 'l','e','t','s','e','n','c','r','y','p','t','.','o','r','g'
	if len(caaPayload) != 1+1+len("issue")+len("letsencrypt.org") {
		t.Errorf(
			"RRoptsCAA.Payload() len = %d, want %d",
			len(caaPayload),
			1+1+len("issue")+len("letsencrypt.org"),
		)
	}

	if caaPayload[0] != 0 {
		t.Errorf("RRoptsCAA.Payload()[0] (flags) = %d, want 0", caaPayload[0])
	}

	if caaPayload[1] != 5 {
		t.Errorf("RRoptsCAA.Payload()[1] (tag-len) = %d, want 5", caaPayload[1])
	}

	if string(caaPayload[2:7]) != "issue" {
		t.Errorf(
			"RRoptsCAA.Payload() tag = %q, want %q",
			string(caaPayload[2:7]),
			"issue",
		)
	}

	if string(caaPayload[7:]) != "letsencrypt.org" {
		t.Errorf(
			"RRoptsCAA.Payload() value = %q, want %q",
			string(caaPayload[7:]),
			"letsencrypt.org",
		)
	}
}

func TestRRBinaryWrite(t *testing.T) {
	name := Domain("example.com.")
	opts := RRoptsA{Target: net.ParseIP("1.2.3.4")}
	rr := NewRR(name, &opts)

	var buf bytes.Buffer
	if err := rr.BinaryWrite(&buf); err != nil {
		t.Fatal(err)
	}

	data := buf.Bytes()
	if len(data) == 0 {
		t.Fatal("BinaryWrite produced no output")
	}
	// first byte is label length of "example" (7)
	if data[0] != 7 {
		t.Errorf("BinaryWrite: first byte = %d, want 7", data[0])
	}
}

func TestRRJSONRoundTrip(t *testing.T) {
	types := []struct {
		name string
		rr   *RR
	}{
		{"A", NewRR("example.com.", &RRoptsA{Target: net.ParseIP("1.2.3.4")})},
		{
			"AAAA",
			NewRR("example.com.", &RRoptsAAAA{Target: net.ParseIP("::1")}),
		},
		{"NS", NewRR("example.com.", &RRoptsNS{Ns: "ns1.example.com."})},
		{
			"CNAME",
			NewRR("www.example.com.", &RRoptsCNAME{Cname: "example.com."}),
		},
		{
			"MX",
			NewRR(
				"example.com.",
				&RRoptsMX{Preference: 10, Mx: "mail.example.com."},
			),
		},
		{"TXT", NewRR("example.com.", &RRoptsTXT{Txt: "v=spf1 -all"})},
		{
			"SRV",
			NewRR(
				"_svc._tcp.example.com.",
				&RRoptsSRV{
					Priority: 10,
					Weight:   20,
					Port:     443,
					Target:   "svc.example.com.",
				},
			),
		},
		{"SOA", NewRR("example.com.", &RRoptsSOA{
			Mname:   "ns1.example.com.",
			Rname:   "admin.example.com.",
			Serial:  1,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minimum: 300,
		})},
		{
			"PTR",
			NewRR("1.2.3.4.in-addr.arpa.", &RRoptsPTR{Ptr: "example.com."}),
		},
		{
			"CAA",
			NewRR(
				"example.com.",
				&RRoptsCAA{Flags: 0, Tag: "issue", Value: "letsencrypt.org"},
			),
		},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.rr)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var rr2 RR
			if err := json.Unmarshal(data, &rr2); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			if rr2.Name != tc.rr.Name {
				t.Errorf("Name mismatch: got %q, want %q", rr2.Name, tc.rr.Name)
			}

			if rr2.RRtype != tc.rr.RRtype {
				t.Errorf(
					"RRtype mismatch: got %q, want %q",
					rr2.RRtype,
					tc.rr.RRtype,
				)
			}
		})
	}
}

// TestSOASerialIgnoredInJSON verifies that the "serial" field is ignored
// SOA serial must round-trip through JSON so it survives master→slave DB transfer.
// The master always overwrites the serial at rebuild time, so CRD-provided values
// are harmless.
func TestSOASerialRoundTripsJSON(t *testing.T) {
	raw := `{"name":"example.com.","rrtype":"SOA","ttl":3600,"payload":{"mname":"ns1.example.com.","rname":"admin.example.com.","serial":999,"refresh":3600,"retry":900,"expire":604800,"minimum":300}}`

	var rr RR

	if err := json.Unmarshal([]byte(raw), &rr); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	opts, ok := rr.Opts.(*RRoptsSOA)
	if !ok {
		t.Fatalf("Opts is %T, want *RRoptsSOA", rr.Opts)
	}

	if opts.Serial != 999 {
		t.Errorf("Serial = %d after unmarshal, want 999", opts.Serial)
	}
}

func TestTXTPayloadDMARCAndDKIM(t *testing.T) {
	// decodeTXT reassembles RFC 1035 length-prefixed TXT RDATA back to a plain string.
	decodeTXT := func(t *testing.T, payload []byte) string {
		t.Helper()

		var out []byte

		for i := 0; i < len(payload); {
			chunkLen := int(payload[i])
			i++

			if i+chunkLen > len(payload) {
				t.Fatalf(
					"malformed payload: chunk at %d claims length %d but only %d bytes remain",
					i-1,
					chunkLen,
					len(payload)-i,
				)
			}

			out = append(out, payload[i:i+chunkLen]...)
			i += chunkLen
		}

		return string(out)
	}

	cases := []struct {
		name   string
		txt    string
		chunks int // expected number of 255-byte chunks
	}{
		{
			// Short DMARC record — fits in a single chunk.
			name:   "DMARC short",
			txt:    "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; fo=1",
			chunks: 1,
		},
		{
			// Long DMARC record spanning 4 chunks: 255+255+255+11.
			name:   "DMARC long (776 chars)",
			txt:    ("v=DMARC1; p=reject; " + strings.Repeat("rua=mailto:dmarc@example.com; ", 30))[:776],
			chunks: 4,
		},
		{
			// DKIM RSA-2048: public key base64-encodes to ~344 chars — 2 chunks.
			name: "DKIM RSA-2048",
			txt: "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxN7xCFbCNOaKMR7Z" +
				"Gy0Z3tPBjI4C8N3hGkCQ5I5p9TqVWtLJfJhNlQM/pREkS2EFJL+Y4LRpxzACF9i" +
				"Rq3wNIDW2KBpXq8tZ7fCNP7HxLQMJGKm5LZ9O4yV8BpVJ3YgEQH2L/k3R1Ns9CmK" +
				"w0pF5VhpVkZQ3p4B7bGkLVhF6M/J+QN5oRTxLkCHJ3mUWqY8Z5VqXtEaYAm8YdVr" +
				"t+aXcP7eWz5g5M+2kLwQHZnFjXaJ1w0lN5L9jKvQ==",
			chunks: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := RRoptsTXT{Txt: tc.txt}.Payload()

			// Chunk count.
			nChunks := 0

			for i := 0; i < len(payload); {
				chunkLen := int(payload[i])
				if chunkLen > 255 {
					t.Errorf(
						"chunk %d length %d exceeds 255",
						nChunks,
						chunkLen,
					)
				}

				nChunks++
				i += 1 + chunkLen
			}

			if nChunks != tc.chunks {
				t.Errorf("chunk count = %d, want %d", nChunks, tc.chunks)
			}

			// Wire length: one length byte per chunk plus content.
			wantLen := len(tc.txt) + tc.chunks
			if len(payload) != wantLen {
				t.Errorf("payload length = %d, want %d", len(payload), wantLen)
			}

			// Round-trip: decoded content must equal original.
			if got := decodeTXT(t, payload); got != tc.txt {
				t.Errorf("round-trip mismatch:\ngot  %q\nwant %q", got, tc.txt)
			}
		})
	}
}

func TestDNSSECPayloads(t *testing.T) {
	// DNSKEY: flags(2) + protocol(1) + algorithm(1) + publicKey(N)
	t.Run("DNSKEY", func(t *testing.T) {
		pubKey := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		opts := RRoptsDNSKEY{
			Flags:     257,
			Protocol:  3,
			Algorithm: 15,
			PublicKey: pubKey,
		}
		r := bytes.NewReader(opts.Payload())

		var flags uint16

		var protocol, algorithm uint8

		binary.Read(r, binary.BigEndian, &flags)
		binary.Read(r, binary.BigEndian, &protocol)
		binary.Read(r, binary.BigEndian, &algorithm)

		if flags != 257 {
			t.Errorf("flags = %d, want 257", flags)
		}

		if protocol != 3 {
			t.Errorf("protocol = %d, want 3", protocol)
		}

		if algorithm != 15 {
			t.Errorf("algorithm = %d, want 15", algorithm)
		}

		remaining := make([]byte, r.Len())
		r.Read(remaining)

		if !bytes.Equal(remaining, pubKey) {
			t.Errorf("publicKey = %v, want %v", remaining, pubKey)
		}
	})

	// DS: keyTag(2) + algorithm(1) + digestType(1) + digest(N)
	t.Run("DS", func(t *testing.T) {
		digest := []byte{0x01, 0x02, 0x03}
		opts := RRoptsDS{
			KeyTag:     1234,
			Algorithm:  8,
			DigestType: 2,
			Digest:     digest,
		}
		r := bytes.NewReader(opts.Payload())

		var keyTag uint16

		var algorithm, digestType uint8

		binary.Read(r, binary.BigEndian, &keyTag)
		binary.Read(r, binary.BigEndian, &algorithm)
		binary.Read(r, binary.BigEndian, &digestType)

		if keyTag != 1234 {
			t.Errorf("keyTag = %d, want 1234", keyTag)
		}

		if algorithm != 8 {
			t.Errorf("algorithm = %d, want 8", algorithm)
		}

		if digestType != 2 {
			t.Errorf("digestType = %d, want 2", digestType)
		}

		remaining := make([]byte, r.Len())
		r.Read(remaining)

		if !bytes.Equal(remaining, digest) {
			t.Errorf("digest = %v, want %v", remaining, digest)
		}
	})

	// RRSIG: typeCovered(2) + algorithm(1) + labels(1) + origTTL(4) +
	//        expiration(4) + inception(4) + keyTag(2) + signerName(wire) + signature(N)
	t.Run("RRSIG", func(t *testing.T) {
		sig := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		opts := RRoptsRRSIG{
			TypeCovered: 1,
			Algorithm:   15,
			Labels:      2,
			OrigTTL:     300,
			Expiration:  1700000000,
			Inception:   1699000000,
			KeyTag:      42,
			SignerName:  "example.com.",
			Signature:   sig,
		}
		r := bytes.NewReader(opts.Payload())

		var typeCovered uint16

		var algorithm, labels uint8

		var origTTL, expiration, inception uint32

		var keyTag uint16

		binary.Read(r, binary.BigEndian, &typeCovered)
		binary.Read(r, binary.BigEndian, &algorithm)
		binary.Read(r, binary.BigEndian, &labels)
		binary.Read(r, binary.BigEndian, &origTTL)
		binary.Read(r, binary.BigEndian, &expiration)
		binary.Read(r, binary.BigEndian, &inception)
		binary.Read(r, binary.BigEndian, &keyTag)

		if typeCovered != 1 {
			t.Errorf("typeCovered = %d, want 1", typeCovered)
		}

		if labels != 2 {
			t.Errorf("labels = %d, want 2", labels)
		}

		if origTTL != 300 {
			t.Errorf("origTTL = %d, want 300", origTTL)
		}

		if expiration != 1700000000 {
			t.Errorf("expiration = %d, want 1700000000", expiration)
		}

		if keyTag != 42 {
			t.Errorf("keyTag = %d, want 42", keyTag)
		}
		// Signature bytes must be at the end after the wire-encoded signer name.
		payload := opts.Payload()
		if !bytes.HasSuffix(payload, sig) {
			t.Error("payload does not end with signature bytes")
		}
	})

	// NSEC3PARAM: hashAlgorithm(1) + flags(1) + iterations(2) + saltLen(1) + salt
	t.Run("NSEC3PARAM", func(t *testing.T) {
		salt := []byte{0xCA, 0xFE}
		opts := RRoptsNSEC3PARAM{
			HashAlgorithm: 1,
			Flags:         0,
			Iterations:    0,
			Salt:          salt,
		}
		r := bytes.NewReader(opts.Payload())

		var hashAlg, flags uint8

		var iterations uint16

		var saltLen uint8

		binary.Read(r, binary.BigEndian, &hashAlg)
		binary.Read(r, binary.BigEndian, &flags)
		binary.Read(r, binary.BigEndian, &iterations)
		binary.Read(r, binary.BigEndian, &saltLen)

		if hashAlg != 1 {
			t.Errorf("hashAlgorithm = %d, want 1", hashAlg)
		}

		if saltLen != uint8(len(salt)) {
			t.Errorf("saltLen = %d, want %d", saltLen, len(salt))
		}

		remaining := make([]byte, r.Len())
		r.Read(remaining)

		if !bytes.Equal(remaining, salt) {
			t.Errorf("salt = %v, want %v", remaining, salt)
		}
	})

	// NSEC3: same header as NSEC3PARAM + nextHashLen(1) + nextHash + typeBitmap
	t.Run("NSEC3", func(t *testing.T) {
		nextHash := []byte{0x11, 0x22, 0x33}
		opts := RRoptsNSEC3{
			HashAlgorithm: 1,
			Flags:         0,
			Iterations:    0,
			Salt:          nil,
			NextHash:      nextHash,
			Types:         []uint16{1, 28}, // A, AAAA
		}
		r := bytes.NewReader(opts.Payload())

		var hashAlg, flags uint8

		var iterations uint16

		var saltLen uint8

		binary.Read(r, binary.BigEndian, &hashAlg)
		binary.Read(r, binary.BigEndian, &flags)
		binary.Read(r, binary.BigEndian, &iterations)
		binary.Read(r, binary.BigEndian, &saltLen)

		if hashAlg != 1 {
			t.Errorf("hashAlgorithm = %d, want 1", hashAlg)
		}

		if saltLen != 0 {
			t.Errorf("saltLen = %d, want 0 (empty salt)", saltLen)
		}

		var nextHashLen uint8

		binary.Read(r, binary.BigEndian, &nextHashLen)

		if nextHashLen != uint8(len(nextHash)) {
			t.Errorf("nextHashLen = %d, want %d", nextHashLen, len(nextHash))
		}

		gotHash := make([]byte, nextHashLen)
		r.Read(gotHash)

		if !bytes.Equal(gotHash, nextHash) {
			t.Errorf("nextHash = %v, want %v", gotHash, nextHash)
		}
		// Remaining bytes are the type bitmap — must be non-empty since Types is set.
		if r.Len() == 0 {
			t.Error("expected type bitmap bytes, got none")
		}
	})
}

func TestTypeBitmap(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if got := TypeBitmap(nil); got != nil {
			t.Errorf("TypeBitmap(nil) = %v, want nil", got)
		}
	})

	t.Run("single type A (1)", func(t *testing.T) {
		b := TypeBitmap([]uint16{1}) // A record = type 1, window 0, bit 1
		// window=0, bitmapLen=1, bitmap byte = 0b01000000 = 0x40
		if len(b) != 3 {
			t.Fatalf("len = %d, want 3", len(b))
		}

		if b[0] != 0 {
			t.Errorf("window = %d, want 0", b[0])
		}

		if b[1] != 1 {
			t.Errorf("bitmapLen = %d, want 1", b[1])
		}

		if b[2] != 0x40 {
			t.Errorf("bitmap byte = 0x%02X, want 0x40 (bit 1)", b[2])
		}
	})

	t.Run("A and AAAA (1, 28)", func(t *testing.T) {
		b := TypeBitmap([]uint16{1, 28})
		// Both in window 0. AAAA=28 → byte 28/8=3, bit 7-(28%8)=7-4=3 → 0x08
		// A=1 → byte 0, bit 7-1=6 → 0x40
		// Result: window=0, len=4, bytes=[0x40, 0x00, 0x00, 0x08]
		if len(b) < 2 {
			t.Fatalf("bitmap too short: %d bytes", len(b))
		}

		if b[0] != 0 {
			t.Errorf("window = %d, want 0", b[0])
		}

		bitmapLen := int(b[1])
		bitmap := b[2 : 2+bitmapLen]
		// bit for A (type 1): byte 0, bit position 6 (MSB=7)
		if bitmap[0]&0x40 == 0 {
			t.Error("A bit (type 1) not set in bitmap")
		}
		// bit for AAAA (type 28): byte 3, bit position 3
		if bitmapLen < 4 || bitmap[3]&0x08 == 0 {
			t.Error("AAAA bit (type 28) not set in bitmap")
		}
	})
}

func TestBinaryWrite_UnknownType(t *testing.T) {
	// Construct an RR whose RRtype has no entry in RRtypeToWire.
	rr := &RR{
		Name:   Domain("example.com."),
		RRtype: RRtype("BOGUS"),
		TTL:    300,
		Opts:   &RRoptsA{Target: net.ParseIP("1.2.3.4")},
	}

	var buf bytes.Buffer

	if err := rr.BinaryWrite(&buf); err == nil {
		t.Error("BinaryWrite with unknown RRtype: expected error, got nil")
	}
}

func TestRroptsUnmarshalJSONUnknown(t *testing.T) {
	_, err := rroptsUnmarshalJSON("UNKNOWN", json.RawMessage(`{}`))
	if err == nil {
		t.Error("expected error for unknown rrtype, got nil")
	}
}
