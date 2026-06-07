// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

// Integration tests for the RFC 2136 Gateway.
//
// These tests spin up a real UDP listener (port 0, OS-assigned) and send
// genuine DNS UPDATE wire messages — signed with TSIG — then assert that
// the mock k8s client received the expected Apply/Delete calls.
//
// The Gateway is started in-process; no cluster or external process is needed.

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// ── gateway helpers ───────────────────────────────────────────────────────────

// startGateway spins up a Gateway on a random UDP port and returns the address
// and a cancel function that shuts it down. The TSIG key is injected directly,
// bypassing the k8s secret fetch.
func startGateway(
	t *testing.T,
	k8s *client.MockClient,
	tsigSecret []byte,
) (addr string, cancel context.CancelFunc) {
	t.Helper()

	cfg := crd.DNSConfigSpec{}
	cfg.Global.Zone = rec.Domain("example.com.")

	gw := New(cfg, "test-ns", k8s, log.NewDefaultLogger("integration-test"))
	gw.tsigKey = tsigSecret
	gw.tsigLoaded = true

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}

	addr = udpConn.LocalAddr().String()

	ctx, cancelFn := context.WithCancel(context.Background())
	go func() { _ = gw.serveUDP(ctx, udpConn) }()

	return addr, func() {
		cancelFn()
		udpConn.Close()
	}
}

// sendUpdate sends a DNS UPDATE message over UDP and returns the parsed response.
func sendUpdate(t *testing.T, addr string, msg []byte) *Message {
	t.Helper()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial UDP: %v", err)
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	resp, err := ParseMessage(buf[:n])
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	return resp
}

// signedUpdate builds and TSIG-signs a DNS UPDATE message containing the given update RRs.
func signedUpdate(
	t *testing.T,
	id uint16,
	secret []byte,
	keyName string,
	updates [][]byte,
) []byte {
	t.Helper()

	now := uint64(time.Now().Unix())
	body := buildUpdateMessage(id, "example.com.", updates)
	tsigVars := buildTSIGVariables(
		keyName,
		algorithmHMACSHA256,
		now,
		300,
		0,
		nil,
	)
	mac := hmacSHA256(secret, append(body, tsigVars...))
	rdata := encodeTSIGRdata(algorithmHMACSHA256, now, 300, mac, id, 0, nil)
	tsigRR := encodeRR(keyName, TypeTSIG, ClassANY, 0, rdata)
	arcount := binary.BigEndian.Uint16(body[10:12])
	binary.BigEndian.PutUint16(body[10:12], arcount+1)

	return append(body, tsigRR...)
}

// ── ADD (table-driven, one per record type) ───────────────────────────────────

func TestIntegration_Add(t *testing.T) {
	secret := []byte("integration-secret")
	keyName := "acme-key."

	tests := []struct {
		name      string
		rrtype    uint16
		rdata     []byte
		wantRcode uint8 // RcodeNoError unless unsupported
	}{
		{
			name:      "A",
			rrtype:    1,
			rdata:     []byte{192, 168, 1, 10},
			wantRcode: RcodeNoError,
		},
		{
			name:   "AAAA",
			rrtype: 28,
			rdata: []byte{
				0x20, 0x01, 0x0d, 0xb8,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
			},
			wantRcode: RcodeNoError,
		},
		{
			name:   "TXT",
			rrtype: 16,
			// Wire TXT: <len><data>
			rdata: append(
				[]byte{byte(len("v=spf1 ~all"))},
				[]byte("v=spf1 ~all")...),
			wantRcode: RcodeNoError,
		},
		{
			name:      "CNAME",
			rrtype:    5,
			rdata:     encodeName("target.example.com."),
			wantRcode: RcodeNoError,
		},
		{
			name:      "NS",
			rrtype:    2,
			rdata:     encodeName("ns1.example.com."),
			wantRcode: RcodeNoError,
		},
		{
			name:      "PTR",
			rrtype:    12,
			rdata:     encodeName("host.example.com."),
			wantRcode: RcodeNoError,
		},
		{
			name:   "MX",
			rrtype: 15,
			rdata: append(
				[]byte{0, 10},
				encodeName("mail.example.com.")...),
			wantRcode: RcodeNoError,
		},
		{
			name:   "SRV",
			rrtype: 33,
			rdata: append([]byte{0, 10, 0, 20, 0, 80},
				encodeName("svc.example.com.")...),
			wantRcode: RcodeNoError,
		},
		{
			name:   "CAA",
			rrtype: 257,
			rdata: func() []byte {
				tag := "issue"
				val := "letsencrypt.org"
				return append([]byte{0, byte(len(tag))},
					append([]byte(tag), []byte(val)...)...)
			}(),
			wantRcode: RcodeNoError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k8s := &client.MockClient{}

			addr, cancel := startGateway(t, k8s, secret)
			defer cancel()

			rrWire := buildRRWire(
				"host.example.com.",
				tc.rrtype,
				ClassIN,
				60,
				tc.rdata,
			)
			resp := sendUpdate(
				t,
				addr,
				signedUpdate(t, 0x0001, secret, keyName, [][]byte{rrWire}),
			)

			if resp.Header.Rcode != tc.wantRcode {
				t.Errorf(
					"rcode: got %d, want %d",
					resp.Header.Rcode,
					tc.wantRcode,
				)
			}

			if tc.wantRcode == RcodeNoError {
				if len(k8s.ApplyCalls) != 1 {
					t.Errorf(
						"expected 1 apply call, got %d",
						len(k8s.ApplyCalls),
					)
				}
			} else {
				if len(k8s.ApplyCalls) != 0 {
					t.Errorf("expected no apply calls on error, got %d", len(k8s.ApplyCalls))
				}
			}
		})
	}
}

// ── DELETE (table-driven) ─────────────────────────────────────────────────────

func TestIntegration_Delete(t *testing.T) {
	secret := []byte("integration-secret")
	keyName := "acme-key."

	existingCR := func(crName, fqdn string, rrtype rec.RRtype) *base.Object[rec.RR] {
		return &base.Object[rec.RR]{
			Metadata: base.Metadata{
				Name:      crName,
				Namespace: "test-ns",
				Labels:    base.Labels{sourceLabel: sourceLabelValue},
			},
			Spec: rec.RR{Name: rec.Domain(fqdn), RRtype: rrtype},
		}
	}

	tests := []struct {
		name        string
		updateRR    []byte
		listResult  []*base.Object[rec.RR]
		wantDeletes int
	}{
		{
			name: "delete specific A RR (CLASS=NONE)",
			updateRR: buildRRWire(
				"host.example.com.",
				1,
				ClassNONE,
				0,
				[]byte{192, 168, 1, 10},
			),
			wantDeletes: 1,
		},
		{
			name: "delete specific TXT RR (CLASS=NONE)",
			updateRR: buildRRWire(
				"host.example.com.",
				16,
				ClassNONE,
				0,
				append([]byte{3}, []byte("foo")...),
			),
			wantDeletes: 1,
		},
		{
			name:     "delete A RRset (CLASS=ANY, type=A)",
			updateRR: buildRRWire("host.example.com.", 1, ClassANY, 0, nil),
			listResult: []*base.Object[rec.RR]{
				existingCR(
					"rfc2136-a-host-example-com-aabbccdd",
					"host.example.com.",
					rec.TypeA,
				),
				existingCR(
					"rfc2136-a-host-example-com-11223344",
					"host.example.com.",
					rec.TypeA,
				),
				// different name — should not be deleted
				existingCR(
					"rfc2136-a-other-example-com-deadbeef",
					"other.example.com.",
					rec.TypeA,
				),
			},
			wantDeletes: 2,
		},
		{
			name:     "delete TXT RRset (CLASS=ANY, type=TXT)",
			updateRR: buildRRWire("host.example.com.", 16, ClassANY, 0, nil),
			listResult: []*base.Object[rec.RR]{
				existingCR(
					"rfc2136-txt-host-example-com-aabbccdd",
					"host.example.com.",
					rec.TypeTXT,
				),
				// different type — should not be deleted
				existingCR(
					"rfc2136-a-host-example-com-11223344",
					"host.example.com.",
					rec.TypeA,
				),
			},
			wantDeletes: 1,
		},
		{
			name:     "delete all RRsets at name (CLASS=ANY, type=255)",
			updateRR: buildRRWire("host.example.com.", 255, ClassANY, 0, nil),
			listResult: []*base.Object[rec.RR]{
				existingCR(
					"rfc2136-a-host-example-com-11111111",
					"host.example.com.",
					rec.TypeA,
				),
				existingCR(
					"rfc2136-txt-host-example-com-22222222",
					"host.example.com.",
					rec.TypeTXT,
				),
				existingCR(
					"rfc2136-aaaa-host-example-com-33333333",
					"host.example.com.",
					rec.TypeAAAA,
				),
				// different name — should not be deleted
				existingCR(
					"rfc2136-a-other-example-com-44444444",
					"other.example.com.",
					rec.TypeA,
				),
			},
			wantDeletes: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k8s := &client.MockClient{
				ListResult: client.MockObjects(tc.listResult...),
			}

			addr, cancel := startGateway(t, k8s, secret)
			defer cancel()

			resp := sendUpdate(
				t,
				addr,
				signedUpdate(t, 0x0002, secret, keyName, [][]byte{tc.updateRR}),
			)

			if resp.Header.Rcode != RcodeNoError {
				t.Errorf("rcode: got %d, want NOERROR", resp.Header.Rcode)
			}

			if len(k8s.DeleteCalls) != tc.wantDeletes {
				t.Errorf(
					"delete calls: got %d, want %d",
					len(k8s.DeleteCalls),
					tc.wantDeletes,
				)
			}
		})
	}
}

// ── auth / zone / idempotency tests ──────────────────────────────────────────

func TestIntegration_TSIGRefused(t *testing.T) {
	secret := []byte("correct-secret")
	keyName := "acme-key."

	k8s := &client.MockClient{}

	addr, cancel := startGateway(t, k8s, secret)
	defer cancel()

	rrWire := buildRRWire(
		"host.example.com.",
		1,
		ClassIN,
		60,
		[]byte{1, 2, 3, 4},
	)
	resp := sendUpdate(
		t,
		addr,
		signedUpdate(
			t,
			0x0003,
			[]byte("wrong-secret"),
			keyName,
			[][]byte{rrWire},
		),
	)

	if resp.Header.Rcode != RcodeRefused {
		t.Errorf(
			"expected REFUSED for wrong TSIG, got rcode=%d",
			resp.Header.Rcode,
		)
	}

	if len(k8s.ApplyCalls) != 0 {
		t.Errorf("expected no apply calls, got %d", len(k8s.ApplyCalls))
	}
}

func TestIntegration_ZoneMismatch(t *testing.T) {
	secret := []byte("integration-secret")
	keyName := "acme-key."

	k8s := &client.MockClient{}

	addr, cancel := startGateway(t, k8s, secret)
	defer cancel()

	// Build an update targeting other.com. instead of example.com.
	zoneWire := encodeName("other.com.")
	zoneWire = append(zoneWire, 0, 6, 0, 1) // SOA, IN
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0004)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(OpcodeUpdate<<11))
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT=1
	body := append(hdr, zoneWire...)

	now := uint64(time.Now().Unix())
	tsigVars := buildTSIGVariables(
		keyName,
		algorithmHMACSHA256,
		now,
		300,
		0,
		nil,
	)
	mac := hmacSHA256(secret, append(body, tsigVars...))
	rdata := encodeTSIGRdata(algorithmHMACSHA256, now, 300, mac, 0x0004, 0, nil)
	tsigRR := encodeRR(keyName, TypeTSIG, ClassANY, 0, rdata)

	binary.BigEndian.PutUint16(body[10:12], 1) // ARCOUNT=1
	msg := append(body, tsigRR...)

	resp := sendUpdate(t, addr, msg)
	if resp.Header.Rcode != RcodeNotZone {
		t.Errorf("expected NOTZONE, got rcode=%d", resp.Header.Rcode)
	}
}

func TestIntegration_Idempotent_Add(t *testing.T) {
	secret := []byte("integration-secret")
	keyName := "acme-key."

	k8s := &client.MockClient{}

	addr, cancel := startGateway(t, k8s, secret)
	defer cancel()

	rrWire := buildRRWire(
		"host.example.com.",
		1,
		ClassIN,
		60,
		[]byte{10, 0, 0, 1},
	)
	for i := range 3 {
		resp := sendUpdate(
			t,
			addr,
			signedUpdate(
				t,
				uint16(0x0010+i),
				secret,
				keyName,
				[][]byte{rrWire},
			),
		)
		if resp.Header.Rcode != RcodeNoError {
			t.Errorf(
				"request %d: expected NOERROR, got rcode=%d",
				i,
				resp.Header.Rcode,
			)
		}
	}

	if len(k8s.ApplyCalls) != 3 {
		t.Fatalf("expected 3 apply calls, got %d", len(k8s.ApplyCalls))
	}

	name0 := k8s.ApplyCalls[0].Params.Name
	for i, call := range k8s.ApplyCalls[1:] {
		if call.Params.Name != name0 {
			t.Errorf(
				"apply %d: CR name not idempotent: %s != %s",
				i+1,
				call.Params.Name,
				name0,
			)
		}
	}
}
