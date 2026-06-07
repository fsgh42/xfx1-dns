// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

func newTestRouter() *Router {
	return New(crd.DNSConfigSpec{}, log.New[log.Null, log.Logfmt]("test"))
}

// newTestRouterWithConnCaps builds a router whose connection caps are set to
// the given values, so over-cap behavior can be exercised without flooding.
func newTestRouterWithConnCaps(tcp, doh, dot int) *Router {
	return New(crd.DNSConfigSpec{
		Router: crd.RouterConfig{
			MaxConnections: crd.MaxConnectionsConfig{
				TCP: tcp,
				DoH: doh,
				DoT: dot,
			},
		},
	}, log.New[log.Null, log.Logfmt]("test"))
}

// TestHandleDoH_PostBodyTooLarge verifies SEC-02: POST bodies exceeding
// maxDoHBodySize are rejected with 413 before any forwarding occurs.
func TestHandleDoH_PostBodyTooLarge(t *testing.T) {
	rt := newTestRouter()
	body := bytes.Repeat([]byte("x"), maxDoHBodySize+1)
	req := httptest.NewRequest(
		http.MethodPost,
		"/dns-query",
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/dns-message")

	w := httptest.NewRecorder()

	rt.handleDoH(w, req, context.Background(), time.Second)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", w.Code)
	}
}

// TestHandleDoH_PostWrongContentType verifies that POST requests with the wrong
// content-type are rejected with 415.
func TestHandleDoH_PostWrongContentType(t *testing.T) {
	rt := newTestRouter()
	req := httptest.NewRequest(
		http.MethodPost,
		"/dns-query",
		bytes.NewReader([]byte("x")),
	)
	req.Header.Set("Content-Type", "text/plain")

	w := httptest.NewRecorder()

	rt.handleDoH(w, req, context.Background(), time.Second)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

// TestHandleDoH_MaxConnections verifies that requests arriving while the DoH
// semaphore is full receive HTTP 503. The cap is set to 1 and the slot is
// held by a goroutine so the second request hits the non-blocking default.
func TestHandleDoH_MaxConnections(t *testing.T) {
	rt := newTestRouterWithConnCaps(10, 1, 10)

	// Occupy the single DoH slot.
	rt.dohSem <- struct{}{}
	defer func() { <-rt.dohSem }()

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns=AAA", nil)
	w := httptest.NewRecorder()
	rt.handleDoH(w, req, context.Background(), time.Second)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// TestHandleTCPConn_MaxConnections verifies that over-cap TCP connections are
// closed immediately without a response (EOF/RST to the client).
func TestHandleTCPConn_MaxConnections(t *testing.T) {
	rt := newTestRouterWithConnCaps(1, 10, 10)

	// Occupy the single TCP slot.
	rt.tcpSem <- struct{}{}
	defer func() { <-rt.tcpSem }()

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		rt.handleTCPConn(context.Background(), server, time.Second)
	}()

	// Reader on the client end should see EOF promptly — handler returned
	// without writing anything because the sem was full.
	client.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected EOF on over-cap TCP conn, got data")
	}

	<-done
}

// TestParseAllowlist_EmptyUsesDefaults verifies that an empty CRD allowlist
// falls back to defaultAllowlistCIDRs — covering loopback, RFC 1918, link-local,
// CGNAT (incl. tailscale), and IPv6 ULA. Spot-check one IP per range.
func TestParseAllowlist_EmptyUsesDefaults(t *testing.T) {
	logger := log.New[log.Null, log.Logfmt]("test")

	nets := parseAllowlist(nil, logger)
	if len(nets) != len(defaultAllowlistCIDRs) {
		t.Fatalf(
			"expected %d default nets, got %d",
			len(defaultAllowlistCIDRs),
			len(nets),
		)
	}

	mustContain := []string{
		"127.0.0.1",   // loopback
		"10.0.0.1",    // RFC 1918 /8
		"172.20.0.1",  // RFC 1918 /12
		"192.168.1.1", // RFC 1918 /16
		"169.254.1.1", // IPv4 link-local
		"100.64.0.1",  // CGNAT (tailscale)
		"::1",         // IPv6 loopback
		"fd00::1",     // IPv6 ULA
		"fe80::1",     // IPv6 link-local
	}
	for _, s := range mustContain {
		ip := net.ParseIP(s)
		matched := false

		for _, n := range nets {
			if n.Contains(ip) {
				matched = true
				break
			}
		}

		if !matched {
			t.Errorf("default allowlist does not cover %s", s)
		}
	}
	// Routable sources must NOT match — guards against over-broad defaults.
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		ip := net.ParseIP(s)
		for _, n := range nets {
			if n.Contains(ip) {
				t.Errorf(
					"default allowlist should not cover public IP %s (matched %s)",
					s,
					n.String(),
				)
			}
		}
	}
}

// TestParseAllowlist_ExplicitOverridesDefaults verifies that any explicit entry
// replaces defaults wholesale (no merging).
func TestParseAllowlist_ExplicitOverridesDefaults(t *testing.T) {
	logger := log.New[log.Null, log.Logfmt]("test")

	nets := parseAllowlist([]string{"192.0.2.0/24"}, logger)
	if len(nets) != 1 {
		t.Fatalf(
			"expected exactly 1 net (no merging with defaults), got %d",
			len(nets),
		)
	}
	// 127.0.0.1 would match defaults but not the explicit list.
	if nets[0].Contains(net.ParseIP("127.0.0.1")) {
		t.Error(
			"explicit allowlist unexpectedly matched loopback — defaults leaked in",
		)
	}
}

// TestHandleDoTConn_MaxConnections verifies that over-cap DoT connections are
// closed immediately without a response (EOF/RST to the client).
func TestHandleDoTConn_MaxConnections(t *testing.T) {
	rt := newTestRouterWithConnCaps(10, 10, 1)

	// Occupy the single DoT slot.
	rt.dotSem <- struct{}{}
	defer func() { <-rt.dotSem }()

	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		rt.handleDoTConn(context.Background(), server, time.Second)
	}()

	client.SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected EOF on over-cap DoT conn, got data")
	}

	<-done
}

// TestHandleDoTConn_Deadline verifies that DoT connections that send a length
// prefix but never deliver the body are closed after the configured timeout.
func TestHandleDoTConn_Deadline(t *testing.T) {
	rt := newTestRouter()

	server, client := net.Pipe()
	defer client.Close()

	const timeout = 100 * time.Millisecond

	done := make(chan struct{})

	go func() {
		defer close(done)
		rt.handleDoTConn(context.Background(), server, timeout)
	}()

	binary.Write(client, binary.BigEndian, uint16(500))

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleDoTConn did not close connection after deadline")
	}
}

// generateTestCert writes a self-signed ECDSA cert+key pair to a temp dir and
// returns the file paths. The cert is valid for 1 hour — long enough for tests.
func generateTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		tmpl,
		tmpl,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certFile, keyFile
}

func newTestRouterWithCert(t *testing.T) *Router {
	t.Helper()
	certFile, keyFile := generateTestCert(t)

	return New(crd.DNSConfigSpec{
		Router: crd.RouterConfig{
			DoH: crd.DoHConfig{CertFile: certFile, KeyFile: keyFile},
		},
	}, log.New[log.Null, log.Logfmt]("test"))
}

// TestLoadTLS_AdvertisesDotALPN verifies that loadTLS sets "dot" in NextProtos
// so that RFC 7858-compliant clients (e.g. kdig) can negotiate the protocol.
func TestLoadTLS_AdvertisesDotALPN(t *testing.T) {
	rt := newTestRouterWithCert(t)
	rt.loadTLS()

	rt.tlsMu.RLock()
	cfg := rt.tlsCfg
	rt.tlsMu.RUnlock()

	if cfg == nil {
		t.Fatal("tlsCfg is nil after loadTLS")
	}

	for _, p := range cfg.NextProtos {
		if p == "dot" {
			return
		}
	}

	t.Errorf("NextProtos does not contain 'dot': %v", cfg.NextProtos)
}

// TestDoT_ALPNNegotiation verifies end-to-end that a TLS client offering "dot"
// ALPN successfully negotiates it against a listener using the router's tlsCfg.
func TestDoT_ALPNNegotiation(t *testing.T) {
	rt := newTestRouterWithCert(t)
	rt.loadTLS()

	rt.tlsMu.RLock()
	serverCfg := rt.tlsCfg.Clone()
	rt.tlsMu.RUnlock()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	negotiated := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			negotiated <- ""
			return
		}

		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			negotiated <- ""
			return
		}
		negotiated <- tlsConn.ConnectionState().NegotiatedProtocol
	}()

	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test-only self-signed cert
		NextProtos:         []string{"dot"},
	}

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatal("TLS dial failed:", err)
	}

	defer conn.Close()

	if got := conn.ConnectionState().NegotiatedProtocol; got != "dot" {
		t.Errorf("client negotiated protocol %q, want 'dot'", got)
	}

	if got := <-negotiated; got != "dot" {
		t.Errorf("server negotiated protocol %q, want 'dot'", got)
	}
}

// TestHandleTCPConn_Deadline verifies SEC-03: connections that send a length
// prefix but never deliver the body are closed after the configured timeout.
func TestHandleTCPConn_Deadline(t *testing.T) {
	rt := newTestRouter()

	server, client := net.Pipe()
	defer client.Close()

	const timeout = 100 * time.Millisecond

	done := make(chan struct{})

	go func() {
		defer close(done)
		rt.handleTCPConn(context.Background(), server, timeout)
	}()

	// Send 2-byte length prefix claiming 500 bytes but nothing more.
	binary.Write(client, binary.BigEndian, uint16(500))

	select {
	case <-done:
		// server-side goroutine exited — deadline worked
	case <-time.After(3 * time.Second):
		t.Fatal(
			"handleTCPConn did not close connection after deadline (SEC-03)",
		)
	}
}
