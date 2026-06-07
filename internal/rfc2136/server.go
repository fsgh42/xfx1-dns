// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/runtime"
)

const (
	defaultListenPort = 5053

	// maxUDPSize is the maximum DNS message size over UDP.
	maxUDPSize = 4096
)

// Gateway is the RFC 2136 DNS UPDATE gateway.
// It implements runtime.Runnable.
type Gateway struct {
	cfg       crd.DNSConfigSpec
	namespace string
	k8s       client.K8sClient
	logger    log.Logger

	tsigKey    []byte // loaded from k8s Secret on startup
	tsigMu     sync.RWMutex
	tsigLoaded bool

	handler *Handler

	m               *metrics.Metrics
	updatesTotal    *metrics.Counter
	updateErrors    *metrics.Counter
	crNameOverflows *metrics.Counter
}

// New creates a new Gateway.
func New(
	cfg crd.DNSConfigSpec,
	namespace string,
	k8sClient client.K8sClient,
	logger log.Logger,
) *Gateway {
	m := metrics.NewMetrics()

	updatesTotal := metrics.NewCounter(
		"rfc2136_updates_total",
		nil,
		"operation",
	)
	updateErrors := metrics.NewCounter(
		"rfc2136_update_errors_total",
		nil,
		"reason",
	)
	crNameOverflows := metrics.NewCounter("rfc2136_cr_name_overflow_total", nil)
	_ = m.Register("rfc2136_updates_total", updatesTotal)
	_ = m.Register("rfc2136_update_errors_total", updateErrors)
	_ = m.Register("rfc2136_cr_name_overflow_total", crNameOverflows)

	handler := NewHandler(
		namespace,
		cfg.Global.Zone,
		k8sClient,
		logger,
		updatesTotal,
		updateErrors,
		crNameOverflows,
	)

	gw := &Gateway{
		cfg:             cfg,
		namespace:       namespace,
		k8s:             k8sClient,
		logger:          logger,
		handler:         handler,
		m:               m,
		updatesTotal:    updatesTotal,
		updateErrors:    updateErrors,
		crNameOverflows: crNameOverflows,
	}

	return gw
}

// Healthy implements runtime.Runnable.
func (g *Gateway) Healthy() runtime.StatusMessage {
	return runtime.StatusOK("healthy")
}

// Ready implements runtime.Runnable. Returns ready once the TSIG key is loaded.
func (g *Gateway) Ready() runtime.StatusMessage {
	g.tsigMu.RLock()
	loaded := g.tsigLoaded
	g.tsigMu.RUnlock()

	if !loaded {
		return runtime.StatusNotReady("TSIG key not loaded")
	}

	return runtime.StatusOK("ready")
}

// RenderAll implements metrics.MetricsProvider.
func (g *Gateway) RenderAll() []string {
	return g.m.RenderAll()
}

// MainLoop implements runtime.Runnable. Loads TSIG key, starts UDP+TCP listeners.
func (g *Gateway) MainLoop(ctx context.Context) error {
	// Step 1: Load TSIG secret
	if err := g.loadTSIGKey(ctx); err != nil {
		return fmt.Errorf("load TSIG key: %w", err)
	}

	port := g.cfg.RFC2136.ListenPort
	if port == 0 {
		port = defaultListenPort
	}

	addr := fmt.Sprintf(":%d", port)

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", addr, err)
	}
	defer udpConn.Close()

	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen TCP %s: %w", addr, err)
	}
	defer tcpLn.Close()

	g.logger.Info(
		fmt.Sprintf("RFC 2136 gateway listening on %s (UDP+TCP)", addr),
	)

	// Cancel listeners when ctx is done
	go func() {
		<-ctx.Done()
		udpConn.Close()
		tcpLn.Close()
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- g.serveUDP(ctx, udpConn) }()
	go func() { errCh <- g.serveTCP(ctx, tcpLn) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return err
		}

		return nil
	}
}

func (g *Gateway) loadTSIGKey(ctx context.Context) error {
	secretName := g.cfg.RFC2136.TSIGSecret
	if secretName == "" {
		return fmt.Errorf("RFC2136.tsigSecret is not configured")
	}

	secretData, err := client.GetSecret(ctx, g.k8s, g.namespace, secretName)
	if err != nil {
		return fmt.Errorf("get TSIG secret %s: %w", secretName, err)
	}

	raw, ok := secretData["tsigKey"]
	if !ok {
		return fmt.Errorf("TSIG secret %s has no 'tsigKey' field", secretName)
	}

	// The tsigKey field is a base64-encoded secret (same convention as miekg/dns).
	// GetSecret already decoded the k8s base64 layer, so raw holds the ASCII
	// base64 string bytes; decode once more to get the actual key material.
	key, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return fmt.Errorf(
			"TSIG secret %s: tsigKey is not valid base64: %w",
			secretName,
			err,
		)
	}

	g.tsigMu.Lock()
	g.tsigKey = key
	g.tsigLoaded = true
	g.tsigMu.Unlock()

	g.logger.Info(fmt.Sprintf("TSIG key loaded from secret %s", secretName))

	return nil
}

// serveUDP reads DNS UPDATE messages from UDP conn and sends responses.
func (g *Gateway) serveUDP(ctx context.Context, conn net.PacketConn) error {
	buf := make([]byte, maxUDPSize)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		go func() {
			resp := g.processMessage(data)

			if _, err := conn.WriteTo(resp, addr); err != nil &&
				ctx.Err() == nil {
				g.logger.Error(fmt.Sprintf("UDP write to %s: %v", addr, err))
			}
		}()
	}
}

// serveTCP accepts TCP connections and handles DNS UPDATE over TCP.
func (g *Gateway) serveTCP(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}

		go g.handleTCP(ctx, conn)
	}
}

// handleTCP handles a single TCP connection.
// DNS over TCP uses a 2-byte length prefix per RFC 1035 §4.2.2.
func (g *Gateway) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read 2-byte length prefix
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		g.logger.Error(fmt.Sprintf("TCP read length: %v", err))
		return
	}

	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen == 0 {
		return
	}

	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msgBuf); err != nil {
		g.logger.Error(fmt.Sprintf("TCP read message: %v", err))

		return
	}

	resp := g.processMessage(msgBuf)

	// Write 2-byte length prefix + response
	out := make([]byte, 2+len(resp))
	out[0] = byte(len(resp) >> 8)
	out[1] = byte(len(resp))
	copy(out[2:], resp)

	if _, err := conn.Write(out); err != nil && ctx.Err() == nil {
		g.logger.Error(fmt.Sprintf("TCP write: %v", err))
	}
}

// processMessage parses a DNS message, validates TSIG, processes updates, and returns a response.
func (g *Gateway) processMessage(data []byte) []byte {
	msg, err := ParseMessage(data)
	if err != nil {
		g.logger.Error(fmt.Sprintf("parse message: %v", err))
		g.updateErrors.Inc("parse")
		// Build a minimal SERVFAIL — we don't have an ID to echo back safely
		if len(data) >= 2 {
			resp := make([]byte, 12)
			resp[0] = data[0]
			resp[1] = data[1]
			resp[2] = 0x80 // QR=1
			resp[3] = byte(RcodeServFail)

			return resp
		}

		return []byte{0, 0, 0x80, byte(RcodeServFail), 0, 0, 0, 0, 0, 0, 0, 0}
	}

	if msg.Header.Opcode != OpcodeUpdate {
		return BuildResponse(msg, RcodeNotimp)
	}

	// Validate TSIG
	g.tsigMu.RLock()
	tsigKey := g.tsigKey
	g.tsigMu.RUnlock()

	if err := ValidateTSIG(msg, tsigKey, time.Now()); err != nil {
		g.logger.Error(fmt.Sprintf("TSIG validation failed: %v", err))
		g.updateErrors.Inc("tsig")

		resp := BuildResponse(msg, RcodeRefused)
		if msg.TSIG != nil {
			resp = appendUnsignedTSIG(resp, msg.TSIG)
		}

		return resp
	}

	// Log incoming update at debug level
	zone := "."
	if msg.Zone != nil {
		zone = msg.Zone.Name
	}

	for _, rr := range msg.Updates {
		g.logger.Debug(
			"UPDATE",
			log.Ctx{
				"zone":  zone,
				"class": rr.Class,
				"type":  rr.Type,
				"name":  rr.Name,
				"rdlen": rr.Rdlength,
			},
		)
	}

	// Process update operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rcode := g.handler.HandleUpdate(ctx, msg)

	resp := BuildResponse(msg, rcode)
	if msg.TSIG != nil {
		resp = SignResponse(resp, msg.TSIG, tsigKey)
	}

	return resp
}

// metricsProvider is satisfied by Gateway (used by runtime to serve /metrics).
var _ interface{ RenderAll() []string } = (*Gateway)(nil)
