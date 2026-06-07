// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/ratelimit"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/runtime"
)

const (
	opcodeQuery = 0
	qtypeAXFR   = 252
	qtypeIXFR   = 251

	// maxDoHBodySize is the upper bound for a DNS-over-HTTPS POST body.
	// Valid DNS messages never exceed 65535 bytes; 4096 is generous for queries.
	maxDoHBodySize = 4096

	// maxUDPMsgSize is the read-buffer size for UDP DNS messages (queries in,
	// responses from slaves). Matches the EDNS payload size we advertise.
	maxUDPMsgSize = 4096

	// defaultMaxConnections is applied when MaxConnectionsConfig fields are zero.
	// Sized for a small-scale authoritative server; bump per-config if you expect
	// more concurrent client connections.
	defaultMaxConnections = 10_000
)

// Router is the client-facing DNS proxy. It listens on UDP/TCP/DoH/DoT and forwards
// raw DNS wire bytes to all known slaves in parallel, returning the first response.
type Router struct {
	cfg    crd.DNSConfigSpec
	logger log.Logger

	m              *metrics.Metrics
	queries        *metrics.Counter
	rlDrops        *metrics.Counter
	rlSlips        *metrics.Counter
	rlActiveBucket *metrics.Gauge
	maxConnRejects *metrics.Counter

	udpLimiter *ratelimit.Limiter
	tcpLimiter *ratelimit.Limiter
	dohLimiter *ratelimit.Limiter
	dotLimiter *ratelimit.Limiter

	// tcpSem / dohSem / dotSem cap concurrent connections per protocol. Non-blocking
	// acquire: over-cap requests are rejected immediately (TCP/DoT close, DoH 503).
	tcpSem chan struct{}
	dohSem chan struct{}
	dotSem chan struct{}

	tlsMu  sync.RWMutex
	tlsCfg *tls.Config
}

// New constructs a Router.
func New(cfg crd.DNSConfigSpec, logger log.Logger) *Router {
	m := metrics.NewMetrics()
	queries := metrics.NewCounter(
		"router_queries_total",
		nil,
		"rrtype",
		"proto",
	)
	_ = m.Register("router_queries_total", queries)

	rlDrops := metrics.NewCounter("router_ratelimit_drops_total", nil, "proto")
	_ = m.Register("router_ratelimit_drops_total", rlDrops)
	rlSlips := metrics.NewCounter("router_ratelimit_slips_total", nil)
	_ = m.Register("router_ratelimit_slips_total", rlSlips)
	rlActiveBucket := metrics.NewGauge(
		"router_ratelimit_active_buckets",
		nil,
		"proto",
	)
	_ = m.Register("router_ratelimit_active_buckets", rlActiveBucket)
	maxConnRejects := metrics.NewCounter(
		"router_maxconn_rejects_total",
		nil,
		"proto",
	)
	_ = m.Register("router_maxconn_rejects_total", maxConnRejects)

	allowlist := parseAllowlist(cfg.Router.RateLimits.Allowlist, logger)

	limiter := newLimiter(cfg.Router.RateLimits.UDP, allowlist, 500_000)
	if limiter != nil {
		logger.Info(
			"UDP rate limiting enabled",
			log.Ctx{
				"burstSize":  cfg.Router.RateLimits.UDP.BurstSize,
				"ratePerSec": cfg.Router.RateLimits.UDP.RatePerSec,
				"slipRatio":  cfg.Router.RateLimits.UDP.SlipRatio,
				"maxBuckets": cfg.Router.RateLimits.UDP.MaxBuckets,
			},
		)
	}

	tcpLimiter := newLimiter(cfg.Router.RateLimits.TCP, allowlist, 100_000)
	if tcpLimiter != nil {
		logger.Info(
			"TCP rate limiting enabled",
			log.Ctx{
				"burstSize":  cfg.Router.RateLimits.TCP.BurstSize,
				"ratePerSec": cfg.Router.RateLimits.TCP.RatePerSec,
				"maxBuckets": cfg.Router.RateLimits.TCP.MaxBuckets,
			},
		)
	}

	dohLimiter := newLimiter(cfg.Router.RateLimits.DoH, allowlist, 100_000)
	if dohLimiter != nil {
		logger.Info(
			"DoH rate limiting enabled",
			log.Ctx{
				"burstSize":  cfg.Router.RateLimits.DoH.BurstSize,
				"ratePerSec": cfg.Router.RateLimits.DoH.RatePerSec,
				"maxBuckets": cfg.Router.RateLimits.DoH.MaxBuckets,
			},
		)
	}

	dotLimiter := newLimiter(cfg.Router.RateLimits.DoT, allowlist, 100_000)
	if dotLimiter != nil {
		logger.Info(
			"DoT rate limiting enabled",
			log.Ctx{
				"burstSize":  cfg.Router.RateLimits.DoT.BurstSize,
				"ratePerSec": cfg.Router.RateLimits.DoT.RatePerSec,
				"maxBuckets": cfg.Router.RateLimits.DoT.MaxBuckets,
			},
		)
	}

	tcpMax := cfg.Router.MaxConnections.TCP
	if tcpMax <= 0 {
		tcpMax = defaultMaxConnections
	}

	dohMax := cfg.Router.MaxConnections.DoH
	if dohMax <= 0 {
		dohMax = defaultMaxConnections
	}

	dotMax := cfg.Router.MaxConnections.DoT
	if dotMax <= 0 {
		dotMax = defaultMaxConnections
	}

	rtr := &Router{
		cfg:            cfg,
		logger:         logger,
		m:              m,
		queries:        queries,
		rlDrops:        rlDrops,
		rlSlips:        rlSlips,
		rlActiveBucket: rlActiveBucket,
		maxConnRejects: maxConnRejects,
		udpLimiter:     limiter,
		tcpLimiter:     tcpLimiter,
		dohLimiter:     dohLimiter,
		dotLimiter:     dotLimiter,
		tcpSem:         make(chan struct{}, tcpMax),
		dohSem:         make(chan struct{}, dohMax),
		dotSem:         make(chan struct{}, dotMax),
	}

	return rtr
}

func (rt *Router) Healthy() runtime.StatusMessage { return runtime.StatusOK("healthy") }

func (rt *Router) Ready() runtime.StatusMessage { return runtime.StatusOK("ready") }

// RenderAll implements metrics.MetricsProvider.
func (rt *Router) RenderAll() []string { return rt.m.RenderAll() }

// MainLoop starts the UDP, TCP, DoH, and DoT listeners.
func (rt *Router) MainLoop(ctx context.Context) error {
	forwardTimeout := 2 * time.Second

	if rt.cfg.Router.ForwardTimeout != "" {
		if d, err := time.ParseDuration(rt.cfg.Router.ForwardTimeout); err == nil {
			forwardTimeout = d
		}
	}

	// Try to load TLS certs; serveDoH retries in the background if unavailable.
	rt.loadTLS()

	listenPort := rt.cfg.Router.ListenPort
	if listenPort == 0 {
		listenPort = 5353
	}

	listenAddr := fmt.Sprintf(":%d", listenPort)

	// UDP listener.
	udpConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", listenAddr, err)
	}

	defer udpConn.Close()

	go rt.serveUDP(ctx, udpConn, forwardTimeout)

	// TCP listener.
	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen TCP %s: %w", listenAddr, err)
	}

	defer tcpLn.Close()

	go rt.serveTCP(ctx, tcpLn, forwardTimeout)

	// DoH listener (port 443).
	go rt.serveDoH(ctx, forwardTimeout)

	// DoT listener (port 853).
	go rt.serveDoT(ctx, forwardTimeout)

	<-ctx.Done()

	return nil
}

// loadTLS attempts to load TLS certificates.
func (rt *Router) loadTLS() {
	cert, err := tls.LoadX509KeyPair(
		rt.cfg.Router.DoH.CertFile,
		rt.cfg.Router.DoH.KeyFile,
	)
	if err != nil {
		rt.logger.Error(fmt.Sprintf("load TLS cert: %v", err))
		return
	}

	rt.tlsMu.Lock()
	// "dot" satisfies RFC 7858 §8.2; without it strict clients (e.g. kdig) send
	// a fatal alert when the server offers no ALPN. net/http appends "h2"/"http/1.1"
	// when it takes ownership of this config for DoH, so both transports are covered.
	rt.tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"dot"},
	}
	rt.tlsMu.Unlock()
}
