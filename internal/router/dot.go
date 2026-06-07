// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// serveDoT handles DNS-over-TLS (RFC 7858).
// It reuses the TLS certificate loaded for DoH — same cert, different port.
// Like serveDoH, it retries loading TLS every 10s until certs are available.
func (rt *Router) serveDoT(ctx context.Context, timeout time.Duration) {
	dotPort := rt.cfg.Router.DoTPort
	if dotPort == 0 {
		dotPort = 8853
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		rt.tlsMu.RLock()
		tlsCfg := rt.tlsCfg
		rt.tlsMu.RUnlock()

		if tlsCfg != nil {
			break
		}

		rt.logger.Error("DoT: TLS cert not available, retrying in 10s")
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rt.loadTLS()
		}
	}

	rt.tlsMu.RLock()
	tlsCfg := rt.tlsCfg
	rt.tlsMu.RUnlock()

	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", dotPort), tlsCfg)
	if err != nil {
		rt.logger.Error(fmt.Sprintf("DoT listen :%d: %v", dotPort, err))
		return
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			continue
		}

		go rt.handleDoTConn(ctx, conn, timeout)
	}
}

func (rt *Router) handleDoTConn(
	ctx context.Context,
	conn net.Conn,
	timeout time.Duration,
) {
	defer conn.Close()

	select {
	case rt.dotSem <- struct{}{}:
		defer func() { <-rt.dotSem }()
	default:
		rt.maxConnRejects.Inc("dot")
		return
	}

	conn.SetDeadline(time.Now().Add(timeout))

	if rt.dotLimiter != nil {
		if ip := remoteIP(conn.RemoteAddr().String()); ip != nil {
			if err := rt.dotLimiter.Allow(ip); err != nil {
				rt.rlDrops.Inc("dot")
				rt.rlActiveBucket.Set(
					int64(rt.dotLimiter.ActiveBuckets()),
					"dot",
				)

				return
			}

			rt.rlActiveBucket.Set(int64(rt.dotLimiter.ActiveBuckets()), "dot")
		}
	}

	rt.handleDNSStreamConn(ctx, conn, timeout, "dot")
}
