// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"strings"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/query"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/ratelimit"
)

// serveDoH handles DNS-over-HTTPS (RFC 8484).
// It retries loading TLS every 10s until certs are available, then starts
// the server with conservative timeouts. This handles the common case where
// cert-manager provisions certs asynchronously after pod startup.
func (rt *Router) serveDoH(ctx context.Context, timeout time.Duration) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		rt.handleDoH(w, r, ctx, timeout)
	})

	// Wait for TLS certs to become available.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		rt.tlsMu.RLock()
		tlsCfg := rt.tlsCfg
		rt.tlsMu.RUnlock()

		if tlsCfg != nil {
			break
		}

		rt.logger.Error("DoH: TLS cert not available, retrying in 10s")
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

	dohPort := rt.cfg.Router.DoHPort
	if dohPort == 0 {
		dohPort = 8443
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", dohPort),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    4096,
		ErrorLog:          stdlog.New(&httpErrorWriter{rt.logger}, "", 0),
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.ListenAndServeTLS("", ""); err != nil &&
		err != http.ErrServerClosed {
		rt.logger.Error("DoH server: " + err.Error())
	}
}

func (rt *Router) handleDoH(
	w http.ResponseWriter,
	r *http.Request,
	ctx context.Context,
	timeout time.Duration,
) {
	// Connection cap: non-blocking acquire. Over-cap requests get a 503 so
	// CDN/clients know to back off rather than bug-report a 500.
	select {
	case rt.dohSem <- struct{}{}:
		defer func() { <-rt.dohSem }()
	default:
		rt.maxConnRejects.Inc("doh")
		http.Error(w, "server busy", http.StatusServiceUnavailable)

		return
	}

	if rt.dohLimiter != nil {
		// RemoteAddr is the raw socket peer; if you ever front DoH with an L7 proxy,
		// all traffic collapses into one bucket. Switch to X-Forwarded-For then.
		if ip := remoteIP(r.RemoteAddr); ip != nil {
			if err := rt.dohLimiter.Allow(ip); err != nil {
				rt.rlDrops.Inc("doh")
				rt.rlActiveBucket.Set(
					int64(rt.dohLimiter.ActiveBuckets()),
					"doh",
				)

				if errors.Is(err, ratelimit.ErrTableFull) {
					http.Error(w, "server busy", http.StatusServiceUnavailable)
				} else {
					http.Error(w, "rate limited", http.StatusTooManyRequests)
				}

				return
			}

			rt.rlActiveBucket.Set(int64(rt.dohLimiter.ActiveBuckets()), "doh")
		}
	}

	var (
		raw []byte
		err error
	)

	switch r.Method {
	case http.MethodGet:
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}

		raw, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			http.Error(w, "invalid base64", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(
				w,
				"invalid content-type",
				http.StatusUnsupportedMediaType,
			)

			return
		}

		raw, err = io.ReadAll(io.LimitReader(r.Body, maxDoHBodySize+1))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		if len(raw) > maxDoHBodySize {
			http.Error(
				w,
				"request body too large",
				http.StatusRequestEntityTooLarge,
			)

			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := query.New(raw)
	if err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	if reject, resp := rt.checkReject(req); reject {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)

		return
	}

	rt.recordQuery(req, "doh", remoteIP(r.RemoteAddr))

	resp, err := rt.forward(ctx, req.Bytes(), timeout, true)
	if err != nil {
		resp = response.ServfailResponse(req.ID(), req.Flags())
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

// httpErrorWriter routes http.Server error log messages to the structured logger.
type httpErrorWriter struct{ logger log.Logger }

func (w *httpErrorWriter) Write(p []byte) (int, error) {
	w.logger.Error(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
