// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package master

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/runtime"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/watch"
)

type (
	// Master is the single-instance controller that watches DNSRecord CRDs,
	// rebuilds the DNS database on any change, and pushes it to all slaves.
	Master struct {
		cfg       crd.DNSConfigSpec
		namespace string
		k8s       client.K8sClient
		logger    log.Logger

		mu      sync.RWMutex
		current *db.DB

		m                *metrics.Metrics
		rebuilds         *metrics.Counter
		rebuildErrors    *metrics.Counter
		rrCount          *metrics.Gauge
		resigns          *metrics.Counter
		watchParseErrors *metrics.Counter

		httpServer *http.Server
	}
)

var pushClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	},
}

// New constructs a Master.
func New(
	cfg crd.DNSConfigSpec,
	namespace string,
	k8sClient client.K8sClient,
	logger log.Logger,
) *Master {
	mtr := metrics.NewMetrics()
	rebuilds := metrics.NewCounter("master_db_rebuilds_total", nil)
	rebuildErrors := metrics.NewCounter("master_db_rebuild_errors_total", nil)
	rrCount := metrics.NewGauge("master_rr_count", nil, "rrtype")
	resigns := metrics.NewCounter("master_resigns_total", nil)
	watchParseErrors := metrics.NewCounter(
		"master_watch_parse_errors_total",
		nil,
	)

	_ = mtr.Register("master_db_rebuilds_total", rebuilds)
	_ = mtr.Register("master_db_rebuild_errors_total", rebuildErrors)
	_ = mtr.Register("master_rr_count", rrCount)
	_ = mtr.Register("master_resigns_total", resigns)
	_ = mtr.Register("master_watch_parse_errors_total", watchParseErrors)

	mst := &Master{
		cfg:              cfg,
		namespace:        namespace,
		k8s:              k8sClient,
		logger:           logger,
		m:                mtr,
		rebuilds:         rebuilds,
		rebuildErrors:    rebuildErrors,
		rrCount:          rrCount,
		resigns:          resigns,
		watchParseErrors: watchParseErrors,
	}

	return mst
}

func (ms *Master) Healthy() runtime.StatusMessage {
	return runtime.StatusOK("healthy")
}

func (ms *Master) Ready() runtime.StatusMessage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if ms.current == nil {
		return runtime.StatusNotReady("no database yet")
	}

	return runtime.StatusOK("ready")
}

// RenderAll implements metrics.MetricsProvider so runtime serves /metrics.
func (ms *Master) RenderAll() []string {
	return ms.m.RenderAll()
}

// MainLoop starts the master's watch loop and HTTP server.
func (ms *Master) MainLoop(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/db/dump", ms.handleDBDump)

	ms.httpServer = &http.Server{
		Addr:        ":8080",
		Handler:     mux,
		IdleTimeout: 30 * time.Second, // close keep-alive connections promptly on shutdown
	}

	go func() {
		if err := ms.httpServer.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			ms.logger.Error(fmt.Sprintf("http server: %v", err))
		}
	}()

	defer ms.httpServer.Close()

	params, err := api.ParamsFor[rec.RR]()
	if err != nil {
		return fmt.Errorf("ParamsFor DNSRecord: %w", err)
	}

	params.Namespace = ms.namespace

	events := watch.Watch[rec.RR](
		ctx,
		ms.k8s,
		params,
		16,
		ms.logger,
		ms.watchParseErrors,
	)

	// Initial rebuild before entering the event loop.
	if err := ms.rebuild(ctx, params); err != nil {
		ms.logger.Error(fmt.Sprintf("initial rebuild: %v", err))
	}

	// Periodic re-sign timer: re-build (and re-sign) at the configured interval
	// so RRSIG validity windows are refreshed before they expire.
	resignInterval := 24 * time.Hour

	if s := ms.cfg.Master.ResignInterval; s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			resignInterval = d
		} else {
			ms.logger.Error(fmt.Sprintf("invalid resignInterval %q, using 24h: %v", s, err))
		}
	}

	ticker := time.NewTicker(resignInterval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ms.resigns.Inc()

				if err := ms.rebuild(ctx, params); err != nil {
					ms.logger.Error(
						fmt.Sprintf("periodic resign rebuild: %v", err),
					)
				}
			}
		}
	}()

	// retryTimer fires when the last rebuild failed and needs a retry.
	// Stopped and nil when there is nothing to retry.
	var retryTimer *time.Timer

	retryC := func() <-chan time.Time {
		if retryTimer != nil {
			return retryTimer.C
		}

		return nil
	}

	doRebuild := func() {
		if err := ms.rebuild(ctx, params); err != nil {
			ms.logger.Error(fmt.Sprintf("rebuild: %v", err))

			if retryTimer == nil {
				retryTimer = time.NewTimer(30 * time.Second)
			}
		} else {
			if retryTimer != nil {
				retryTimer.Stop()
				retryTimer = nil
			}
		}
	}

	triggers := debounce(ctx, events, 5*time.Second, 30*time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-triggers:
			if !ok {
				return nil
			}

			doRebuild()
		case <-retryC():
			retryTimer = nil

			ms.logger.Info("retrying failed rebuild")
			doRebuild()
		}
	}
}

// pushToSlaves resolves the slave discovery record and POSTs the DB JSON to each slave.
func (ms *Master) pushToSlaves(d *db.DB) {
	data, err := json.Marshal(d)
	if err != nil {
		ms.logger.Error(fmt.Sprintf("marshal DB: %v", err))

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(
		ctx,
		ms.cfg.Master.SlaveDiscoveryRecord,
	)
	if err != nil {
		ms.logger.Error(
			fmt.Sprintf(
				"resolve slave discovery %s: %v",
				ms.cfg.Master.SlaveDiscoveryRecord,
				err,
			),
		)

		return
	}

	for _, addr := range addrs {
		addr := addr
		go func() {
			url := fmt.Sprintf("http://%s:8080/db", addr)

			resp, err := pushClient.Post(
				url,
				"application/json",
				bytes.NewReader(data),
			)
			if err != nil {
				ms.logger.Error(fmt.Sprintf("push to slave %s: %v", addr, err))
				return
			}

			resp.Body.Close()
			ms.logger.Info(fmt.Sprintf("pushed DB to slave %s", addr))
		}()
	}
}

// handleDBDump serves GET /db/dump — returns the current DB as JSON, or 503 if nil.
func (ms *Master) handleDBDump(w http.ResponseWriter, r *http.Request) {
	ms.mu.RLock()
	d := ms.current
	ms.mu.RUnlock()

	if d == nil {
		http.Error(w, "no database", http.StatusServiceUnavailable)

		return
	}

	data, err := json.Marshal(d)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
