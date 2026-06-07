// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/runtime"
)

// Slave receives DB copies from the master and answers DNS queries.
type Slave struct {
	cfg    crd.DNSConfigSpec
	logger log.Logger

	mu         sync.RWMutex
	currDB     *db.DB
	nsec3Chain *dnssec.NSEC3Chain // nil if DNSSECEnabled is false; rebuilt on each DB swap
	ready      bool

	m       *metrics.Metrics
	queries *metrics.Counter
	dbSyncs *metrics.Counter

	httpServer *http.Server
}

// New constructs a Slave.
func New(cfg crd.DNSConfigSpec, logger log.Logger) *Slave {
	m := metrics.NewMetrics()
	queries := metrics.NewCounter(
		"slave_queries_total",
		nil,
		"rrtype",
		"rcode",
		"supported",
	)
	dbSyncs := metrics.NewCounter("slave_db_syncs_total", nil, "method")

	_ = m.Register("slave_queries_total", queries)
	_ = m.Register("slave_db_syncs_total", dbSyncs)

	return &Slave{
		cfg:     cfg,
		logger:  logger,
		m:       m,
		queries: queries,
		dbSyncs: dbSyncs,
	}
}

func (s *Slave) Healthy() runtime.StatusMessage {
	return runtime.StatusOK("healthy")
}

func (s *Slave) Ready() runtime.StatusMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.ready {
		return runtime.StatusNotReady("no database yet")
	}

	return runtime.StatusOK("ready")
}

// RenderAll implements metrics.MetricsProvider.
func (s *Slave) RenderAll() []string {
	return s.m.RenderAll()
}

// MainLoop starts the DNS server, HTTP server, and poll loop.
func (s *Slave) MainLoop(ctx context.Context) error {
	pollClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		},
	}

	// Warm up from snapshot before polling so that a temporarily unreachable
	// master does not block serving. Errors are non-fatal: log and continue.
	snapshotLoaded := false

	if path := s.cfg.Slave.SnapshotLocation; path != "" {
		if d, err := loadSnapshot(path); err != nil {
			s.logger.Error(fmt.Sprintf("load snapshot: %v", err))
		} else {
			s.swapDB(d)

			snapshotLoaded = true
		}
	}

	// initial database pull
	if err := s.poll(pollClient); err != nil {
		if !snapshotLoaded {
			return fmt.Errorf("initial poll: %w", err)
		}

		s.logger.Error(fmt.Sprintf("initial poll: %v", err))
	}

	// HTTP server: POST /db (push) and GET /db/dump.
	mux := http.NewServeMux()
	mux.HandleFunc("/db", s.handleDBPush)
	mux.HandleFunc("/db/dump", s.handleDBDump)
	s.httpServer = &http.Server{Addr: ":8080", Handler: mux}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			s.logger.Error(fmt.Sprintf("http server: %v", err))
		}
	}()

	defer s.httpServer.Close()

	listenPort := s.cfg.Slave.ListenPort
	if listenPort == 0 {
		listenPort = 5353
	}

	listenAddr := fmt.Sprintf(":%d", listenPort)

	// Start DNS UDP listener.
	udpConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", listenAddr, err)
	}
	defer udpConn.Close()

	go s.serveUDP(ctx, udpConn)

	// Start DNS TCP listener.
	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen TCP %s: %w", listenAddr, err)
	}
	defer tcpLn.Close()

	go s.serveTCP(ctx, tcpLn)

	// Poll loop.
	pollInterval := 60 * time.Second

	if s.cfg.Slave.PollInterval != "" {
		if d, err := time.ParseDuration(s.cfg.Slave.PollInterval); err == nil {
			pollInterval = d
		}
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.poll(pollClient); err != nil {
				s.logger.Error(fmt.Sprintf("poll: %v", err))
			}
		}
	}
}

// swapDB atomically replaces the current DB and rebuilds the NSEC3 chain if needed.
func (s *Slave) swapDB(newDB *db.DB) {
	var chain *dnssec.NSEC3Chain

	if newDB.DNSSECEnabled {
		var err error

		chain, err = dnssec.RebuildNSEC3Chain(newDB)
		if err != nil {
			s.logger.Error(fmt.Sprintf("rebuild NSEC3 chain: %v", err))

			chain = nil
		} else {
			s.logger.Info("rebuilt NSEC3 chain", log.Ctx{"rrCount": len(chain.Records)})
		}
	}

	s.mu.Lock()
	s.currDB = newDB
	s.nsec3Chain = chain
	s.ready = true
	s.mu.Unlock()
	s.logger.Info(
		"zone loaded",
		log.Ctx{"zone": newDB.Zone, "dnssec": newDB.DNSSECEnabled},
	)

	if path := s.cfg.Slave.SnapshotLocation; path != "" {
		if err := saveSnapshot(path, newDB); err != nil {
			s.logger.Error(fmt.Sprintf("save snapshot: %v", err))
		}
	}
}
