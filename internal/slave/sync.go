// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

// maxDBBodyBytes computes the maximum acceptable byte size for a serialised DB
// payload (push or poll). The budget is generous but finite:
//
//	maxRecords × (numDNSSECKeys + 2) × 1024 bytes
//
// The +2 accounts for the record itself and NSEC3 chain overhead; each
// additional key adds roughly one RRSIG per record. 1 KiB per record covers
// the largest realistic JSON representation (base64-encoded RRSIG signatures
// included).
func (s *Slave) maxDBBodyBytes() int64 {
	maxRecords := s.cfg.Master.MaxRecords
	if maxRecords <= 0 {
		maxRecords = 100_000
	}

	numKeys := len(s.cfg.DNSSEC.Keys)

	return int64(maxRecords) * int64(numKeys+2) * 1024
}

// handleDBPush accepts a POST /db with JSON body and swaps the DB.
func (s *Slave) handleDBPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxDBBodyBytes())

	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	var newDB db.DB

	if err := json.Unmarshal(data, &newDB); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	s.swapDB(&newDB)
	s.dbSyncs.Inc("push")
	w.WriteHeader(http.StatusNoContent)
}

// handleDBDump serves GET /db/dump.
func (s *Slave) handleDBDump(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	d := s.currDB
	s.mu.RUnlock()

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

// poll fetches the DB from the master via GET /db/dump.
// Retries up to 10 times with 1s sleep on any network error or non-200 status.
func (s *Slave) poll(c *http.Client) error {
	url := fmt.Sprintf("http://%s/db/dump", s.cfg.Slave.MasterAddr)

	const maxAttempts = 10

	var resp *http.Response

	var lastErr error

	for attempt := range maxAttempts {
		var err error

		resp, err = c.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}

		if resp != nil {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			resp.Body.Close()
			resp = nil
		} else {
			lastErr = err
		}

		if attempt < maxAttempts-1 {
			s.logger.Info(
				fmt.Sprintf(
					"poll attempt %d/%d failed (%v), retrying in 1s",
					attempt+1,
					maxAttempts,
					lastErr,
				),
			)
			time.Sleep(time.Second)
		}
	}

	if resp == nil {
		return fmt.Errorf("GET %s: %w", url, lastErr)
	}

	defer resp.Body.Close()

	limit := s.maxDBBodyBytes()

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if int64(len(data)) > limit {
		return fmt.Errorf("poll response too large (>%d bytes)", limit)
	}

	var newDB db.DB
	if err := json.Unmarshal(data, &newDB); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	s.swapDB(&newDB)
	s.dbSyncs.Inc("poll")

	s.logger.Debug("db fetch done", log.Ctx{"new_size": newDB.RRCount()})

	return nil
}
