// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"sort"
	"time"
)

// maybeGC runs GC if the periodic interval has elapsed. Must be called with l.mu held.
func (l *Limiter) maybeGC(now time.Time) {
	if now.Sub(l.lastGC) < gcInterval {
		return
	}

	l.runGC(now)
}

// runGC selects and runs the appropriate GC pass. Must be called with l.mu held.
func (l *Limiter) runGC(now time.Time) {
	l.lastGC = now
	if l.cfg.MaxBuckets > 0 &&
		float64(len(l.buckets)) >= float64(l.cfg.MaxBuckets)*gcForceThreshold {
		l.forceGC()
	} else {
		l.normalGC(now)
	}
}

// normalGC removes buckets whose age exceeds MaxAge. Must be called with l.mu held.
func (l *Limiter) normalGC(now time.Time) {
	for key, b := range l.buckets {
		b.mu.Lock()
		old := now.Sub(b.createdAt) > l.cfg.MaxAge
		b.mu.Unlock()

		if old {
			delete(l.buckets, key)
		}
	}
}

// forceGC sorts all buckets by createdAt ascending and evicts the oldest 25% (minimum 1).
// Must be called with l.mu held.
func (l *Limiter) forceGC() {
	type entry struct {
		key       string
		createdAt time.Time
	}

	entries := make([]entry, 0, len(l.buckets))

	for key, b := range l.buckets {
		b.mu.Lock()
		entries = append(entries, entry{key, b.createdAt})
		b.mu.Unlock()
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].createdAt.Before(entries[j].createdAt)
	})

	toEvict := max(len(entries)/4, 1)
	for _, e := range entries[:toEvict] {
		delete(l.buckets, e.key)
	}
}
