// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"net"
	"sync"
	"time"
)

type bucket struct {
	mu        sync.Mutex
	tokens    float64
	lastFill  time.Time
	createdAt time.Time
	drops     int64
}

// consume refills tokens proportional to elapsed time and consumes one token.
// Returns true if the query is allowed. Must be called with b.mu held.
func (l *Limiter) consume(b *bucket, now time.Time) bool {
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.cfg.RatePerSec
		if b.tokens > float64(l.cfg.BurstSize) {
			b.tokens = float64(l.cfg.BurstSize)
		}

		b.lastFill = now
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// allowlisted reports whether ip is in any of the configured allowlist CIDRs.
// Callers bypass bucket lookup and token consumption entirely for these IPs.
func (l *Limiter) allowlisted(ip net.IP) bool {
	for _, n := range l.cfg.Allowlist {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// getOrCreate returns the bucket for key, creating one if needed.
// Returns (nil, false) if the table is at MaxBuckets capacity and GC cannot free space.
// Must not be called with l.mu held.
func (l *Limiter) getOrCreate(key string, now time.Time) (*bucket, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Run GC before the lookup so any bucket we return is guaranteed to still
	// be in the map (forceGC evicts by createdAt, which can include the key we
	// would otherwise have just found).
	if l.cfg.MaxBuckets > 0 &&
		float64(len(l.buckets)) >= float64(l.cfg.MaxBuckets)*gcForceThreshold {
		l.runGC(now) // bypass periodic timer: must free space now
	} else {
		l.maybeGC(now)
	}

	if b, ok := l.buckets[key]; ok {
		return b, true
	}

	// New prefix: enforce capacity before inserting.
	if l.cfg.MaxBuckets > 0 && len(l.buckets) >= l.cfg.MaxBuckets {
		return nil, false // safety valve; normally unreachable after force GC
	}

	b := &bucket{
		tokens:    float64(l.cfg.BurstSize),
		lastFill:  now,
		createdAt: now,
	}
	l.buckets[key] = b

	return b, true
}
