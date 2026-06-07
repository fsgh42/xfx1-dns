// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"net"
	"time"
)

// CheckAt exposes checkAt for deterministic testing.
func (l *Limiter) CheckAt(addr net.Addr, now time.Time) Decision {
	return l.checkAt(addr, now)
}

// AllowAt exposes allowAt for deterministic testing.
func (l *Limiter) AllowAt(ip net.IP, now time.Time) error {
	return l.allowAt(ip, now)
}

// SetLastGC sets lastGC for testing GC behaviour.
func (l *Limiter) SetLastGC(t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastGC = t
}

// SetBucket injects a bucket directly for testing.
func (l *Limiter) SetBucket(
	key string,
	tokens float64,
	lastFill, createdAt time.Time,
) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets[key] = &bucket{
		tokens:    tokens,
		lastFill:  lastFill,
		createdAt: createdAt,
	}
}

// PrefixKey exposes prefixKey for testing.
func PrefixKey(ip net.IP) string {
	return prefixKey(ip)
}
