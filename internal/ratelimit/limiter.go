// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"errors"
	"net"
	"sync"
	"time"
)

// ErrRateLimited is returned by Allow when the source prefix has exceeded its token budget.
var ErrRateLimited = errors.New("rate limited")

// ErrTableFull is returned by Allow when the bucket table is at capacity and GC could not
// free space. This is a safety-valve path; normal operation never reaches it because force
// GC always evicts at least one entry before a new bucket is created.
var ErrTableFull = errors.New("rate limit table full")

// Decision is the action the router should take for a UDP query.
type Decision int

const (
	Allow Decision = iota // forward the query normally
	Slip                  // send a TC=1 truncated response, do not forward
	Drop                  // silently discard the query
)

// Config holds rate-limiting parameters.
type Config struct {
	// BurstSize is the maximum number of tokens (queries) a bucket may accumulate.
	// Allows short bursts above the sustained rate. Default: 200.
	BurstSize int

	// RatePerSec is the token refill rate in queries per second per source prefix.
	// Default: 50.
	RatePerSec float64

	// SlipRatio: every SlipRatio-th dropped UDP query sends a TC=1 truncated response
	// instead of silently dropping. 0 disables slip. Only meaningful for UDP.
	SlipRatio int

	// MaxBuckets caps the number of concurrently tracked source prefixes. When the
	// table reaches 75% of this limit a force GC evicts the oldest 25% of buckets to
	// make room. 0 means uncapped (no force GC, periodic age-based GC only).
	MaxBuckets int

	// MaxAge is how long a bucket is kept before normal GC (fill < 75%) evicts it.
	// Default: 5 minutes.
	MaxAge time.Duration

	// Allowlist is a list of CIDR prefixes whose queries bypass rate limiting
	// entirely (no bucket lookup, no token consumption). Intended for loopback
	// and trusted internal networks. Parse with net.ParseCIDR upstream.
	Allowlist []*net.IPNet
}

// Limiter manages per-prefix token buckets with two-tier GC:
//   - Normal GC (periodic, fill < 75%): removes buckets older than MaxAge.
//   - Force GC (triggered at ≥ 75% fill): sorts by createdAt, evicts oldest 25%.
type Limiter struct {
	cfg Config

	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

const (
	gcInterval       = time.Minute
	gcForceThreshold = 0.75
)

// NewLimiter creates a Limiter with the given config. Zero values are replaced with defaults.
func NewLimiter(cfg Config) *Limiter {
	if cfg.BurstSize <= 0 {
		cfg.BurstSize = 200
	}

	if cfg.RatePerSec <= 0 {
		cfg.RatePerSec = 50
	}

	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 5 * time.Minute
	}

	return &Limiter{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
		lastGC:  time.Now(),
	}
}

// Allow checks whether ip is within its rate limit.
// Returns nil if the query is allowed, ErrRateLimited if the token budget is
// exhausted, or ErrTableFull if the bucket table is at capacity.
func (l *Limiter) Allow(ip net.IP) error {
	return l.allowAt(ip, time.Now())
}

func (l *Limiter) allowAt(ip net.IP, now time.Time) error {
	if l.allowlisted(ip) {
		return nil
	}

	key := prefixKey(ip)

	b, ok := l.getOrCreate(key, now)
	if !ok {
		return ErrTableFull
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if l.consume(b, now) {
		return nil
	}

	b.drops++

	return ErrRateLimited
}

// Check decides what to do with a UDP query from addr.
// Non-UDP addresses always receive Allow.
func (l *Limiter) Check(addr net.Addr) Decision {
	return l.checkAt(addr, time.Now())
}

func (l *Limiter) checkAt(addr net.Addr, now time.Time) Decision {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return Allow
	}

	if l.allowlisted(udp.IP) {
		return Allow
	}

	key := prefixKey(udp.IP)

	b, ok := l.getOrCreate(key, now)
	if !ok {
		return Drop // table full → drop UDP silently
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if l.consume(b, now) {
		return Allow
	}

	b.drops++
	if l.cfg.SlipRatio > 0 && b.drops%int64(l.cfg.SlipRatio) == 0 {
		return Slip
	}

	return Drop
}

// ActiveBuckets returns the number of tracked source prefixes.
func (l *Limiter) ActiveBuckets() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.buckets)
}
