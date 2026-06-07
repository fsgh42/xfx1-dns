// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package ratelimit_test

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/ratelimit"
)

func udpAddr(ip string) net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: 1234}
}

func TestAllow(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  5,
		RatePerSec: 10,
		SlipRatio:  0,
	})
	now := time.Now()
	addr := udpAddr("1.2.3.4")

	for i := 0; i < 5; i++ {
		if d := l.CheckAt(addr, now); d != ratelimit.Allow {
			t.Fatalf("query %d: got %d, want Allow", i+1, d)
		}
	}
	// 6th should be dropped (no slip configured).
	if d := l.CheckAt(addr, now); d != ratelimit.Drop {
		t.Fatalf("query 6: got %d, want Drop", d)
	}
}

func TestRefill(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  5,
		RatePerSec: 10,
		SlipRatio:  0,
	})
	now := time.Now()
	addr := udpAddr("1.2.3.4")

	// Drain the bucket.
	for i := 0; i < 5; i++ {
		l.CheckAt(addr, now)
	}

	if d := l.CheckAt(addr, now); d != ratelimit.Drop {
		t.Fatalf("expected Drop after drain, got %d", d)
	}

	// Advance 200ms → 10/s * 0.2s = 2 tokens refilled.
	later := now.Add(200 * time.Millisecond)
	if d := l.CheckAt(addr, later); d != ratelimit.Allow {
		t.Fatalf("expected Allow after refill, got %d", d)
	}

	if d := l.CheckAt(addr, later); d != ratelimit.Allow {
		t.Fatalf("expected second Allow after refill, got %d", d)
	}
	// Third should drop (only 2 tokens were refilled).
	if d := l.CheckAt(addr, later); d != ratelimit.Drop {
		t.Fatalf("expected Drop after refill exhausted, got %d", d)
	}
}

func TestSlip(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1,
		RatePerSec: 0.001, // effectively no refill
		SlipRatio:  3,
	})
	now := time.Now()
	addr := udpAddr("10.0.0.1")

	// Query 1: Allow (uses the 1 token).
	if d := l.CheckAt(addr, now); d != ratelimit.Allow {
		t.Fatalf("query 1: got %d, want Allow", d)
	}

	// Queries 2..10: all rate-limited.
	// drops counter increments: 1,2,3,4,5,6,7,8,9
	// Slip when drops % 3 == 0, i.e. drops=3,6,9 → queries 4,7,10.
	expected := []ratelimit.Decision{
		ratelimit.Drop, // query 2, drops=1
		ratelimit.Drop, // query 3, drops=2
		ratelimit.Slip, // query 4, drops=3
		ratelimit.Drop, // query 5, drops=4
		ratelimit.Drop, // query 6, drops=5
		ratelimit.Slip, // query 7, drops=6
		ratelimit.Drop, // query 8, drops=7
		ratelimit.Drop, // query 9, drops=8
		ratelimit.Slip, // query 10, drops=9
	}
	for i, want := range expected {
		got := l.CheckAt(addr, now)
		if got != want {
			t.Fatalf("query %d: got %d, want %d", i+2, got, want)
		}
	}
}

func TestIPv4Prefix(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  2,
		RatePerSec: 0.001,
	})
	now := time.Now()

	a := udpAddr("1.2.3.4")
	b := udpAddr("1.2.3.200")
	c := udpAddr("1.2.4.1")

	// a and b share /24: drain together.
	l.CheckAt(a, now)
	l.CheckAt(b, now)

	if d := l.CheckAt(a, now); d != ratelimit.Drop {
		t.Fatalf("expected a and b to share bucket, got %d", d)
	}

	// c is a different /24: still has tokens.
	if d := l.CheckAt(c, now); d != ratelimit.Allow {
		t.Fatalf("expected c in separate bucket, got %d", d)
	}
}

func TestIPv6Prefix(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  2,
		RatePerSec: 0.001,
	})
	now := time.Now()

	a := udpAddr("2001:db8::1")
	b := udpAddr("2001:db8::ffff")
	c := udpAddr("2001:db8:1::1")

	// a and b share /48.
	l.CheckAt(a, now)
	l.CheckAt(b, now)

	if d := l.CheckAt(a, now); d != ratelimit.Drop {
		t.Fatalf("expected a and b to share bucket, got %d", d)
	}

	// c is a different /48.
	if d := l.CheckAt(c, now); d != ratelimit.Allow {
		t.Fatalf("expected c in separate bucket, got %d", d)
	}
}

func TestIPv4MappedIPv6(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  2,
		RatePerSec: 0.001,
	})
	now := time.Now()

	mapped := udpAddr("::ffff:1.2.3.4")
	native := udpAddr("1.2.3.100")

	l.CheckAt(mapped, now)
	l.CheckAt(native, now)

	if d := l.CheckAt(mapped, now); d != ratelimit.Drop {
		t.Fatalf("expected mapped and native to share bucket, got %d", d)
	}
}

func TestGC(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  5,
		RatePerSec: 10,
		MaxAge:     5 * time.Minute,
	})
	now := time.Now()

	// Create two buckets.
	l.CheckAt(udpAddr("1.2.3.4"), now)
	l.CheckAt(udpAddr("5.6.7.8"), now)

	if n := l.ActiveBuckets(); n != 2 {
		t.Fatalf("expected 2 buckets, got %d", n)
	}

	// Make those two buckets old enough to be evicted by normal GC (age > MaxAge).
	stale := now.Add(-10 * time.Minute)
	l.SetBucket("1.2.3.0/24", 5, stale, stale)
	l.SetBucket("5.6.7.0/24", 5, stale, stale)
	l.SetLastGC(now.Add(-2 * time.Minute))

	// Trigger GC via a new check at a time past the gcInterval (1 min after SetLastGC).
	gcTime := now.Add(-2*time.Minute + time.Minute + time.Second)
	l.CheckAt(udpAddr("9.9.9.9"), gcTime)

	// The two stale buckets should be gone; only 9.9.9.0/24 remains.
	if n := l.ActiveBuckets(); n != 1 {
		t.Fatalf("expected 1 bucket after GC, got %d", n)
	}
}

func TestNonUDPAddr(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1,
		RatePerSec: 0.001,
	})
	addr := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 80}

	if d := l.Check(addr); d != ratelimit.Allow {
		t.Fatalf("expected Allow for non-UDP addr, got %d", d)
	}
}

func TestPrefixKeyIPv4(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"1.2.3.4", "1.2.3.0/24"},
		{"10.0.0.255", "10.0.0.0/24"},
		{"192.168.1.1", "192.168.1.0/24"},
	}
	for _, tt := range tests {
		got := ratelimit.PrefixKey(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("PrefixKey(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestPrefixKeyIPv6(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"2001:db8::1", "2001:db8::/48"},
		{"2001:db8:abcd::1", "2001:db8:abcd::/48"},
		{"fe80::1", "fe80::/48"},
	}
	for _, tt := range tests {
		got := ratelimit.PrefixKey(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("PrefixKey(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{})
	now := time.Now()
	addr := udpAddr("1.2.3.4")

	// Should allow 200 queries (default burst).
	for i := 0; i < 200; i++ {
		if d := l.CheckAt(addr, now); d != ratelimit.Allow {
			t.Fatalf("query %d: got %d, want Allow (default burst=200)", i+1, d)
		}
	}

	if d := l.CheckAt(addr, now); d != ratelimit.Drop {
		t.Fatalf("query 201: expected Drop, got %d", d)
	}
}

// ── Allow() tests ─────────────────────────────────────────────────────────────

func TestAllow_Allow(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{BurstSize: 3, RatePerSec: 0.001})
	ip := net.ParseIP("1.2.3.4")
	now := time.Now()

	for i := range 3 {
		if err := l.AllowAt(ip, now); err != nil {
			t.Fatalf("query %d: got %v, want nil", i+1, err)
		}
	}
}

func TestAllow_RateLimited(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{BurstSize: 1, RatePerSec: 0.001})
	ip := net.ParseIP("1.2.3.4")
	now := time.Now()
	l.AllowAt(ip, now) // drain

	if err := l.AllowAt(ip, now); !errors.Is(err, ratelimit.ErrRateLimited) {
		t.Fatalf("got %v, want ErrRateLimited", err)
	}
}

func TestAllow_SeparatePrefixes(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{BurstSize: 1, RatePerSec: 0.001})
	now := time.Now()
	// Drain the /24 bucket for 1.2.3.x.
	l.AllowAt(net.ParseIP("1.2.3.4"), now)
	// Same /24 → limited.
	if err := l.AllowAt(net.ParseIP("1.2.3.99"), now); !errors.Is(
		err,
		ratelimit.ErrRateLimited,
	) {
		t.Fatalf("got %v, want ErrRateLimited", err)
	}
	// Different /24 → still has tokens.
	if err := l.AllowAt(net.ParseIP("2.3.4.5"), now); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
}

func TestAllow_Refill(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{BurstSize: 1, RatePerSec: 10})
	ip := net.ParseIP("10.0.0.1")
	now := time.Now()
	l.AllowAt(ip, now) // drain
	// After 200ms: 10/s * 0.2s = 2 tokens → allow.
	if err := l.AllowAt(ip, now.Add(200*time.Millisecond)); err != nil {
		t.Fatalf("got %v after refill, want nil", err)
	}
}

// ── MaxBuckets / GC tests ─────────────────────────────────────────────────────

// TestForceGC verifies that hitting ≥ 75% of MaxBuckets triggers force GC,
// which evicts the oldest 25% to make room for new IPs.
func TestForceGC(t *testing.T) {
	const max = 100
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  5,
		RatePerSec: 1,
		MaxBuckets: max,
		MaxAge:     time.Hour, // disable normal GC
	})

	base := time.Now()

	// Inject 80 buckets directly (bypasses capacity check) to reach 80% fill.
	for i := range 80 {
		key := fmt.Sprintf("10.0.%d.0/24", i)
		l.SetBucket(key, 5, base, base)
	}

	if n := l.ActiveBuckets(); n != 80 {
		t.Fatalf("expected 80 buckets after setup, got %d", n)
	}

	// A new /24 triggers force GC (fill 80% ≥ 75%): evicts oldest 25% of 80 = 20.
	later := base.Add(time.Millisecond)
	if err := l.AllowAt(net.ParseIP("192.168.1.1"), later); err != nil {
		t.Fatalf("AllowAt after force GC: %v", err)
	}

	// 80 - 20 evicted + 1 new = 61 buckets.
	if n := l.ActiveBuckets(); n > 61 {
		t.Errorf("expected ≤ 61 buckets after force GC, got %d", n)
	}
}

// TestForceGC_EvictsOldest verifies that force GC removes the oldest buckets,
// preserving the most recently created ones.
func TestForceGC_EvictsOldest(t *testing.T) {
	const max = 4
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  5,
		RatePerSec: 1,
		MaxBuckets: max,
		MaxAge:     time.Hour,
	})

	old := time.Now()
	recent := old.Add(time.Minute)

	// Inject 3 old buckets directly.
	l.SetBucket("1.0.0.0/24", 5, old, old)
	l.SetBucket("2.0.0.0/24", 5, old, old)
	l.SetBucket("3.0.0.0/24", 5, old, old)
	// 3 buckets = 75% of max=4 → next new IP triggers force GC.

	// New IP at "recent": force GC evicts oldest 25% (= 1), then inserts this one.
	if err := l.AllowAt(net.ParseIP("4.5.6.7"), recent); err != nil {
		t.Fatalf("AllowAt: %v", err)
	}
	// 3 - 1 evicted + 1 new = 3 buckets.
	if n := l.ActiveBuckets(); n != 3 {
		t.Errorf("expected 3 buckets, got %d", n)
	}
	// The most recently created bucket (4.5.6.0/24) should still exist.
	if err := l.AllowAt(net.ParseIP("4.5.6.8"), recent); err != nil {
		t.Fatalf("recently inserted bucket was evicted: %v", err)
	}
}

// TestNormalGC_AgeEviction verifies that normal GC removes buckets older than MaxAge.
func TestNormalGC_AgeEviction(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  5,
		RatePerSec: 10,
		MaxAge:     5 * time.Minute,
	})
	now := time.Now()

	l.CheckAt(udpAddr("1.2.3.4"), now)
	l.CheckAt(udpAddr("5.6.7.8"), now)

	stale := now.Add(-10 * time.Minute)
	l.SetBucket("1.2.3.0/24", 5, stale, stale)
	l.SetBucket("5.6.7.0/24", 5, stale, stale)
	l.SetLastGC(now.Add(-2 * time.Minute))

	// Advance past gcInterval to trigger periodic GC.
	gcTime := now.Add(-2*time.Minute + time.Minute + time.Second)
	l.CheckAt(udpAddr("9.9.9.9"), gcTime)

	if n := l.ActiveBuckets(); n != 1 {
		t.Fatalf("expected 1 bucket after normal GC, got %d", n)
	}
}

// TestUDPTableFull_Drops verifies that when the table is full (after force GC runs)
// UDP queries from new prefixes still get through — force GC always makes room.
func TestUDPTableFull_NeverDropsAfterGC(t *testing.T) {
	const max = 8
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  10,
		RatePerSec: 1,
		MaxBuckets: max,
		MaxAge:     time.Hour,
	})
	now := time.Now()

	// Drive 100 distinct /24s through the limiter; force GC should keep making room.
	for i := range 100 {
		ip := net.IPv4(byte(i+1), 0, 0, 1)

		d := l.CheckAt(
			&net.UDPAddr{IP: ip, Port: 53},
			now.Add(time.Duration(i)*time.Millisecond),
		)
		if d == ratelimit.Drop {
			// Drop is fine for rate-limited IPs but the first query from each new
			// prefix should always be allowed (fresh bucket = full tokens).
			// The first query from each distinct /24 must succeed.
			t.Errorf("prefix %d: first query from new /24 was dropped", i)
		}

		if l.ActiveBuckets() > max {
			t.Errorf(
				"bucket count %d exceeds MaxBuckets %d",
				l.ActiveBuckets(),
				max,
			)
		}
	}
}

// mustCIDR parses a CIDR string or fails the test; helper for allowlist tests.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()

	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}

	return n
}

// TestAllowlist_BypassUDP verifies that queries from allowlisted IPs are never
// rate-limited on the UDP path, even when the bucket would otherwise be drained.
func TestAllowlist_BypassUDP(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1,
		RatePerSec: 0.001,
		Allowlist:  []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
	})
	now := time.Now()
	addr := udpAddr("127.0.0.1")

	// Many more queries than the bucket would allow; all must be Allow.
	for i := 0; i < 100; i++ {
		if d := l.CheckAt(addr, now); d != ratelimit.Allow {
			t.Fatalf("query %d: got %d, want Allow (allowlisted)", i+1, d)
		}
	}
	// And crucially no bucket should have been created — allowlisted paths skip bucket logic.
	if n := l.ActiveBuckets(); n != 0 {
		t.Errorf("expected 0 buckets for allowlisted traffic, got %d", n)
	}
}

// TestAllowlist_BypassTCP verifies the same bypass applies to the Allow() path
// used by TCP and DoH.
func TestAllowlist_BypassTCP(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1,
		RatePerSec: 0.001,
		Allowlist:  []*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
	})
	ip := net.ParseIP("10.5.5.5")
	now := time.Now()

	for i := 0; i < 100; i++ {
		if err := l.AllowAt(ip, now); err != nil {
			t.Fatalf("query %d: got %v, want nil (allowlisted)", i+1, err)
		}
	}
}

// TestAllowlist_NonMatchStillLimited verifies that IPs outside the allowlist
// follow the normal rate-limit path.
func TestAllowlist_NonMatchStillLimited(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1,
		RatePerSec: 0.001,
		Allowlist:  []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
	})
	now := time.Now()
	addr := udpAddr("8.8.8.8")

	if d := l.CheckAt(addr, now); d != ratelimit.Allow {
		t.Fatalf("first query: got %d, want Allow", d)
	}

	if d := l.CheckAt(addr, now); d != ratelimit.Drop {
		t.Fatalf(
			"second query: got %d, want Drop (non-allowlisted, bucket drained)",
			d,
		)
	}
}

// TestAllowlist_IPv6 verifies IPv6 CIDR matching.
func TestAllowlist_IPv6(t *testing.T) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1,
		RatePerSec: 0.001,
		Allowlist: []*net.IPNet{
			mustCIDR(t, "::1/128"),
			mustCIDR(t, "fd00::/8"),
		},
	})
	now := time.Now()

	for _, ipStr := range []string{"::1", "fd12:3456::1"} {
		addr := udpAddr(ipStr)
		for i := 0; i < 5; i++ {
			if d := l.CheckAt(addr, now); d != ratelimit.Allow {
				t.Fatalf("%s query %d: got %d, want Allow", ipStr, i+1, d)
			}
		}
	}
}

func BenchmarkCheck(b *testing.B) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1000,
		RatePerSec: 1000,
	})
	addr := udpAddr("1.2.3.4")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		l.Check(addr)
	}
}

func BenchmarkAllow(b *testing.B) {
	l := ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  1000,
		RatePerSec: 1000,
	})
	ip := net.ParseIP("1.2.3.4")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		l.Allow(ip)
	}
}
