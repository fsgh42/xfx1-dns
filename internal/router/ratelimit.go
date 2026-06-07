// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"fmt"
	"net"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/ratelimit"
)

// defaultAllowlistCIDRs are the non-globally-routable ranges bypassed by the
// rate limiter when no explicit allowlist is configured. Router is assumed to
// face a public IP via hostPort, so any source in these ranges is local infra
// (cluster pods, node probes, LAN, tailscale mesh) and never an abuser.
// RFC refs: 1918 (private IPv4), 3927 (IPv4 link-local), 6598 (CGNAT),
// 4193 (IPv6 ULA), 4291 (IPv6 loopback/link-local).
var defaultAllowlistCIDRs = []string{
	"127.0.0.0/8",    // loopback
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"169.254.0.0/16", // IPv4 link-local
	"100.64.0.0/10",  // RFC 6598 CGNAT
	"::1/128",        // IPv6 loopback
	"fc00::/7",       // IPv6 ULA (covers fc00::/8 + fd00::/8)
	"fe80::/10",      // IPv6 link-local
}

// newLimiter constructs a Limiter from cfg when Enabled is true.
// allowlist is shared across all three protocol limiters (see parseAllowlist).
// defaultMaxBuckets is used when cfg.MaxBuckets is zero.
func newLimiter(
	cfg crd.RateLimitConfig,
	allowlist []*net.IPNet,
	defaultMaxBuckets int,
) *ratelimit.Limiter {
	if !cfg.Enabled {
		return nil
	}

	maxBuckets := cfg.MaxBuckets
	if maxBuckets <= 0 {
		maxBuckets = defaultMaxBuckets
	}

	maxAge := 5 * time.Minute

	if cfg.MaxAge != "" {
		if d, err := time.ParseDuration(cfg.MaxAge); err == nil {
			maxAge = d
		}
	}

	return ratelimit.NewLimiter(ratelimit.Config{
		BurstSize:  cfg.BurstSize,
		RatePerSec: cfg.RatePerSec,
		SlipRatio:  cfg.SlipRatio,
		MaxBuckets: maxBuckets,
		MaxAge:     maxAge,
		Allowlist:  allowlist,
	})
}

// parseAllowlist parses CIDR strings into *net.IPNet. An empty input falls
// back to defaultAllowlistCIDRs; to disable bypass entirely, configure an
// allowlist with a non-matching CIDR (e.g. ["255.255.255.255/32"]). Invalid
// entries are logged and skipped — an unparseable allowlist entry never fails
// router startup, since the safe fallback (no bypass) is to enforce the rate
// limit as normal.
func parseAllowlist(entries []string, logger log.Logger) []*net.IPNet {
	usingDefaults := false

	if len(entries) == 0 {
		entries = defaultAllowlistCIDRs
		usingDefaults = true
	}

	nets := make([]*net.IPNet, 0, len(entries))

	for _, e := range entries {
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			logger.Error(
				fmt.Sprintf(
					"ratelimit allowlist: skipping invalid CIDR %q: %v",
					e,
					err,
				),
			)

			continue
		}

		nets = append(nets, n)
	}

	if len(nets) > 0 {
		logger.Info(
			"ratelimit allowlist loaded",
			log.Ctx{"count": len(nets), "defaults": usingDefaults},
		)
	}

	return nets
}

// remoteIP extracts the IP from a "host:port" addr string.
func remoteIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	return net.ParseIP(host)
}
