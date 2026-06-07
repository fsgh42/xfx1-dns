// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"fmt"
	"net"
)

// prefixKey computes the rate-limit key for an IP address:
// IPv4 → /24 (e.g. "1.2.3.0/24"), IPv6 → /48 (e.g. "2001:db8:abcd::/48").
// IPv4-mapped IPv6 addresses are treated as IPv4.
func prefixKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}

	v6 := ip.To16()
	if v6 == nil {
		return ip.String()
	}

	var masked net.IP = make(net.IP, net.IPv6len)

	copy(masked[:6], v6[:6])

	return masked.String() + "/48"
}
