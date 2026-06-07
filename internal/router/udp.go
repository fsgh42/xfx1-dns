// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"context"
	"fmt"
	"net"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/query"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/ratelimit"
)

// serveUDP handles UDP DNS packets.
func (rt *Router) serveUDP(
	ctx context.Context,
	conn net.PacketConn,
	timeout time.Duration,
) {
	buf := make([]byte, maxUDPMsgSize)

	for {
		if ctx.Err() != nil {
			return
		}

		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			rt.logger.Error(fmt.Sprintf("udp read: %v", err))

			continue
		}

		raw := make([]byte, n)
		copy(raw, buf[:n])

		req, err := query.New(raw)
		if err != nil {
			continue // drop malformed
		}

		if rt.udpLimiter != nil {
			switch rt.udpLimiter.Check(addr) {
			case ratelimit.Slip:
				rt.rlSlips.Inc()
				conn.WriteTo(
					response.TruncatedResponse(req.ID(), req.Flags(), false),
					addr,
				)
				rt.rlActiveBucket.Set(
					int64(rt.udpLimiter.ActiveBuckets()),
					"udp",
				)

				continue
			case ratelimit.Drop:
				rt.rlDrops.Inc("udp")
				rt.rlActiveBucket.Set(
					int64(rt.udpLimiter.ActiveBuckets()),
					"udp",
				)

				continue
			}

			rt.rlActiveBucket.Set(int64(rt.udpLimiter.ActiveBuckets()), "udp")
		}

		go func() {
			if reject, resp := rt.checkReject(req); reject {
				conn.WriteTo(resp, addr)
				return
			}

			rt.recordQuery(req, "udp", remoteIP(addr.String()))

			resp, err := rt.forward(ctx, req.Bytes(), timeout, false)
			if err != nil {
				rt.logger.Error(fmt.Sprintf("udp forward: %v", err))

				resp = response.ServfailResponse(req.ID(), req.Flags())
			}

			conn.WriteTo(resp, addr)
		}()
	}
}
