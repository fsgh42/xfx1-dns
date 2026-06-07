// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/query"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
)

// serveTCP handles TCP DNS connections.
func (rt *Router) serveTCP(
	ctx context.Context,
	ln net.Listener,
	timeout time.Duration,
) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			continue
		}

		go rt.handleTCPConn(ctx, conn, timeout)
	}
}

func (rt *Router) handleTCPConn(
	ctx context.Context,
	conn net.Conn,
	timeout time.Duration,
) {
	defer conn.Close()
	// Connection cap: non-blocking acquire. Over-cap connections are closed
	// without a response — same shape as the TCP rate-limit path.
	select {
	case rt.tcpSem <- struct{}{}:
		defer func() { <-rt.tcpSem }()
	default:
		rt.maxConnRejects.Inc("tcp")
		return
	}
	conn.SetDeadline(time.Now().Add(timeout))

	if rt.tcpLimiter != nil {
		if ip := remoteIP(conn.RemoteAddr().String()); ip != nil {
			if err := rt.tcpLimiter.Allow(ip); err != nil {
				rt.rlDrops.Inc("tcp")
				rt.rlActiveBucket.Set(
					int64(rt.tcpLimiter.ActiveBuckets()),
					"tcp",
				)

				return // close without response; client sees EOF/RST
			}

			rt.rlActiveBucket.Set(int64(rt.tcpLimiter.ActiveBuckets()), "tcp")
		}
	}

	rt.handleDNSStreamConn(ctx, conn, timeout, "tcp")
}

// handleDNSStreamConn reads one DNS message from conn, forwards it to a slave,
// and writes the response. The caller sets the deadline and handles sem/rate-limit.
// proto is "tcp" or "dot" and is used for metrics and log labels.
func (rt *Router) handleDNSStreamConn(
	ctx context.Context,
	conn net.Conn,
	timeout time.Duration,
	proto string,
) {
	var msgLen uint16
	if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
		return
	}

	raw := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return
	}

	req, err := query.New(raw)
	if err != nil {
		return // close without response; client sees EOF
	}

	if reject, resp := rt.checkReject(req); reject {
		binary.Write(conn, binary.BigEndian, uint16(len(resp)))
		conn.Write(resp)

		return
	}

	rt.recordQuery(req, proto, remoteIP(conn.RemoteAddr().String()))

	resp, err := rt.forward(ctx, req.Bytes(), timeout, true)
	if err != nil {
		resp = response.ServfailResponse(req.ID(), req.Flags())
	}

	binary.Write(conn, binary.BigEndian, uint16(len(resp)))
	conn.Write(resp)
}
