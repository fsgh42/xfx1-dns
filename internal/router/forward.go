// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package router

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/query"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// checkReject returns (true, REFUSED response) if the query should be rejected.
func (rt *Router) checkReject(req *query.Request) (bool, []byte) {
	if req.Opcode != opcodeQuery {
		return true, response.RefusedResponse(req.ID(), req.Flags())
	}

	if req.QType == qtypeAXFR || req.QType == qtypeIXFR {
		return true, response.RefusedResponse(req.ID(), req.Flags())
	}

	return false, nil
}

// recordQuery increments the query counter and logs the query.
// proto is "udp", "tcp", "doh", or "dot"; ip is the client IP (nil if unparseable).
func (rt *Router) recordQuery(req *query.Request, proto string, ip net.IP) {
	rrtype, ok := rec.RRtypeFromWire[req.QType]
	if !ok {
		return
	}

	rt.queries.Inc(string(rrtype), proto)
	rt.logger.Debug("query", log.Ctx{
		"proto": proto,
		"qname": req.QName,
		"qtype": string(rrtype),
		"ip":    ip,
	})
}

// forward resolves the slave discovery record on every call (no caching) so that
// DaemonSet scale-out is picked up immediately, then sends the DNS query to all
// resolved addresses in parallel and returns the first response.
func (rt *Router) forward(
	ctx context.Context,
	query []byte,
	timeout time.Duration,
	useTCP bool,
) ([]byte, error) {
	addrs, err := net.DefaultResolver.LookupHost(
		ctx,
		rt.cfg.Router.SlaveDiscoveryRecord,
	)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf(
			"resolve slaves %s: %w",
			rt.cfg.Router.SlaveDiscoveryRecord,
			err,
		)
	}

	slavePort := rt.cfg.Router.SlavePort
	if slavePort == 0 {
		slavePort = 5353
	}

	slavePortStr := strconv.Itoa(slavePort)

	ch := make(chan []byte, len(addrs))

	for _, addr := range addrs {
		go func() {
			resp, err := forwardTo(
				net.JoinHostPort(addr, slavePortStr),
				query,
				timeout,
				useTCP,
			)
			if err != nil {
				return
			}
			select {
			case ch <- resp:
			default:
			}
		}()
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-deadline.C:
		return nil, fmt.Errorf("forward timeout")
	case resp := <-ch:
		return resp, nil
	}
}

// forwardTo sends query to a single slave and returns the response.
// addrPort must be a host:port string (e.g. from net.JoinHostPort).
func forwardTo(
	addrPort string,
	query []byte,
	timeout time.Duration,
	useTCP bool,
) ([]byte, error) {
	if useTCP {
		conn, err := net.DialTimeout("tcp", addrPort, timeout)
		if err != nil {
			return nil, err
		}

		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))

		if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
			return nil, err
		}

		if _, err := conn.Write(query); err != nil {
			return nil, err
		}

		var respLen uint16
		if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
			return nil, err
		}

		resp := make([]byte, respLen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}

		return resp, nil
	}

	conn, err := net.DialTimeout("udp", addrPort, timeout)
	if err != nil {
		return nil, err
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	resp := make([]byte, maxUDPMsgSize)

	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}

	return resp[:n], nil
}
