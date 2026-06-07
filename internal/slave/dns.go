// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/query"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dns/response"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// serveUDP handles incoming UDP DNS packets.
func (s *Slave) serveUDP(ctx context.Context, conn net.PacketConn) {
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

			s.logger.Error(fmt.Sprintf("udp read: %v", err))

			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		go func() {
			req, resp, qi := s.handleDNS(query)
			if resp == nil {
				return
			}

			if qi.rrtype != "" {
				s.queries.Inc(
					string(qi.rrtype),
					rcodeName(qi.rcode),
					fmt.Sprintf("%t", qi.supported),
				)
				s.logger.Debug(
					"query",
					log.Ctx{
						"proto":  "udp",
						"qname":  qi.qname,
						"qtype":  string(qi.rrtype),
						"rcode":  rcodeName(qi.rcode),
						"dnssec": qi.dnssec,
					},
				)
			}

			// Determine UDP truncation threshold from EDNS.
			// RFC 6891 §6.2.3: values below 512 MUST be treated as 512.
			maxUDP := 512
			if qi.udpSize > 512 {
				maxUDP = int(qi.udpSize)
			}

			if maxUDP > maxUDPMsgSize {
				maxUDP = maxUDPMsgSize
			}

			if len(resp) > maxUDP {
				resp = response.TruncatedResponse(req.ID(), req.Flags(), true)
			}

			conn.WriteTo(resp, addr)
		}()
	}
}

// serveTCP handles incoming TCP DNS connections.
func (s *Slave) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			s.logger.Error(fmt.Sprintf("tcp accept: %v", err))

			continue
		}

		go s.handleTCPConn(conn, tcpConnTimeout)
	}
}

func (s *Slave) handleTCPConn(conn net.Conn, timeout time.Duration) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	// Read 2-byte length prefix.
	var msgLen uint16

	if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
		return
	}

	query := make([]byte, msgLen)

	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}

	req, resp, qi := s.handleDNS(query)
	if resp == nil {
		return
	}

	if qi.rrtype != "" {
		s.queries.Inc(
			string(qi.rrtype),
			rcodeName(qi.rcode),
			fmt.Sprintf("%t", qi.supported),
		)
		s.logger.Debug(
			"query",
			log.Ctx{
				"proto":  "tcp",
				"qname":  qi.qname,
				"qtype":  string(qi.rrtype),
				"rcode":  rcodeName(qi.rcode),
				"dnssec": qi.dnssec,
			},
		)
	}

	if len(resp) > maxTCPResponseSize {
		// Byte-slicing a DNS message mid-record produces malformed wire data.
		// Return a clean TC=1 response so the client knows to retry differently.
		resp = response.TruncatedResponse(req.ID(), req.Flags(), true)
	}

	// Write 2-byte length prefix + response.
	if err := binary.Write(conn, binary.BigEndian, uint16(len(resp))); err != nil {
		return
	}

	conn.Write(resp)
}

// handleDNS processes one DNS query message and returns the parsed request,
// a response, and query metadata. req is nil when the message is malformed.
func (s *Slave) handleDNS(msg []byte) (*query.Request, []byte, queryInfo) {
	req, err := query.New(msg)
	if err != nil {
		s.logger.Debug(fmt.Sprintf("drop malformed query: %v", err))
		return nil, nil, queryInfo{}
	}

	txid := req.ID()
	flags := req.Flags()
	qname := req.QName
	qtype := req.QType
	pos := req.QuestionEnd()

	// Reject non-query opcodes (UPDATE etc.) with REFUSED.
	if req.Opcode != opcodeQuery {
		resp := response.RefusedResponse(txid, flags)
		return req, resp, queryInfo{}
	}

	// Reject AXFR/IXFR.
	if qtype == qtypeAXFR || qtype == qtypeIXFR {
		resp := response.RefusedResponse(txid, flags)
		qi := queryInfo{
			qname:  qname,
			rrtype: rec.RRtype(fmt.Sprintf("%d", qtype)),
			rcode:  response.RcodeRefused,
		}

		return req, resp, qi
	}

	// Parse EDNS(0) from additional section.
	edns := parseOPT(msg, pos)
	doBit := edns.do

	rrtype, ok := rec.RRtypeFromWire[qtype]
	if !ok {
		// Unknown type — return NOERROR with no answers.
		resp := response.BuildResponse(
			txid,
			flags,
			msg[12:pos],
			nil,
			nil,
			nil,
			response.RcodeNoError,
		)
		if edns.present {
			resp = response.AppendOPT(resp, edns.do, 0)
		}

		qi := queryInfo{
			qname:   qname,
			rrtype:  rec.RRtype(fmt.Sprintf("%d", qtype)),
			udpSize: edns.udpSize,
		}

		return req, resp, qi
	}

	// BADVERS: reject EDNS versions > 0 (RFC 6891 §6.1.3).
	if edns.present && edns.version != 0 {
		resp := response.BuildResponse(
			txid,
			flags,
			msg[12:pos],
			nil,
			nil,
			nil,
			response.RcodeNoError,
		)
		// Extended RCODE 16 (BADVERS) = OPT TTL byte 0 = 1, header RCODE = 0.
		resp = response.AppendOPT(resp, false, 1)

		qi := queryInfo{
			qname:     qname,
			rrtype:    rrtype,
			rcode:     16,
			udpSize:   edns.udpSize,
			supported: true,
		}

		return req, resp, qi
	}

	s.mu.RLock()
	currDB := s.currDB
	chain := s.nsec3Chain
	s.mu.RUnlock()

	var (
		rcode      uint16
		answers    []*rec.RR
		additional []*rec.RR
		authority  []*rec.RR
	)

	if currDB == nil {
		rcode = response.RcodeRefused
	} else {
		name, err := rec.NewDomain(qname)
		if err != nil {
			rcode = response.RcodeRefused
		} else {
			var effectiveOwner rec.Domain
			rcode, answers, additional, effectiveOwner = lookupRRset(currDB, name, rrtype)

			answers, authority, err = appendDNSSEC(currDB, chain, name, effectiveOwner, qtype, rcode, answers, authority, doBit)
			if err != nil {
				s.logger.Error(fmt.Sprintf("ClosestEncloserProof %s: %v", name, err))
			}

			authority = appendNegativeAuthority(currDB, rcode, answers, authority, doBit)
		}
	}

	qi := queryInfo{
		qname:     qname,
		rrtype:    rrtype,
		rcode:     rcode,
		dnssec:    doBit,
		udpSize:   edns.udpSize,
		supported: true,
	}

	resp := response.BuildResponse(
		txid,
		flags,
		msg[12:pos],
		answers,
		additional,
		authority,
		rcode,
	)

	if edns.present {
		resp = response.AppendOPT(resp, edns.do, 0)
	}

	return req, resp, qi
}

// synthesiseAnswers copies wildcardRRs with each record's Name replaced by
// queriedName, implementing RFC 1034 §4.3.2 owner-name synthesis.
// The original *rec.RR pointers are not mutated.
func synthesiseAnswers(
	wildcardRRs []*rec.RR,
	queriedName rec.Domain,
) []*rec.RR {
	result := make([]*rec.RR, len(wildcardRRs))

	for i, rr := range wildcardRRs {
		copy := *rr
		copy.Name = queriedName
		result[i] = &copy
	}

	return result
}
