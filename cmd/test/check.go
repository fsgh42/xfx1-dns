// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// supportedPlainTypes lists the RR types checked in plain/DoH/DoT rounds.
// RRSIG and NSEC3 are excluded: signatures change on every re-sign and
// NSEC3 records change with zone content.
var supportedPlainTypes = map[rec.RRtype]bool{
	rec.TypeA:          true,
	rec.TypeAAAA:       true,
	rec.TypeNS:         true,
	rec.TypeCNAME:      true,
	rec.TypeSOA:        true,
	rec.TypePTR:        true,
	rec.TypeMX:         true,
	rec.TypeTXT:        true,
	rec.TypeSRV:        true,
	rec.TypeCAA:        true,
	rec.TypeDNSKEY:     true,
	rec.TypeDS:         true,
	rec.TypeNSEC3PARAM: true,
}

// checkRecord runs all enabled checks for one DNSRecord CRD object.
func checkRecord(
	ctx context.Context,
	cfg *config,
	servers []string,
	tlsCfg *tls.Config,
	dnskeys []parsedDNSKEY,
	obj *base.Object[rec.RR],
) []result {
	var results []result

	label := obj.Metadata.Name
	qname := string(obj.Spec.Name)
	rrtype := obj.Spec.RRtype

	if !supportedPlainTypes[rrtype] {
		return nil
	}

	qtype, ok := rec.RRtypeToWire[rrtype]
	if !ok {
		return nil
	}

	if cfg.Plain {
		results = append(
			results,
			checkPlain(
				ctx,
				cfg,
				servers,
				label,
				qname,
				qtype,
				rrtype,
				obj.Spec.Opts,
			)...)
	}

	if cfg.DNSSEC {
		results = append(
			results,
			checkDNSSEC(
				ctx,
				cfg,
				servers,
				dnskeys,
				label,
				qname,
				qtype,
				rrtype,
			)...)
	}

	if cfg.DoH && tlsCfg != nil {
		results = append(
			results,
			checkDoH(
				ctx,
				cfg,
				servers,
				tlsCfg,
				label,
				qname,
				qtype,
				rrtype,
				obj.Spec.Opts,
			)...)
	}

	if cfg.DoT && tlsCfg != nil {
		results = append(
			results,
			checkDoT(
				ctx,
				cfg,
				servers,
				tlsCfg,
				label,
				qname,
				qtype,
				rrtype,
				obj.Spec.Opts,
			)...)
	}

	return results
}

// checkPlain tests a record over plain TCP and UDP against every server.
func checkPlain(
	ctx context.Context,
	cfg *config,
	servers []string,
	label, qname string,
	qtype uint16,
	rrtype rec.RRtype,
	opts rec.RRopts,
) []result {
	var results []result

	msg := buildQuery(0x1234, qname, qtype, false, false)

	for _, srv := range servers {
		addr := dnsAddr(srv, cfg.DNSPort)

		// TCP
		resp, err := sendTCP(addr, cfg.Timeout, msg)
		if err != nil {
			results = append(
				results,
				fail(label, "plain-tcp", addr, err.Error()),
			)
		} else {
			results = append(results, evalRdata("plain-tcp", label, addr, qtype, rrtype, opts, resp))
		}

		// UDP
		resp, err = sendUDP(addr, cfg.Timeout, msg)
		if err != nil {
			results = append(
				results,
				fail(label, "plain-udp", addr, err.Error()),
			)
		} else {
			results = append(results, evalRdata("plain-udp", label, addr, qtype, rrtype, opts, resp))
		}
	}

	return results
}

// checkDoH tests a record over DNS-over-HTTPS against every server.
func checkDoH(
	ctx context.Context,
	cfg *config,
	servers []string,
	tlsCfg *tls.Config,
	label, qname string,
	qtype uint16,
	rrtype rec.RRtype,
	opts rec.RRopts,
) []result {
	var results []result

	msg := buildQuery(0x1234, qname, qtype, false, false)

	for _, srv := range servers {
		url := dohURL(srv, cfg.DoHPort)

		resp, err := sendDoH(ctx, url, tlsCfg, cfg.Timeout, msg)
		if err != nil {
			results = append(results, fail(label, "doh", url, err.Error()))
		} else {
			results = append(results, evalRdata("doh", label, url, qtype, rrtype, opts, resp))
		}
	}

	return results
}

// checkDoT tests a record over DNS-over-TLS against every server.
func checkDoT(
	ctx context.Context,
	cfg *config,
	servers []string,
	tlsCfg *tls.Config,
	label, qname string,
	qtype uint16,
	rrtype rec.RRtype,
	opts rec.RRopts,
) []result {
	var results []result

	msg := buildQuery(0x1234, qname, qtype, false, false)

	for _, srv := range servers {
		addr := dnsAddr(srv, cfg.DoTPort)

		resp, err := sendDoT(ctx, addr, tlsCfg, cfg.Timeout, msg)
		if err != nil {
			results = append(results, fail(label, "dot", addr, err.Error()))
		} else {
			results = append(results, evalRdata("dot", label, addr, qtype, rrtype, opts, resp))
		}
	}

	return results
}

// checkDNSSEC verifies RRSIG records for one DNSRecord via TCP with DO bit.
func checkDNSSEC(
	ctx context.Context,
	cfg *config,
	servers []string,
	dnskeys []parsedDNSKEY,
	label, qname string,
	qtype uint16,
	rrtype rec.RRtype,
) []result {
	var results []result

	msg := buildQuery(0x1234, qname, qtype, true, true) // EDNS + DO

	rrsigType, _ := rec.RRtypeToWire[rec.TypeRRSIG]

	for _, srv := range servers {
		addr := dnsAddr(srv, cfg.DNSPort)
		tag := "dnssec"

		resp, err := sendTCP(addr, cfg.Timeout, msg)
		if err != nil {
			results = append(results, fail(label, tag, addr, err.Error()))
			continue
		}

		parsed, err := parseResponse(resp)
		if err != nil {
			results = append(
				results,
				fail(label, tag, addr, "parse: "+err.Error()),
			)

			continue
		}

		// Collect the non-RRSIG answers as the effective RRset. Deriving the
		// type from the actual answers (not qtype) handles CNAME fallback
		// responses where the server returns CNAME for an A/AAAA query.
		var rrset []parsedRR

		for _, rr := range parsed.answers {
			if rr.rtype != rrsigType {
				rrset = append(rrset, rr)
			}
		}

		if len(rrset) == 0 {
			results = append(results, fail(label, tag, addr, "no answers"))
			continue
		}

		effectiveType := rrset[0].rtype

		// Find RRSIG(s) covering the effective type.
		var rrsigs []parsedRRSIG

		for _, rr := range parsed.answers {
			if rr.rtype != rrsigType {
				continue
			}

			sig, err := parseRRSIGRdata(rr.rdata)
			if err != nil {
				continue
			}

			if sig.typeCovered == effectiveType {
				rrsigs = append(rrsigs, sig)
			}
		}

		if len(rrsigs) == 0 {
			results = append(
				results,
				fail(label, tag, addr, "no RRSIG for type"),
			)

			continue
		}

		// Verify at least one RRSIG against the fetched DNSKEYs.
		var verifyErr error

		for _, sig := range rrsigs {
			if err := verifyRRSIG(sig, rrset, dnskeys); err == nil {
				verifyErr = nil
				break
			} else {
				verifyErr = err
			}
		}

		if verifyErr != nil {
			results = append(
				results,
				fail(label, tag, addr, "verify: "+verifyErr.Error()),
			)
		} else {
			results = append(results, pass(label, tag, addr))
		}
	}

	return results
}

// checkEdns0 runs EDNS(0) compliance checks against all servers for the given zone.
func checkEdns0(cfg *config, servers []string, zone string) []result {
	var results []result

	soaType, _ := rec.RRtypeToWire[rec.TypeSOA]
	dnskeyType, _ := rec.RRtypeToWire[rec.TypeDNSKEY]

	for _, srv := range servers {
		addr := dnsAddr(srv, cfg.DNSPort)
		tag := "edns0"
		label := zone

		// 1. OPT record present in response (DO=0).
		msg := buildQuery(0x0001, zone, soaType, true, false)

		resp, err := sendUDP(addr, cfg.Timeout, msg)
		if err != nil {
			results = append(
				results,
				fail(label, tag+"-opt", addr, err.Error()),
			)
		} else {
			parsed, err := parseResponse(resp)
			if err != nil {
				results = append(results, fail(label, tag+"-opt", addr, "parse: "+err.Error()))
			} else if !parsed.hasOPT {
				results = append(results, fail(label, tag+"-opt", addr, "OPT record absent"))
			} else {
				results = append(results, pass(label, tag+"-opt", addr))
			}
		}

		// 2. DO bit echoed.
		msg = buildQuery(0x0002, zone, soaType, true, true)

		resp, err = sendUDP(addr, cfg.Timeout, msg)
		if err != nil {
			results = append(results, fail(label, tag+"-do", addr, err.Error()))
		} else {
			parsed, err := parseResponse(resp)
			if err != nil {
				results = append(results, fail(label, tag+"-do", addr, "parse: "+err.Error()))
			} else if !parsed.doBit {
				results = append(results, fail(label, tag+"-do", addr, "DO bit not echoed"))
			} else {
				results = append(results, pass(label, tag+"-do", addr))
			}
		}

		// 3. Large UDP response (DNSKEY) not truncated.
		if cfg.DNSSEC {
			msg = buildQuery(0x0003, zone, dnskeyType, true, false)

			resp, err = sendUDP(addr, cfg.Timeout, msg)
			if err != nil {
				results = append(
					results,
					fail(label, tag+"-nodrop", addr, err.Error()),
				)
			} else {
				parsed, err := parseResponse(resp)
				if err != nil {
					results = append(results, fail(label, tag+"-nodrop", addr, "parse: "+err.Error()))
				} else if parsed.flags&flagTC != 0 {
					results = append(results, fail(label, tag+"-nodrop", addr, "DNSKEY response truncated"))
				} else if len(parsed.answers) == 0 {
					results = append(results, fail(label, tag+"-nodrop", addr, "no DNSKEY answers"))
				} else {
					results = append(results, pass(label, tag+"-nodrop", addr))
				}
			}
		}
	}

	return results
}

// checkDoTALPN verifies that the DoT server negotiates the "dot" ALPN identifier
// (RFC 7858 §8.2). Strict clients such as kdig send a fatal alert when the
// server offers no ALPN, so advertising "dot" is a correctness requirement.
func checkDoTALPN(cfg *config, servers []string, tlsCfg *tls.Config) []result {
	var results []result

	dotCfg := tlsCfg.Clone()
	dotCfg.NextProtos = []string{"dot"}

	for _, srv := range servers {
		addr := dnsAddr(srv, cfg.DoTPort)

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: cfg.Timeout},
			"tcp",
			addr,
			dotCfg,
		)
		if err != nil {
			results = append(
				results,
				fail("dot-alpn", "dot-alpn", addr, err.Error()),
			)

			continue
		}

		got := conn.ConnectionState().NegotiatedProtocol
		conn.Close()

		if got != "dot" {
			results = append(results, fail("dot-alpn", "dot-alpn", addr,
				fmt.Sprintf("negotiated ALPN %q, want 'dot'", got)))
		} else {
			results = append(results, pass("dot-alpn", "dot-alpn", addr))
		}
	}

	return results
}

// checkNSEC3Probes queries a non-existent name and expects NXDOMAIN + NSEC3 in authority.
func checkNSEC3Probes(cfg *config, servers []string, zone string) []result {
	var results []result

	aType, _ := rec.RRtypeToWire[rec.TypeA]
	nsec3Type, _ := rec.RRtypeToWire[rec.TypeNSEC3]

	zonePlain := strings.TrimSuffix(zone, ".")
	probe := fmt.Sprintf("nonexistent-test-xfx1.%s.", zonePlain)

	msg := buildQuery(0x0004, probe, aType, true, true) // DO=1 to get NSEC3

	for _, srv := range servers {
		addr := dnsAddr(srv, cfg.DNSPort)
		tag := "dnssec-nsec3"

		resp, err := sendTCP(addr, cfg.Timeout, msg)
		if err != nil {
			results = append(results, fail(zone, tag, addr, err.Error()))
			continue
		}

		parsed, err := parseResponse(resp)
		if err != nil {
			results = append(
				results,
				fail(zone, tag, addr, "parse: "+err.Error()),
			)

			continue
		}

		if parsed.rcode != rcodeNXDomain {
			results = append(results, fail(zone, tag, addr,
				fmt.Sprintf("expected NXDOMAIN, got rcode %d", parsed.rcode)))
			continue
		}

		hasNSEC3 := false

		for _, rr := range parsed.authority {
			if rr.rtype == nsec3Type {
				hasNSEC3 = true
				break
			}
		}

		if !hasNSEC3 {
			results = append(
				results,
				fail(zone, tag, addr, "no NSEC3 in authority"),
			)
		} else {
			results = append(results, pass(zone, tag, addr))
		}
	}

	return results
}

// evalRdata parses a DNS response and checks it contains the expected RDATA.
func evalRdata(
	test, label, addr string,
	qtype uint16,
	rrtype rec.RRtype,
	opts rec.RRopts,
	raw []byte,
) result {
	parsed, err := parseResponse(raw)
	if err != nil {
		return fail(label, test, addr, "parse: "+err.Error())
	}

	if parsed.rcode != rcodeNoError {
		return fail(label, test, addr, fmt.Sprintf("rcode %d", parsed.rcode))
	}

	if parsed.flags&flagTC != 0 {
		return fail(label, test, addr, "response truncated")
	}

	if matchRdata(rrtype, opts, parsed.answers) {
		return pass(label, test, addr)
	}

	return fail(
		label,
		test,
		addr,
		fmt.Sprintf("want %s %s — not found in %d answer(s)",
			rrtype, opts.RRtype(), len(parsed.answers)),
	)
}

// matchRdata reports whether the expected record payload appears in answers.
// SOA is compared by mname+rname only (serial is server-assigned).
func matchRdata(rrtype rec.RRtype, opts rec.RRopts, answers []parsedRR) bool {
	want := opts.Payload()
	wireType := rec.RRtypeToWire[rrtype]

	for _, a := range answers {
		if a.rtype != wireType {
			continue
		}

		if rrtype == rec.TypeSOA {
			if soaMatch(want, a.rdata) {
				return true
			}
		} else {
			if bytes.Equal(want, a.rdata) {
				return true
			}
		}
	}

	return false
}

// soaMatch compares the mname and rname fields of two SOA RDATA byte slices,
// ignoring the serial, refresh, retry, expire, and minimum fields.
func soaMatch(want, got []byte) bool {
	wMname, wOff, err := parseUncompressedDomain(want, 0)
	if err != nil {
		return false
	}

	gMname, gOff, err := parseUncompressedDomain(got, 0)
	if err != nil {
		return false
	}

	if !strings.EqualFold(wMname, gMname) {
		return false
	}

	wRname, _, err := parseUncompressedDomain(want, wOff)
	if err != nil {
		return false
	}

	gRname, _, err := parseUncompressedDomain(got, gOff)
	if err != nil {
		return false
	}

	return strings.EqualFold(wRname, gRname)
}
