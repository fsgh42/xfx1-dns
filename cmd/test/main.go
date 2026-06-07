// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	_ "git.xfx1.de/infrastructure/xfx1-dns/internal/crd" // registers rec.RR in k8s API registry
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	k8sclient "git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	k8s := k8sclient.NewDefaultK8sClient(cfg.Timeout)

	servers, err := discoverServers(ctx, cfg, k8s)
	if err != nil {
		log.Fatalf("discover servers: %v", err)
	}

	info(fmt.Sprintf("mode=%s servers=%v", cfg.EndpointMode, servers))

	records, err := fetchRecords(ctx, k8s, cfg.Namespace)
	if err != nil {
		log.Fatalf("fetch records: %v", err)
	}

	info(fmt.Sprintf("loaded %d DNSRecord(s)", len(records)))

	// Load TLS cert/config for DoH and DoT.
	var tlsCfg *tls.Config

	if cfg.DoH || cfg.DoT {
		if cfg.TLSInsecure {
			tlsCfg = makeTLSConfig(true, nil, "")

			info("TLS: insecure mode — certificate verification disabled")
		} else {
			cert, err := fetchTLSCert(ctx, k8s, cfg.Namespace, cfg.TLSSecret)
			if err != nil {
				info(fmt.Sprintf("TLS secret %q unavailable — DoH/DoT disabled: %v", cfg.TLSSecret, err))
				cfg.DoH = false
				cfg.DoT = false
			} else {
				sn := certServerName(cert)
				tlsCfg = makeTLSConfig(false, cert, sn)
				info(fmt.Sprintf("TLS: loaded from %q serverName=%q", cfg.TLSSecret, sn))
			}
		}
	}

	// Fetch DNSKEY records for DNSSEC verification.
	var dnskeys []parsedDNSKEY

	zoneName := findZone(records)

	if cfg.DNSSEC {
		if zoneName == "" {
			info("DNSSEC: no SOA record — disabled")

			cfg.DNSSEC = false
		} else if len(servers) > 0 {
			addr := dnsAddr(servers[0], cfg.DNSPort)

			dnskeys, err = fetchDNSKEYs(addr, zoneName, cfg.Timeout)
			if err != nil {
				info(fmt.Sprintf("DNSSEC: fetch DNSKEY failed — disabled: %v", err))

				cfg.DNSSEC = false
			} else if len(dnskeys) == 0 {
				info("DNSSEC: no DNSKEY records — disabled")

				cfg.DNSSEC = false
			} else {
				info(fmt.Sprintf("DNSSEC: %d key(s) for %s", len(dnskeys), zoneName))
			}
		}
	}

	var results []result

	// Zone-level EDNS(0) checks.
	if cfg.EDNS0 && zoneName != "" {
		results = append(results, checkEdns0(cfg, servers, zoneName)...)
	}

	// DoT ALPN negotiation check (RFC 7858 §8.2).
	if cfg.DoT && tlsCfg != nil {
		results = append(results, checkDoTALPN(cfg, servers, tlsCfg)...)
	}

	// Per-record checks.
	for _, obj := range records {
		results = append(
			results,
			checkRecord(ctx, cfg, servers, tlsCfg, dnskeys, obj)...)
	}

	// DNSSEC denial-of-existence (NSEC3) probes.
	if cfg.DNSSEC && zoneName != "" {
		results = append(results, checkNSEC3Probes(cfg, servers, zoneName)...)
	}

	fmt.Println()

	fails := printResults(results)

	fmt.Println()

	if fails == 0 {
		fmt.Printf(
			"%sPASS%s all %d check(s) passed\n",
			green,
			reset,
			len(results),
		)
		os.Exit(0)
	} else {
		fmt.Printf("%sFAIL%s %d/%d check(s) failed\n", red, reset, fails, len(results))
		os.Exit(1)
	}
}

// fetchRecords lists all DNSRecord CRDs in namespace via the k8s API.
func fetchRecords(
	ctx context.Context,
	c k8sclient.K8sClient,
	namespace string,
) ([]*base.Object[rec.RR], error) {
	p, err := api.ParamsFor[rec.RR]()
	if err != nil {
		return nil, err
	}

	p.Namespace = namespace

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	objs, err := k8sclient.QueryApiWithParams[rec.RR](listCtx, c, p)
	if errors.Is(err, k8sclient.ErrNoResults) {
		return nil, nil
	}

	return objs, err
}

// findZone returns the zone apex from the SOA DNSRecord, or "" if none found.
func findZone(records []*base.Object[rec.RR]) string {
	for _, obj := range records {
		if obj.Spec.RRtype == rec.TypeSOA {
			return string(obj.Spec.Name)
		}
	}

	return ""
}
