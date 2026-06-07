// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package master

import (
	"context"
	"fmt"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/dnssec"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

const (
	defaultMaxRRsize = 100_000
)

// rebuild queries all DNSRecord CRDs, builds a new DB, runs sanity checks,
// and if successful swaps the current DB and pushes to slaves.
func (ms *Master) rebuild(
	ctx context.Context,
	params *api.ApiRequestParams,
) error {
	ms.rebuilds.Inc()

	listParams := params.Clone()
	listParams.Watch = false
	listParams.Name = ""

	objects, err := client.QueryApiWithParams[rec.RR](ctx, ms.k8s, listParams)
	if err != nil && err != client.ErrNoResults {
		ms.rebuildErrors.Inc()

		return fmt.Errorf("QueryApiWithParams DNSRecords: %w", err)
	}

	records := make([]*rec.RR, 0, len(objects))

	for _, obj := range objects {
		rr := obj.Spec
		records = append(records, &rr)
	}

	// TTL is hardcoded to 60s — the CRD field is ignored.
	for _, rr := range records {
		rr.TTL = rec.DefaultTTL
	}

	maxRecords := ms.cfg.Master.MaxRecords
	if maxRecords <= 0 {
		maxRecords = defaultMaxRRsize
	}

	if len(records) > maxRecords {
		ms.rebuildErrors.Inc()
		ms.logger.Error(
			fmt.Sprintf(
				"rebuild rejected: %d records exceeds limit of %d",
				len(records),
				maxRecords,
			),
		)

		return fmt.Errorf(
			"record count %d exceeds limit %d",
			len(records),
			maxRecords,
		)
	}

	newDB := db.NewDB(ms.cfg.Global.Zone, records)

	// Set the SOA serial to the current Unix timestamp (seconds) before sanity
	// checks so the non-zero serial check in SanityChecks can verify it.
	// Monotonically increasing across restarts and rebuilds; valid until 2106.
	serial := uint32(time.Now().Unix())

	for _, rr := range newDB.ByType[rec.TypeSOA] {
		if opts, ok := rr.Opts.(*rec.RRoptsSOA); ok {
			opts.Serial = serial
		}
	}

	if err := db.SanityChecks(newDB); err != nil {
		ms.rebuildErrors.Inc()
		ms.logger.Error(fmt.Sprintf("sanity checks failed: %v", err))

		return fmt.Errorf("sanity checks: %w", err)
	}

	// DNSSEC signing pipeline (steps 1–7)
	if len(ms.cfg.DNSSEC.Keys) > 0 {
		signed, err := ms.signDB(ctx, newDB)
		if err != nil {
			ms.rebuildErrors.Inc()
			ms.logger.Error(fmt.Sprintf("DNSSEC signing failed: %v", err))

			return fmt.Errorf("dnssec: %w", err)
		}

		newDB = signed
	}

	for rrtype, rrs := range newDB.ByType {
		ms.rrCount.Set(int64(len(rrs)), string(rrtype))
	}

	ms.mu.Lock()
	ms.current = newDB
	ms.mu.Unlock()

	ms.logger.Info(fmt.Sprintf("rebuilt DB: %d records", len(records)))

	go ms.pushToSlaves(newDB)

	return nil
}

// signDB runs the full DNSSEC signing pipeline on d and returns a new *db.DB
// containing all original records plus DNSKEY, RRSIG, NSEC3, and NSEC3PARAM RRs.
func (ms *Master) signDB(ctx context.Context, d *db.DB) (*db.DB, error) {
	// Step 1: Read key Secrets from k8s
	secrets := make([]dnssec.KeySecret, 0, len(ms.cfg.DNSSEC.Keys))

	for _, keyRef := range ms.cfg.DNSSEC.Keys {
		secretData, err := client.GetSecret(
			ctx,
			ms.k8s,
			ms.namespace,
			keyRef.SecretRef,
		)
		if err != nil {
			return nil, fmt.Errorf("read secret %q: %w", keyRef.SecretRef, err)
		}

		secrets = append(
			secrets,
			dnssec.KeySecret{
				KeyType:    string(secretData["keyType"]),
				PrivateKey: string(secretData["privateKey"]),
			},
		)
	}

	// Step 2: Parse signing keys
	keys, err := dnssec.LoadKeys(secrets, ms.cfg.Global.Zone)
	if err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	var rrSigWindow time.Duration
	if ms.cfg.DNSSEC.RRSIGValidityWindow != "" {
		rrSigWindow, err = time.ParseDuration(ms.cfg.DNSSEC.RRSIGValidityWindow)
		if err != nil {
			return nil, fmt.Errorf("parse rrSigValidityWindow: %w", err)
		}
	}

	// Step 3: Inject DNSKEY RRs into the DB
	records := d.AllRecords()

	for _, sk := range keys {
		rr := &rec.RR{
			Name:   d.Zone,
			RRtype: rec.TypeDNSKEY,
			TTL:    rec.RRttl(sk.DNSKEY.TTL), // always dnskeyTTL (3600)
			Opts: &rec.RRoptsDNSKEY{
				Flags:     sk.DNSKEY.Flags,
				Protocol:  sk.DNSKEY.Protocol,
				Algorithm: sk.DNSKEY.Algorithm,
				PublicKey: sk.DNSKEY.PublicKey,
			},
		}
		records = append(records, rr)
	}

	d = db.NewDB(d.Zone, records)

	// Step 4: Sign all RRsets (DNSKEY by KSK, others by ZSK)
	rrsigs, err := dnssec.SignDB(d, keys, rrSigWindow)
	if err != nil {
		return nil, fmt.Errorf("SignDB: %w", err)
	}

	records = append(records, rrsigs...)

	d = db.NewDB(d.Zone, records)

	// Step 5: Build NSEC3 chain
	chain, nsec3paramRR, err := dnssec.BuildNSEC3Chain(
		d,
		dnssec.DefaultNSEC3PARAMRecord(),
	)
	if err != nil {
		return nil, fmt.Errorf("BuildNSEC3Chain: %w", err)
	}

	nsec3Records := chain.Records
	records = append(records, nsec3Records...)
	records = append(records, nsec3paramRR)

	d = db.NewDB(d.Zone, records)

	// Step 6: Sign the NSEC3 and NSEC3PARAM RRsets with ZSK keys
	var zsks []*dnssec.SigningKey

	for _, k := range keys {
		if k.IsZSK() {
			zsks = append(zsks, k)
		}
	}

	if len(zsks) == 0 {
		zsks = keys // single-key setup
	}

	opts := dnssec.DefaultRRSIGOpts(rrSigWindow)

	for _, nsec3RR := range nsec3Records {
		for _, zsk := range zsks {
			sig, err := dnssec.SignRRset([]*rec.RR{nsec3RR}, zsk, opts)
			if err != nil {
				return nil, fmt.Errorf("sign NSEC3 %s: %w", nsec3RR.Name, err)
			}

			records = append(records, sig.AsRR(nsec3RR.Name, nsec3RR.TTL))
		}
	}

	for _, zsk := range zsks {
		sig, err := dnssec.SignRRset([]*rec.RR{nsec3paramRR}, zsk, opts)
		if err != nil {
			return nil, fmt.Errorf("sign NSEC3PARAM: %w", err)
		}

		records = append(records, sig.AsRR(nsec3paramRR.Name, nsec3paramRR.TTL))
	}

	d = db.NewDB(d.Zone, records)

	// Step 7: Mark DNSSEC enabled
	d.DNSSECEnabled = true

	return d, nil
}
