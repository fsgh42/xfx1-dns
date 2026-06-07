// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"encoding/json"
	"strings"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func TestIntegration_SignAndProve(t *testing.T) {
	zone := testZone()
	ksk, zsk := loadTestKeys(t)

	// Step 1: Build initial DB
	records := []*rec.RR{makeSOA(zone), makeNS(zone), makeA("www.xfx1.de.")}
	d := db.NewDB(zone, records)

	// Step 2: Load keys (already done via loadTestKeys)

	// Step 3: Inject DNSKEY RRs
	for _, sk := range []*SigningKey{ksk, zsk} {
		records = append(records, &rec.RR{
			Name:   zone,
			RRtype: rec.TypeDNSKEY,
			TTL:    rec.RRttl(sk.DNSKEY.TTL),
			Opts: &rec.RRoptsDNSKEY{
				Flags:     sk.DNSKEY.Flags,
				Protocol:  sk.DNSKEY.Protocol,
				Algorithm: sk.DNSKEY.Algorithm,
				PublicKey: sk.DNSKEY.PublicKey,
			},
		})
	}

	d = db.NewDB(zone, records)

	// Step 4: SignDB
	rrsigs, err := SignDB(d, []*SigningKey{ksk, zsk}, 0)
	if err != nil {
		t.Fatalf("SignDB: %v", err)
	}

	records = append(records, rrsigs...)
	d = db.NewDB(zone, records)

	// Step 5: BuildNSEC3Chain
	params := DefaultNSEC3PARAMRecord()

	chain, nsec3paramRR, err := BuildNSEC3Chain(d, params)
	if err != nil {
		t.Fatalf("BuildNSEC3Chain: %v", err)
	}

	nsec3Records := chain.Records
	records = append(records, nsec3Records...)
	records = append(records, nsec3paramRR)
	d = db.NewDB(zone, records)

	// Step 6: Sign NSEC3/NSEC3PARAM RRsets
	zsks := []*SigningKey{zsk}
	for _, nsec3RR := range nsec3Records {
		for _, sk := range zsks {
			sig, err := SignRRset([]*rec.RR{nsec3RR}, sk, DefaultRRSIGOpts(0))
			if err != nil {
				t.Fatalf("sign NSEC3: %v", err)
			}

			records = append(records, sig.AsRR(nsec3RR.Name, nsec3RR.TTL))
		}
	}

	for _, sk := range zsks {
		sig, err := SignRRset([]*rec.RR{nsec3paramRR}, sk, DefaultRRSIGOpts(0))
		if err != nil {
			t.Fatalf("sign NSEC3PARAM: %v", err)
		}

		records = append(records, sig.AsRR(nsec3paramRR.Name, nsec3paramRR.TTL))
	}

	d = db.NewDB(zone, records)

	// Step 7: Set DNSSECEnabled
	d.DNSSECEnabled = true

	// Step 8: RebuildNSEC3Chain from final DB
	chain2, err := RebuildNSEC3Chain(d)
	if err != nil {
		t.Fatalf("RebuildNSEC3Chain: %v", err)
	}

	// Step 9: ClosestEncloserProof
	queried := mustDomain("nxdomain.xfx1.de.")

	proof, err := chain2.ClosestEncloserProof(queried, zone, d)
	if err != nil {
		t.Fatalf("ClosestEncloserProof: %v", err)
	}

	// Step 10: Assert all three proof records present and are NSEC3
	if proof.ClosestEncloser == nil || proof.NextCloser == nil ||
		proof.WildcardAtCE == nil {
		t.Fatal("proof records missing")
	}

	for _, rr := range []*rec.RR{proof.ClosestEncloser, proof.NextCloser, proof.WildcardAtCE} {
		if rr.RRtype != rec.TypeNSEC3 {
			t.Errorf("proof record is %s, want NSEC3", rr.RRtype)
		}
		// Owner name should end with the zone
		if !strings.HasSuffix(string(rr.Name), string(zone)) {
			t.Errorf(
				"proof record owner %s does not end with zone %s",
				rr.Name,
				zone,
			)
		}
	}

	// Step 11: Find RRSIGs for each proof record in the DB
	for _, proofRR := range []*rec.RR{proof.ClosestEncloser, proof.NextCloser, proof.WildcardAtCE} {
		rrsigRRs := d.LookupByType(proofRR.Name, rec.TypeRRSIG)
		found := false

		for _, rr := range rrsigRRs {
			opts := rr.Opts.(*rec.RRoptsRRSIG)
			if opts.TypeCovered == rec.RRtypeToWire[rec.TypeNSEC3] {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("no RRSIG for NSEC3 at %s", proofRR.Name)
		}
	}

	// Step 12: JSON round-trip
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal DB: %v", err)
	}

	var d2 db.DB
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatalf("unmarshal DB: %v", err)
	}

	if !d2.DNSSECEnabled {
		t.Error("DNSSECEnabled not preserved through JSON round-trip")
	}

	chain3, err := RebuildNSEC3Chain(&d2)
	if err != nil {
		t.Fatalf("RebuildNSEC3Chain after JSON round-trip: %v", err)
	}

	if len(chain3.Records) != len(chain2.Records) {
		t.Errorf(
			"chain length after round-trip: got %d, want %d",
			len(chain3.Records),
			len(chain2.Records),
		)
	}
}
