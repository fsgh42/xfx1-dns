// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package master

import (
	"context"
	"net"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func makeRRObject(name, ip string) *base.Object[rec.RR] {
	rr := rec.NewRR(rec.Domain(name), &rec.RRoptsA{Target: net.ParseIP(ip)})

	return &base.Object[rec.RR]{
		Metadata: base.Metadata{Name: "rr-" + name, Namespace: "test-ns"},
		Spec:     *rr,
	}
}

func rebuildParams(t *testing.T) *api.ApiRequestParams {
	t.Helper()

	p, err := api.ParamsFor[rec.RR]()
	if err != nil {
		t.Fatalf("ParamsFor: %v", err)
	}

	p.Namespace = "test-ns"

	return p
}

// TestRebuild_RecordLimitExceeded verifies that rebuild rejects a record set that
// exceeds MaxRecords, increments the error metric, and returns an error.
func TestRebuild_RecordLimitExceeded(t *testing.T) {
	cfg := crd.DNSConfigSpec{}
	cfg.Global.Zone = rec.Domain("example.com.")
	cfg.Master.MaxRecords = 2 // limit to 2; we will send 3

	k8s := &client.MockClient{
		ListResult: client.MockObjects(
			makeRRObject("a.example.com.", "1.1.1.1"),
			makeRRObject("b.example.com.", "2.2.2.2"),
			makeRRObject("c.example.com.", "3.3.3.3"),
		),
	}
	ms := New(cfg, "test-ns", k8s, log.New[log.Null, log.Logfmt]("test"))

	if err := ms.rebuild(context.Background(), rebuildParams(t)); err == nil {
		t.Error("expected error when record count exceeds limit, got nil")
	}

	// Error metric must have been incremented.
	lines := ms.rebuildErrors.Render()
	if len(lines) == 0 || lines[0] != "master_db_rebuild_errors_total 1" {
		t.Errorf(
			"rebuildErrors metric: got %v, want [master_db_rebuild_errors_total 1]",
			lines,
		)
	}

	// Current DB must remain nil (no successful rebuild).
	ms.mu.RLock()
	current := ms.current
	ms.mu.RUnlock()

	if current != nil {
		t.Error("current DB should still be nil after rejected rebuild")
	}
}

// TestRebuild_WithinLimit verifies that rebuild succeeds when record count is
// within the configured limit. Uses a small zone with a valid SOA.
func TestRebuild_WithinLimit(t *testing.T) {
	cfg := crd.DNSConfigSpec{}
	cfg.Global.Zone = rec.Domain("example.com.")
	cfg.Master.MaxRecords = 10

	soa := rec.NewRR(rec.Domain("example.com."), &rec.RRoptsSOA{
		Mname: "ns1.example.com.", Rname: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
	})
	ns := rec.NewRR(
		rec.Domain("example.com."),
		&rec.RRoptsNS{Ns: "ns1.example.com."},
	)
	ns1 := rec.NewRR(
		rec.Domain("ns1.example.com."),
		&rec.RRoptsA{Target: net.ParseIP("1.2.3.4")},
	)

	k8s := &client.MockClient{
		ListResult: client.MockObjects(
			&base.Object[rec.RR]{
				Metadata: base.Metadata{Name: "soa", Namespace: "test-ns"},
				Spec:     *soa,
			},
			&base.Object[rec.RR]{
				Metadata: base.Metadata{Name: "ns", Namespace: "test-ns"},
				Spec:     *ns,
			},
			&base.Object[rec.RR]{
				Metadata: base.Metadata{Name: "ns1", Namespace: "test-ns"},
				Spec:     *ns1,
			},
		),
	}
	ms := New(cfg, "test-ns", k8s, log.New[log.Null, log.Logfmt]("test"))

	if err := ms.rebuild(context.Background(), rebuildParams(t)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ms.mu.RLock()
	current := ms.current
	ms.mu.RUnlock()

	if current == nil {
		t.Fatal("current DB is nil after successful rebuild")
	}

	if current.RRCount() != 3 {
		t.Errorf("RRCount = %d, want 3", current.RRCount())
	}
}

// TestRebuild_DefaultLimit verifies that MaxRecords=0 uses the 100k default
// (not zero, which would reject everything).
func TestRebuild_DefaultLimit(t *testing.T) {
	cfg := crd.DNSConfigSpec{}
	cfg.Global.Zone = rec.Domain("example.com.")
	// MaxRecords intentionally left at 0 — should default to 100k.

	soa := rec.NewRR(rec.Domain("example.com."), &rec.RRoptsSOA{
		Mname: "ns1.example.com.", Rname: "hostmaster.example.com.",
		Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minimum: 300,
	})
	ns := rec.NewRR(
		rec.Domain("example.com."),
		&rec.RRoptsNS{Ns: "ns1.example.com."},
	)
	ns1 := rec.NewRR(
		rec.Domain("ns1.example.com."),
		&rec.RRoptsA{Target: net.ParseIP("1.2.3.4")},
	)

	k8s := &client.MockClient{
		ListResult: client.MockObjects(
			&base.Object[rec.RR]{
				Metadata: base.Metadata{Name: "soa", Namespace: "test-ns"},
				Spec:     *soa,
			},
			&base.Object[rec.RR]{
				Metadata: base.Metadata{Name: "ns", Namespace: "test-ns"},
				Spec:     *ns,
			},
			&base.Object[rec.RR]{
				Metadata: base.Metadata{Name: "ns1", Namespace: "test-ns"},
				Spec:     *ns1,
			},
		),
	}
	ms := New(cfg, "test-ns", k8s, log.New[log.Null, log.Logfmt]("test"))

	if err := ms.rebuild(context.Background(), rebuildParams(t)); err != nil {
		t.Errorf("unexpected error with default limit: %v", err)
	}
}
