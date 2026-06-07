// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"context"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func newTestHandler(k8s *client.MockClient) *Handler {
	m := metrics.NewMetrics()
	updatesTotal := metrics.NewCounter(
		"rfc2136_updates_total",
		nil,
		"operation",
	)
	updateErrors := metrics.NewCounter(
		"rfc2136_update_errors_total",
		nil,
		"reason",
	)
	crNameOverflows := metrics.NewCounter("rfc2136_cr_name_overflow_total", nil)
	_ = m.Register("rfc2136_updates_total", updatesTotal)
	_ = m.Register("rfc2136_update_errors_total", updateErrors)
	_ = m.Register("rfc2136_cr_name_overflow_total", crNameOverflows)

	return NewHandler(
		"test-ns",
		"example.com.",
		k8s,
		log.NewDefaultLogger("test"),
		updatesTotal,
		updateErrors,
		crNameOverflows,
	)
}

func makeUpdateMsg(updates []*RR) *Message {
	zone := &RR{Name: "example.com.", Type: 6, Class: ClassIN}

	return &Message{
		Header:  Header{Opcode: OpcodeUpdate},
		Zone:    zone,
		Updates: updates,
	}
}

// TestHandleUpdate_Add verifies that an ADD operation calls ApplyOrUpdate.
func TestHandleUpdate_Add(t *testing.T) {
	k8s := &client.MockClient{}
	h := newTestHandler(k8s)

	rr := &RR{
		Name:     "host.example.com.",
		Type:     1, // A
		Class:    ClassIN,
		TTL:      60,
		Rdlength: 4,
		Rdata:    []byte{1, 2, 3, 4},
	}
	msg := makeUpdateMsg([]*RR{rr})

	rcode := h.HandleUpdate(context.Background(), msg)
	if rcode != RcodeNoError {
		t.Errorf("expected NOERROR, got %d", rcode)
	}

	if len(k8s.ApplyCalls) != 1 {
		t.Fatalf("expected 1 apply call, got %d", len(k8s.ApplyCalls))
	}
}

// TestHandleUpdate_AddIdempotent verifies that the same ADD twice produces the same CR name.
func TestHandleUpdate_AddIdempotent(t *testing.T) {
	k8s := &client.MockClient{}
	h := newTestHandler(k8s)

	rr := &RR{
		Name: "host.example.com.", Type: 1, Class: ClassIN, TTL: 60,
		Rdlength: 4, Rdata: []byte{1, 2, 3, 4},
	}
	msg := makeUpdateMsg([]*RR{rr})

	h.HandleUpdate(context.Background(), msg)
	h.HandleUpdate(context.Background(), msg)

	if len(k8s.ApplyCalls) != 2 {
		t.Fatalf("expected 2 apply calls, got %d", len(k8s.ApplyCalls))
	}

	name1 := k8s.ApplyCalls[0].Params.Name
	name2 := k8s.ApplyCalls[1].Params.Name

	if name1 != name2 {
		t.Errorf("idempotency broken: %s != %s", name1, name2)
	}
}

// TestHandleUpdate_DeleteRR verifies that a NONE/0 operation calls Delete.
func TestHandleUpdate_DeleteRR(t *testing.T) {
	k8s := &client.MockClient{}
	h := newTestHandler(k8s)

	rr := &RR{
		Name:     "host.example.com.",
		Type:     1, // A
		Class:    ClassNONE,
		TTL:      0,
		Rdlength: 4,
		Rdata:    []byte{1, 2, 3, 4},
	}
	msg := makeUpdateMsg([]*RR{rr})

	rcode := h.HandleUpdate(context.Background(), msg)
	if rcode != RcodeNoError {
		t.Errorf("expected NOERROR, got %d", rcode)
	}

	if len(k8s.DeleteCalls) != 1 {
		t.Fatalf("expected 1 delete call, got %d", len(k8s.DeleteCalls))
	}
}

// TestHandleUpdate_DeleteRRset verifies that ANY/0/nonzero-type operation lists and deletes matching CRs.
func TestHandleUpdate_DeleteRRset(t *testing.T) {
	matching := &base.Object[rec.RR]{
		Metadata: base.Metadata{
			Name: "rfc2136-a-host-example-com-aabbccdd", Namespace: "test-ns",
			Labels: base.Labels{sourceLabel: sourceLabelValue},
		},
		Spec: rec.RR{Name: "host.example.com.", RRtype: rec.TypeA},
	}
	k8s := &client.MockClient{ListResult: client.MockObjects(matching)}
	h := newTestHandler(k8s)

	rr := &RR{
		Name:     "host.example.com.",
		Type:     1,
		Class:    ClassANY,
		TTL:      0,
		Rdlength: 0,
	}

	rcode := h.HandleUpdate(context.Background(), makeUpdateMsg([]*RR{rr}))
	if rcode != RcodeNoError {
		t.Errorf("expected NOERROR, got %d", rcode)
	}

	if len(k8s.DeleteCalls) != 1 {
		t.Fatalf("expected 1 delete call, got %d", len(k8s.DeleteCalls))
	}
}

// TestHandleUpdate_ZoneMismatch verifies NOTZONE is returned for wrong zone.
func TestHandleUpdate_ZoneMismatch(t *testing.T) {
	k8s := &client.MockClient{}
	h := newTestHandler(k8s)

	msg := &Message{
		Header: Header{Opcode: OpcodeUpdate},
		Zone:   &RR{Name: "other.com.", Type: 6, Class: ClassIN},
	}

	rcode := h.HandleUpdate(context.Background(), msg)
	if rcode != RcodeNotZone {
		t.Errorf("expected NOTZONE(%d), got %d", RcodeNotZone, rcode)
	}
}

// TestHandleUpdate_K8sError verifies SERVFAIL on k8s API error.
func TestHandleUpdate_K8sError(t *testing.T) {
	k8s := &client.MockClient{ApplyErr: errFakeK8s}
	h := newTestHandler(k8s)

	rr := &RR{
		Name: "host.example.com.", Type: 1, Class: ClassIN, TTL: 60,
		Rdlength: 4, Rdata: []byte{1, 2, 3, 4},
	}

	rcode := h.HandleUpdate(context.Background(), makeUpdateMsg([]*RR{rr}))
	if rcode != RcodeServFail {
		t.Errorf("expected SERVFAIL, got %d", rcode)
	}
}

// TestHandleUpdate_CRNameOverflow verifies SERVFAIL when CR name exceeds 253 chars.
func TestHandleUpdate_CRNameOverflow(t *testing.T) {
	k8s := &client.MockClient{}
	h := newTestHandler(k8s)

	longLabel := make([]byte, 240)
	for i := range longLabel {
		longLabel[i] = 'a'
	}

	rr := &RR{
		Name: string(
			longLabel,
		) + ".example.com.", Type: 1, Class: ClassIN, TTL: 60,
		Rdlength: 4, Rdata: []byte{1, 2, 3, 4},
	}

	rcode := h.HandleUpdate(context.Background(), makeUpdateMsg([]*RR{rr}))
	if rcode != RcodeServFail {
		t.Errorf("expected SERVFAIL on overflow, got %d", rcode)
	}
}

// TestHandleUpdate_Prerequisites verifies NOTIMP is returned when prerequisites are present.
func TestHandleUpdate_Prerequisites(t *testing.T) {
	k8s := &client.MockClient{}
	h := newTestHandler(k8s)

	msg := &Message{
		Header: Header{Opcode: OpcodeUpdate},
		Zone:   &RR{Name: "example.com.", Type: 6, Class: ClassIN},
		Prerequisites: []*RR{
			{Name: "host.example.com.", Type: 1, Class: ClassANY},
		},
	}

	rcode := h.HandleUpdate(context.Background(), msg)
	if rcode != RcodeNotimp {
		t.Errorf("expected NOTIMP(%d), got %d", RcodeNotimp, rcode)
	}
}

// TestHandleUpdate_DeleteAllAtName verifies that ANY/0/type=255 deletes all CRs at the name.
func TestHandleUpdate_DeleteAllAtName(t *testing.T) {
	matchingA := &base.Object[rec.RR]{
		Metadata: base.Metadata{
			Name: "rfc2136-a-host-example-com-aabbccdd", Namespace: "test-ns",
			Labels: base.Labels{sourceLabel: sourceLabelValue},
		},
		Spec: rec.RR{Name: "host.example.com.", RRtype: rec.TypeA},
	}
	matchingTXT := &base.Object[rec.RR]{
		Metadata: base.Metadata{
			Name: "rfc2136-txt-host-example-com-11223344", Namespace: "test-ns",
			Labels: base.Labels{sourceLabel: sourceLabelValue},
		},
		Spec: rec.RR{Name: "host.example.com.", RRtype: rec.TypeTXT},
	}
	other := &base.Object[rec.RR]{
		Metadata: base.Metadata{
			Name: "rfc2136-a-other-example-com-deadbeef", Namespace: "test-ns",
			Labels: base.Labels{sourceLabel: sourceLabelValue},
		},
		Spec: rec.RR{Name: "other.example.com.", RRtype: rec.TypeA},
	}
	k8s := &client.MockClient{
		ListResult: client.MockObjects(matchingA, matchingTXT, other),
	}
	h := newTestHandler(k8s)

	rr := &RR{
		Name:     "host.example.com.",
		Type:     255,
		Class:    ClassANY,
		TTL:      0,
		Rdlength: 0,
	}

	rcode := h.HandleUpdate(context.Background(), makeUpdateMsg([]*RR{rr}))
	if rcode != RcodeNoError {
		t.Errorf("expected NOERROR, got %d", rcode)
	}

	if len(k8s.DeleteCalls) != 2 {
		t.Fatalf(
			"expected 2 delete calls (both matching CRs), got %d",
			len(k8s.DeleteCalls),
		)
	}
}

// TestHandleUpdate_DeleteRRset_ListError verifies SERVFAIL when k8s list fails during deleteRRset.
func TestHandleUpdate_DeleteRRset_ListError(t *testing.T) {
	k8s := &client.MockClient{ListErr: errFakeK8s}
	h := newTestHandler(k8s)

	rr := &RR{
		Name:     "host.example.com.",
		Type:     1,
		Class:    ClassANY,
		TTL:      0,
		Rdlength: 0,
	}

	rcode := h.HandleUpdate(context.Background(), makeUpdateMsg([]*RR{rr}))
	if rcode != RcodeServFail {
		t.Errorf("expected SERVFAIL, got %d", rcode)
	}
}

// TestHandleUpdate_DeleteRR_K8sError verifies SERVFAIL when k8s delete fails during deleteRR.
func TestHandleUpdate_DeleteRR_K8sError(t *testing.T) {
	k8s := &client.MockClient{DeleteErr: errFakeK8s}
	h := newTestHandler(k8s)

	rr := &RR{
		Name: "host.example.com.", Type: 1, Class: ClassNONE, TTL: 0,
		Rdlength: 4, Rdata: []byte{1, 2, 3, 4},
	}

	rcode := h.HandleUpdate(context.Background(), makeUpdateMsg([]*RR{rr}))
	if rcode != RcodeServFail {
		t.Errorf("expected SERVFAIL, got %d", rcode)
	}
}

// errFakeK8s is a sentinel error for testing.
type fakeK8sError struct{}

func (e fakeK8sError) Error() string { return "fake k8s error" }

var errFakeK8s = fakeK8sError{}
