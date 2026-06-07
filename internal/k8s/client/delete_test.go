// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
)

func TestDelete_OK(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				t.Errorf("expected DELETE, got %s", r.Method)
			}

			w.WriteHeader(http.StatusOK)
		}),
	)
	defer srv.Close()

	tc := NewTestClient(srv.Client(), srv.URL)
	p := &api.ApiRequestParams{
		Version:      "v1",
		ResourceType: "dnsrecords",
		Name:         "foo",
	}

	if err := tc.Delete(context.Background(), p); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestDelete_NotFound(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
	)
	defer srv.Close()

	tc := NewTestClient(srv.Client(), srv.URL)
	p := &api.ApiRequestParams{
		Version:      "v1",
		ResourceType: "dnsrecords",
		Name:         "gone",
	}

	if err := tc.Delete(context.Background(), p); err != nil {
		t.Fatalf("expected nil on 404 (idempotent), got: %v", err)
	}
}

func TestDelete_ServerError(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}),
	)
	defer srv.Close()

	tc := NewTestClient(srv.Client(), srv.URL)
	p := &api.ApiRequestParams{
		Version:      "v1",
		ResourceType: "dnsrecords",
		Name:         "bad",
	}

	if err := tc.Delete(context.Background(), p); err == nil {
		t.Fatal("expected error on 500, got nil")
	}
}
