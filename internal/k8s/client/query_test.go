// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
)

type DummySpec struct {
	Foo string `json:"foo"`
}

func TestQueryApiWithParams_NoResults(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// return an empty items list
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
		}),
	)
	defer srv.Close()

	tc := NewTestClient(srv.Client(), srv.URL)

	p := &api.ApiRequestParams{Version: "v1", ResourceType: "nodes"}

	res, err := QueryApiWithParams[DummySpec](
		context.Background(),
		tc.Client,
		p,
	)
	if err == nil {
		t.Fatalf("expected ErrNoResults, got nil and res: %#v", res)
	}
}

func TestQueryApiWithParams_Success(t *testing.T) {
	// prepare two objects
	obj1 := map[string]any{
		"apiVersion": "v1",
		"kind":       "Test",
		"metadata":   map[string]any{"name": "a"},
		"spec":       map[string]any{"foo": "1"},
	}
	obj2 := map[string]any{
		"apiVersion": "v1",
		"kind":       "Test",
		"metadata":   map[string]any{"name": "b"},
		"spec":       map[string]any{"foo": "2"},
	}

	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).
				Encode(map[string]any{"items": []any{obj1, obj2}})
		}),
	)
	defer srv.Close()

	tc := NewTestClient(srv.Client(), srv.URL)
	p := &api.ApiRequestParams{Version: "v1", ResourceType: "nodes"}

	res, err := QueryApiWithParams[DummySpec](
		context.Background(),
		tc.Client,
		p,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res))
	}

	if res[0].Spec.Foo != "1" || res[1].Spec.Foo != "2" {
		t.Fatalf("unexpected spec values: %#v", res)
	}
}

func TestQueryApiWithParams_UnmarshalError(t *testing.T) {
	// server returns items with invalid object that will not unmarshal into Object[DummySpec]
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// items array containing a string (not an object) will cause unmarshal to fail
			_ = json.NewEncoder(w).
				Encode(map[string]any{"items": []any{"not-an-object"}})
		}),
	)
	defer srv.Close()

	tc := NewTestClient(srv.Client(), srv.URL)
	p := &api.ApiRequestParams{Version: "v1", ResourceType: "nodes"}

	_, err := QueryApiWithParams[DummySpec](context.Background(), tc.Client, p)
	if err == nil {
		t.Fatalf("expected unmarshal error, got nil")
	}
}
