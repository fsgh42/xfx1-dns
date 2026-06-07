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

func TestQueryApi_Paginated(t *testing.T) {
	// server returns two pages: first with metadata.continue token, second without
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			cont := q.Get("continue")

			if cont == "" {
				// first page
				resp := map[string]any{
					"metadata": map[string]any{"continue": "tok"},
					"items":    []map[string]any{{"foo": "1"}},
				}
				_ = json.NewEncoder(w).Encode(resp)

				return
			}

			// second page
			resp := map[string]any{
				"items": []map[string]any{{"foo": "2"}},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}),
	)
	defer srv.Close()

	tc := NewTestClient(srv.Client(), srv.URL)

	p := &api.ApiRequestParams{Version: "v1", ResourceType: "nodes"}

	data, err := tc.QueryApi(context.Background(), p)
	if err != nil {
		t.Fatalf("QueryApi error: %v", err)
	}

	if len(data) != 2 {
		t.Fatalf("expected 2 items, got %d", len(data))
	}

	want := []string{"1", "2"}

	for i, raw := range data {
		var item map[string]string

		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatalf("item %d: unmarshal: %v", i, err)
		}

		if item["foo"] != want[i] {
			t.Errorf("item %d: foo=%q, want %q", i, item["foo"], want[i])
		}
	}
}
