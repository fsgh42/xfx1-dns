// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import "testing"

func TestMergeCtx(t *testing.T) {
	ctx1 := Ctx{"a": 1, "b": 2}
	ctx2 := Ctx{"b": 3, "c": 4}

	merged := mergeCtx([]Ctx{ctx1, ctx2})

	if merged["a"] != 1 {
		t.Errorf("expected a=1, got %v", merged["a"])
	}

	if merged["b"] != 3 {
		t.Errorf("expected b=3 (overwritten), got %v", merged["b"])
	}

	if merged["c"] != 4 {
		t.Errorf("expected c=4, got %v", merged["c"])
	}
}

func TestMergeCtxEmpty(t *testing.T) {
	merged := mergeCtx(nil)
	if merged != nil {
		t.Errorf("expected nil for empty ctx, got %v", merged)
	}

	merged = mergeCtx([]Ctx{})
	if merged != nil {
		t.Errorf("expected nil for empty slice, got %v", merged)
	}
}
