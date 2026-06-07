// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"maps"
	"slices"
)

type (
	// Ctx is a map of contextual key-value pairs for structured logging
	Ctx map[string]any
)

func (c Ctx) sortedKeys() []string {
	return slices.Sorted(maps.Keys(c))
}

func mergeCtx(ctxs []Ctx) Ctx {
	if len(ctxs) == 0 {
		return nil
	}

	merged := make(Ctx)
	for _, c := range ctxs {
		maps.Copy(merged, c)
	}

	return merged
}
