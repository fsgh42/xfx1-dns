// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

type (
	MetricsProvider interface {
		// RenderAll renders and returns all metrics
		// of implementing data types.
		RenderAll() []string
	}
)
