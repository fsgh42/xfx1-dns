// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"fmt"
	"strconv"
)

// histogramSeries holds the per-label-combination data for a histogram.
type histogramSeries struct {
	labelValues []string
	Counts      []uint64
	Sum         float64
	Count       uint64
}

type Histogram struct {
	metricBase
	Buckets []float64                   // bucket upper bounds, shared across all label combinations
	series  map[string]*histogramSeries // keyed by labelKey(labelValues)
}

// NewHistogram creates a histogram with the given name, buckets, static labels, and dynamic label keys.
func NewHistogram(
	name string,
	buckets []float64,
	staticLabels Labels,
	labelKeys ...string,
) *Histogram {
	return &Histogram{
		metricBase: metricBase{
			Name:         name,
			StaticLabels: staticLabels,
			LabelKeys:    labelKeys,
		},
		Buckets: buckets,
		series:  make(map[string]*histogramSeries),
	}
}

func (h *Histogram) Observe(value float64, labelValues ...string) {
	if err := validateLabelValues(labelValues); err != nil {
		// Log error but don't panic - metrics should not crash the application
		// Silently drop the observation to prevent corruption
		return
	}

	key := h.labelKey(labelValues)
	h.mut.Lock()
	defer h.mut.Unlock()

	s, ok := h.series[key]
	if !ok {
		s = &histogramSeries{
			labelValues: labelValues,
			Counts:      make([]uint64, len(h.Buckets)),
		}
		h.series[key] = s
	}

	s.Sum += value
	s.Count++

	// Counts are cumulative: increment all buckets where value <= bound.
	// This matches Prometheus histogram semantics directly.
	for idx, bv := range h.Buckets {
		if value <= bv {
			s.Counts[idx]++
		}
	}
}

func (h *Histogram) Render() []string {
	h.mut.Lock()
	defer h.mut.Unlock()

	// No observations yet - render zeros with static labels only
	if len(h.series) == 0 {
		return h.renderSeries(nil, h.StaticLabels)
	}

	var lines []string

	for _, s := range h.series {
		labels := h.labelsFor(s.labelValues)
		lines = append(lines, h.renderSeries(s, labels)...)
	}

	return lines
}

// renderSeries renders a single histogram series (one label combination).
func (h *Histogram) renderSeries(s *histogramSeries, labels Labels) []string {
	lines := make([]string, 0, len(h.Buckets)+3)

	// Handle nil series (for zero-value render)
	var counts []uint64

	var sum float64

	var count uint64

	if s != nil {
		counts = s.Counts
		sum = s.Sum
		count = s.Count
	} else {
		counts = make([]uint64, len(h.Buckets))
	}

	// Counts are already cumulative (stored that way in Observe),
	// so we can render them directly without accumulation.
	for i, ub := range h.Buckets {
		le := strconv.FormatFloat(ub, 'g', -1, 64)
		lbl := labels.StringWithExtra(Labels{"le": le})
		lines = append(
			lines,
			fmt.Sprintf(`%s_bucket%s %d`, h.Name, lbl, counts[i]),
		)
	}

	// +Inf bucket: total count of all observations
	lines = append(
		lines,
		fmt.Sprintf(
			`%s_bucket%s %d`,
			h.Name,
			labels.StringWithExtra(Labels{"le": "+Inf"}),
			count,
		),
	)
	lines = append(
		lines,
		fmt.Sprintf(`%s_sum%s %g`, h.Name, labels.String(), sum),
	)
	lines = append(
		lines,
		fmt.Sprintf(`%s_count%s %d`, h.Name, labels.String(), count),
	)

	return lines
}
