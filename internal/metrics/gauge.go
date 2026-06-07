// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import "fmt"

type gaugeSeries struct {
	labelValues []string
	value       int64
}

type Gauge struct {
	metricBase
	series map[string]*gaugeSeries // keyed by labelKey(labelValues)
}

// NewGauge creates a gauge with the given name, static labels, and dynamic label keys.
func NewGauge(name string, staticLabels Labels, labelKeys ...string) *Gauge {
	return &Gauge{
		metricBase: metricBase{
			Name:         name,
			StaticLabels: staticLabels,
			LabelKeys:    labelKeys,
		},
		series: make(map[string]*gaugeSeries),
	}
}

func (g *Gauge) Set(v int64, labelValues ...string) {
	if err := validateLabelValues(labelValues); err != nil {
		// Log error but don't panic - metrics should not crash the application
		// Silently drop the observation to prevent corruption
		return
	}

	key := g.labelKey(labelValues)
	g.mut.Lock()

	s, ok := g.series[key]
	if !ok {
		s = &gaugeSeries{labelValues: labelValues}
		g.series[key] = s
	}

	s.value = v
	g.mut.Unlock()
}

// Add adds `d` to value.
func (g *Gauge) Add(d int64, labelValues ...string) {
	if err := validateLabelValues(labelValues); err != nil {
		// Log error but don't panic - metrics should not crash the application
		// Silently drop the observation to prevent corruption
		return
	}

	key := g.labelKey(labelValues)
	g.mut.Lock()

	s, ok := g.series[key]
	if !ok {
		s = &gaugeSeries{labelValues: labelValues}
		g.series[key] = s
	}

	s.value += d
	g.mut.Unlock()
}

func (g *Gauge) Inc(labelValues ...string) { g.Add(1, labelValues...) }
func (g *Gauge) Dec(labelValues ...string) { g.Add(-1, labelValues...) }

// Render emits Prometheus text format (no timestamps).
func (g *Gauge) Render() []string {
	g.mut.Lock()
	defer g.mut.Unlock()

	// No observations yet - render zero with static labels only
	if len(g.series) == 0 {
		return []string{fmt.Sprintf(`%s%s 0`, g.Name, g.StaticLabels.String())}
	}

	lines := make([]string, 0, len(g.series))

	for _, s := range g.series {
		labels := g.labelsFor(s.labelValues)
		lines = append(
			lines,
			fmt.Sprintf(`%s%s %d`, g.Name, labels.String(), s.value),
		)
	}

	return lines
}
