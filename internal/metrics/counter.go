// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import "fmt"

type counterSeries struct {
	labelValues []string
	count       uint64
}

type Counter struct {
	metricBase
	series map[string]*counterSeries // keyed by labelKey(labelValues)
}

// NewCounter creates a counter with the given name, static labels, and dynamic label keys.
func NewCounter(
	name string,
	staticLabels Labels,
	labelKeys ...string,
) *Counter {
	return &Counter{
		metricBase: metricBase{
			Name:         name,
			StaticLabels: staticLabels,
			LabelKeys:    labelKeys,
		},
		series: make(map[string]*counterSeries),
	}
}

func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

func (c *Counter) Add(n uint64, labelValues ...string) {
	if err := validateLabelValues(labelValues); err != nil {
		// Log error but don't panic - metrics should not crash the application
		// Silently drop the observation to prevent corruption
		return
	}

	key := c.labelKey(labelValues)
	c.mut.Lock()

	s, ok := c.series[key]
	if !ok {
		s = &counterSeries{labelValues: labelValues}
		c.series[key] = s
	}

	s.count += n
	c.mut.Unlock()
}

func (c *Counter) Render() []string {
	c.mut.Lock()
	defer c.mut.Unlock()

	// No observations yet - render zero with static labels only
	if len(c.series) == 0 {
		return []string{fmt.Sprintf(`%s%s 0`, c.Name, c.StaticLabels.String())}
	}

	lines := make([]string, 0, len(c.series))

	for _, s := range c.series {
		labels := c.labelsFor(s.labelValues)
		lines = append(
			lines,
			fmt.Sprintf(`%s%s %d`, c.Name, labels.String(), s.count),
		)
	}

	return lines
}
