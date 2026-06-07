// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"fmt"
	"strings"
	"sync"
)

type (
	Metric interface {
		// Render emits Prometheus text format (no timestamps)
		Render() []string
	}
	// metricBase provides shared functionality for all metric types.
	// It handles static labels (fixed at creation) and dynamic label keys
	// (values provided at observation time).
	metricBase struct {
		mut          sync.Mutex
		Name         string
		StaticLabels Labels
		LabelKeys    []string // dynamic label keys, e.g., ["command", "status"]
	}
)

// validateLabelValues checks that label values don't contain null bytes,
// which are used internally as separators and would cause metrics corruption.
func validateLabelValues(labelValues []string) error {
	for i, v := range labelValues {
		if strings.Contains(v, "\x00") {
			return fmt.Errorf(
				"label value at index %d contains null byte (\\x00)",
				i,
			)
		}
	}

	return nil
}

// labelKey creates a map key from dynamic label values.
// Values are joined with null byte separator (not valid in label values).
// Callers must validate label values with validateLabelValues before calling this.
func (m *metricBase) labelKey(labelValues []string) string {
	return strings.Join(labelValues, "\x00")
}

// labelsFor merges static labels with dynamic label key-value pairs.
// Dynamic labels override static labels with the same key.
func (m *metricBase) labelsFor(labelValues []string) Labels {
	result := make(Labels, len(m.StaticLabels)+len(labelValues))
	for k, v := range m.StaticLabels {
		result[k] = v
	}

	for i, k := range m.LabelKeys {
		if i < len(labelValues) {
			result[k] = labelValues[i]
		}
	}

	return result
}
