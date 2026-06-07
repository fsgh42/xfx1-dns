// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"errors"
	"fmt"
	"sync"
)

type (
	Metrics struct {
		mut     sync.Mutex
		metrics map[string]Metric
	}
)

var (
	ErrMetricExists    = errors.New("metric already registered")
	ErrMetricNotExists = errors.New("metric not registered")
)

func NewMetrics() *Metrics {
	return &Metrics{
		mut:     sync.Mutex{},
		metrics: map[string]Metric{},
	}
}

func (m *Metrics) Register(name string, mtr Metric) error {
	m.mut.Lock()
	defer m.mut.Unlock()

	if _, found := m.metrics[name]; found {
		return fmt.Errorf("%w: %s", ErrMetricExists, name)
	}

	m.metrics[name] = mtr

	return nil
}

func (m *Metrics) Remove(name string) error {
	m.mut.Lock()
	defer m.mut.Unlock()

	if _, found := m.metrics[name]; !found {
		return fmt.Errorf("%w: %s", ErrMetricNotExists, name)
	}

	delete(m.metrics, name)

	return nil
}

// GetMetric returns a metric by name.
// Returns nil if no metric for that name can be found.
func (m *Metrics) GetMetric(name string) Metric {
	m.mut.Lock()
	defer m.mut.Unlock()

	metric, found := m.metrics[name]
	if !found {
		return nil
	}

	return metric
}

func (m *Metrics) RenderAll() []string {
	m.mut.Lock()
	defer m.mut.Unlock()

	res := []string{}

	for _, mtr := range m.metrics {
		res = append(res, mtr.Render()...)
	}

	return res
}
