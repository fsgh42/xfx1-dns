// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"errors"
	"sync"
	"testing"
)

func TestMetrics_Register(t *testing.T) {
	t.Run("register new metric", func(t *testing.T) {
		m := NewMetrics()
		g := NewGauge("gauge1", Labels{"label1": "value1"})

		if err := m.Register(g.Name, g); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		actual := m.GetMetric(g.Name)
		if actual == nil {
			t.Fatal("no metric returned")
		}

		if actual != g {
			t.Fatal("wrong metric returned")
		}
	})

	t.Run("register duplicate metric", func(t *testing.T) {
		m := NewMetrics()
		g := NewGauge("gauge1", nil)

		if err := m.Register(g.Name, g); err != nil {
			t.Fatalf("first register failed: %v", err)
		}

		err := m.Register(g.Name, g)
		if err == nil {
			t.Fatal("expected error for duplicate registration")
		}

		if !errors.Is(err, ErrMetricExists) {
			t.Fatalf("expected ErrMetricExists, got: %v", err)
		}
	})
}

func TestMetrics_Remove(t *testing.T) {
	t.Run("remove existing metric", func(t *testing.T) {
		m := NewMetrics()
		g := NewGauge("gauge1", nil)

		if err := m.Register(g.Name, g); err != nil {
			t.Fatalf("register failed: %v", err)
		}

		if err := m.Remove(g.Name); err != nil {
			t.Fatalf("remove failed: %v", err)
		}

		if m.GetMetric(g.Name) != nil {
			t.Fatal("metric should be removed")
		}
	})

	t.Run("remove non-existent metric", func(t *testing.T) {
		m := NewMetrics()

		err := m.Remove("does_not_exist")
		if err == nil {
			t.Fatal("expected error for non-existent metric")
		}

		if !errors.Is(err, ErrMetricNotExists) {
			t.Fatalf("expected ErrMetricNotExists, got: %v", err)
		}
	})
}

func TestMetrics_GetMetric(t *testing.T) {
	t.Run("get existing metric", func(t *testing.T) {
		m := NewMetrics()
		g := NewGauge("gauge1", nil)

		if err := m.Register(g.Name, g); err != nil {
			t.Fatalf("register failed: %v", err)
		}

		actual := m.GetMetric(g.Name)
		if actual != g {
			t.Fatalf("expected %v, got %v", g, actual)
		}
	})

	t.Run("get non-existent metric", func(t *testing.T) {
		m := NewMetrics()

		actual := m.GetMetric("does_not_exist")
		if actual != nil {
			t.Fatalf("expected nil, got %v", actual)
		}
	})
}

func TestMetrics_RenderAll(t *testing.T) {
	t.Run("render empty metrics", func(t *testing.T) {
		m := NewMetrics()

		lines := m.RenderAll()
		if len(lines) != 0 {
			t.Fatalf("expected 0 lines, got %d", len(lines))
		}
	})

	t.Run("render single metric", func(t *testing.T) {
		m := NewMetrics()
		g := NewGauge("gauge1", nil)
		g.Set(42)

		if err := m.Register(g.Name, g); err != nil {
			t.Fatalf("register failed: %v", err)
		}

		lines := m.RenderAll()
		if len(lines) != 1 {
			t.Fatalf("expected 1 line, got %d", len(lines))
		}

		if lines[0] != "gauge1 42" {
			t.Fatalf("expected 'gauge1 42', got %q", lines[0])
		}
	})

	t.Run("render multiple metrics", func(t *testing.T) {
		m := NewMetrics()
		g := NewGauge("gauge1", nil)
		g.Set(10)

		c := NewCounter("counter1", nil)
		c.Add(20)

		if err := m.Register(g.Name, g); err != nil {
			t.Fatalf("register gauge failed: %v", err)
		}

		if err := m.Register(c.Name, c); err != nil {
			t.Fatalf("register counter failed: %v", err)
		}

		lines := m.RenderAll()
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines, got %d", len(lines))
		}
	})
}

func TestMetrics_Concurrent(t *testing.T) {
	m := NewMetrics()

	const goroutines = 10

	const opsPerGoroutine = 100

	var wg sync.WaitGroup

	wg.Add(goroutines * 3)

	// Concurrent registers
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()

			for j := range opsPerGoroutine {
				g := NewGauge("gauge", nil)
				_ = m.Register(g.Name, g)
				_ = m.Remove(g.Name)
				_ = j
			}
		}(i)
	}

	// Concurrent gets
	for range goroutines {
		go func() {
			defer wg.Done()

			for range opsPerGoroutine {
				_ = m.GetMetric("gauge")
			}
		}()
	}

	// Concurrent renders
	for range goroutines {
		go func() {
			defer wg.Done()

			for range opsPerGoroutine {
				_ = m.RenderAll()
			}
		}()
	}

	wg.Wait()
}
