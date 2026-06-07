// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"math"
	"strconv"
	"sync"
	"testing"
)

func TestGauge_Set(t *testing.T) {
	tests := []struct {
		name  string
		value int64
	}{
		{"positive value", 42},
		{"zero value", 0},
		{"negative value", -100},
		{"large positive", math.MaxInt64},
		{"large negative", math.MinInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGauge("test_gauge", nil)
			g.Set(tt.value)

			lines := g.Render()
			if len(lines) != 1 {
				t.Fatalf("expected 1 line, got %d", len(lines))
			}

			want := "test_gauge " + itoa(tt.value)
			if lines[0] != want {
				t.Errorf("got %q, want %q", lines[0], want)
			}
		})
	}
}

func TestGauge_Add(t *testing.T) {
	tests := []struct {
		name     string
		initial  int64
		add      int64
		expected int64
	}{
		{"add positive", 10, 5, 15},
		{"add negative", 10, -3, 7},
		{"add zero", 10, 0, 10},
		{"add to zero", 0, 42, 42},
		{"add to negative", -5, 3, -2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGauge("test_gauge", nil)
			g.Set(tt.initial)
			g.Add(tt.add)

			lines := g.Render()
			want := "test_gauge " + itoa(tt.expected)

			if lines[0] != want {
				t.Errorf("got %q, want %q", lines[0], want)
			}
		})
	}
}

func TestGauge_IncDec(t *testing.T) {
	g := NewGauge("test_gauge", nil)

	g.Inc()

	if lines := g.Render(); lines[0] != "test_gauge 1" {
		t.Errorf("after Inc: got %q, want %q", lines[0], "test_gauge 1")
	}

	g.Inc()

	if lines := g.Render(); lines[0] != "test_gauge 2" {
		t.Errorf("after second Inc: got %q, want %q", lines[0], "test_gauge 2")
	}

	g.Dec()

	if lines := g.Render(); lines[0] != "test_gauge 1" {
		t.Errorf("after Dec: got %q, want %q", lines[0], "test_gauge 1")
	}

	g.Dec()
	g.Dec()

	if lines := g.Render(); lines[0] != "test_gauge -1" {
		t.Errorf(
			"after two more Dec: got %q, want %q",
			lines[0],
			"test_gauge -1",
		)
	}
}

func TestGauge_Render(t *testing.T) {
	tests := []struct {
		name  string
		gauge *Gauge
		want  string
	}{
		{
			name:  "without labels",
			gauge: NewGauge("my_gauge", nil),
			want:  "my_gauge 0",
		},
		{
			name:  "with single label",
			gauge: NewGauge("my_gauge", Labels{"env": "prod"}),
			want:  `my_gauge{env="prod"} 0`,
		},
		{
			name: "with multiple labels",
			gauge: NewGauge(
				"http_connections",
				Labels{"host": "localhost", "port": "8080"},
			),
			want: `http_connections{host="localhost",port="8080"} 0`,
		},
		{
			name:  "with nil labels",
			gauge: NewGauge("nil_labels", nil),
			want:  "nil_labels 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := tt.gauge.Render()
			if len(lines) != 1 {
				t.Fatalf("expected 1 line, got %d", len(lines))
			}

			if lines[0] != tt.want {
				t.Errorf("got %q, want %q", lines[0], tt.want)
			}
		})
	}
}

func TestGauge_RenderWithValue(t *testing.T) {
	g := NewGauge("queue_size", Labels{"queue": "main"})
	g.Set(150)

	lines := g.Render()
	want := `queue_size{queue="main"} 150`

	if lines[0] != want {
		t.Errorf("got %q, want %q", lines[0], want)
	}
}

func TestGauge_DynamicLabels(t *testing.T) {
	g := NewGauge("active_connections", nil, "protocol")

	g.Set(10, "tcp")
	g.Set(5, "udp")

	lines := g.Render()
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}

	found := map[string]bool{}
	for _, line := range lines {
		found[line] = true
	}

	wantTCP := `active_connections{protocol="tcp"} 10`
	wantUDP := `active_connections{protocol="udp"} 5`

	if !found[wantTCP] {
		t.Errorf("missing line %q in %v", wantTCP, lines)
	}

	if !found[wantUDP] {
		t.Errorf("missing line %q in %v", wantUDP, lines)
	}
}

func TestGauge_Concurrent(t *testing.T) {
	g := NewGauge("concurrent_gauge", nil)

	const goroutines = 10

	const opsPerGoroutine = 100

	var wg sync.WaitGroup

	wg.Add(goroutines * 2)

	// Half goroutines increment
	for range goroutines {
		go func() {
			defer wg.Done()

			for range opsPerGoroutine {
				g.Inc()
			}
		}()
	}

	// Half goroutines decrement
	for range goroutines {
		go func() {
			defer wg.Done()

			for range opsPerGoroutine {
				g.Dec()
			}
		}()
	}

	wg.Wait()

	// Equal increments and decrements should result in 0
	lines := g.Render()
	if lines[0] != "concurrent_gauge 0" {
		t.Errorf("got %q, want %q", lines[0], "concurrent_gauge 0")
	}
}

func TestGauge_ConcurrentSetAndRender(t *testing.T) {
	g := NewGauge("test_concurrent_render", Labels{"type": "test"})

	var wg sync.WaitGroup

	const goroutines = 5

	// Concurrent writes
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for j := 0; j < 100; j++ {
				g.Set(int64(j))
			}
		}()
	}

	// Concurrent reads
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for range 100 {
				_ = g.Render()
			}
		}()
	}

	wg.Wait()
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
