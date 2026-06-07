// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"fmt"
	"math"
	"sync"
	"testing"
)

func TestCounter_Inc(t *testing.T) {
	c := NewCounter("test_counter", nil)

	c.Inc()

	if lines := c.Render(); lines[0] != "test_counter 1" {
		t.Errorf("after Inc: got %q, want %q", lines[0], "test_counter 1")
	}

	c.Inc()

	if lines := c.Render(); lines[0] != "test_counter 2" {
		t.Errorf(
			"after second Inc: got %q, want %q",
			lines[0],
			"test_counter 2",
		)
	}

	c.Inc()
	c.Inc()
	c.Inc()

	if lines := c.Render(); lines[0] != "test_counter 5" {
		t.Errorf("after five Inc: got %q, want %q", lines[0], "test_counter 5")
	}
}

func TestCounter_Add(t *testing.T) {
	tests := []struct {
		name     string
		adds     []uint64
		expected uint64
	}{
		{"add single value", []uint64{42}, 42},
		{"add zero", []uint64{0}, 0},
		{"add multiple values", []uint64{10, 20, 30}, 60},
		{"add large value", []uint64{math.MaxUint64}, math.MaxUint64},
		{"add one", []uint64{1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCounter("test_counter", nil)
			for _, n := range tt.adds {
				c.Add(n)
			}

			lines := c.Render()
			if len(lines) != 1 {
				t.Fatalf("expected 1 line, got %d", len(lines))
			}

			want := fmt.Sprintf("test_counter %d", tt.expected)
			if lines[0] != want {
				t.Errorf("got %q, want %q", lines[0], want)
			}
		},
		)
	}
}

func TestCounter_Render(t *testing.T) {
	tests := []struct {
		name    string
		counter *Counter
		want    string
	}{
		{
			name:    "without labels",
			counter: NewCounter("requests_total", nil),
			want:    "requests_total 0",
		},
		{
			name:    "with single static label",
			counter: NewCounter("http_requests_total", Labels{"method": "GET"}),
			want:    `http_requests_total{method="GET"} 0`,
		},
		{
			name: "with multiple static labels",
			counter: NewCounter(
				"api_calls_total",
				Labels{"endpoint": "/users", "status": "200"},
			),
			want: `api_calls_total{endpoint="/users",status="200"} 0`,
		},
		{
			name:    "with nil labels",
			counter: NewCounter("nil_labels", nil),
			want:    "nil_labels 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := tt.counter.Render()
			if len(lines) != 1 {
				t.Fatalf("expected 1 line, got %d", len(lines))
			}

			if lines[0] != tt.want {
				t.Errorf("got %q, want %q", lines[0], tt.want)
			}
		})
	}
}

func TestCounter_RenderWithValue(t *testing.T) {
	c := NewCounter("errors_total", Labels{"type": "timeout"})
	c.Add(150)

	lines := c.Render()
	want := `errors_total{type="timeout"} 150`

	if lines[0] != want {
		t.Errorf("got %q, want %q", lines[0], want)
	}
}

func TestCounter_DynamicLabels(t *testing.T) {
	c := NewCounter("cni_operations_total", nil, "command")

	c.Inc("ADD")
	c.Inc("ADD")
	c.Inc("DEL")

	lines := c.Render()
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}

	// Check both lines exist (order is map iteration order, so check contains)
	found := map[string]bool{}
	for _, line := range lines {
		found[line] = true
	}

	wantADD := `cni_operations_total{command="ADD"} 2`
	wantDEL := `cni_operations_total{command="DEL"} 1`

	if !found[wantADD] {
		t.Errorf("missing line %q in %v", wantADD, lines)
	}

	if !found[wantDEL] {
		t.Errorf("missing line %q in %v", wantDEL, lines)
	}
}

func TestCounter_StaticAndDynamicLabels(t *testing.T) {
	c := NewCounter(
		"http_requests_total",
		Labels{"node": "node-1"},
		"method",
		"status",
	)

	c.Inc("GET", "200")
	c.Inc("POST", "201")

	lines := c.Render()
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}

	found := map[string]bool{}
	for _, line := range lines {
		found[line] = true
	}

	wantGET := `http_requests_total{method="GET",node="node-1",status="200"} 1`
	wantPOST := `http_requests_total{method="POST",node="node-1",status="201"} 1`

	if !found[wantGET] {
		t.Errorf("missing line %q in %v", wantGET, lines)
	}

	if !found[wantPOST] {
		t.Errorf("missing line %q in %v", wantPOST, lines)
	}
}

func TestCounter_Concurrent(t *testing.T) {
	c := NewCounter("concurrent_counter", nil)

	const goroutines = 10

	const incsPerGoroutine = 100

	var wg sync.WaitGroup

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for range incsPerGoroutine {
				c.Inc()
			}
		}()
	}

	wg.Wait()

	lines := c.Render()
	want := "concurrent_counter 1000"

	if lines[0] != want {
		t.Errorf("got %q, want %q", lines[0], want)
	}
}

func TestCounter_ConcurrentAdd(t *testing.T) {
	c := NewCounter("concurrent_add", nil)

	const goroutines = 10

	const addsPerGoroutine = 100

	const addValue = uint64(5)

	var wg sync.WaitGroup

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for range addsPerGoroutine {
				c.Add(addValue)
			}
		}()
	}

	wg.Wait()

	lines := c.Render()
	want := "concurrent_add 5000"

	if lines[0] != want {
		t.Errorf("got %q, want %q", lines[0], want)
	}
}

func TestCounter_ConcurrentAddAndRender(t *testing.T) {
	c := NewCounter("test_concurrent_render", Labels{"type": "test"})

	var wg sync.WaitGroup

	const goroutines = 5

	// Concurrent writes
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for range 100 {
				c.Inc()
			}
		}()
	}

	// Concurrent reads
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for range 100 {
				_ = c.Render()
			}
		}()
	}

	wg.Wait()
}

func TestCounter_ConcurrentDynamicLabels(t *testing.T) {
	c := NewCounter("concurrent_dynamic", nil, "command")

	const goroutines = 10

	const opsPerGoroutine = 100

	var wg sync.WaitGroup

	wg.Add(goroutines * 2)

	// Half increment ADD
	for range goroutines {
		go func() {
			defer wg.Done()

			for range opsPerGoroutine {
				c.Inc("ADD")
			}
		}()
	}

	// Half increment DEL
	for range goroutines {
		go func() {
			defer wg.Done()

			for range opsPerGoroutine {
				c.Inc("DEL")
			}
		}()
	}

	wg.Wait()

	lines := c.Render()
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	found := map[string]bool{}
	for _, line := range lines {
		found[line] = true
	}

	wantADD := `concurrent_dynamic{command="ADD"} 1000`
	wantDEL := `concurrent_dynamic{command="DEL"} 1000`

	if !found[wantADD] {
		t.Errorf("missing line %q in %v", wantADD, lines)
	}

	if !found[wantDEL] {
		t.Errorf("missing line %q in %v", wantDEL, lines)
	}
}
