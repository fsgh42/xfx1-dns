// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"strings"
	"sync"
	"testing"
)

func TestHistogram_Observe(t *testing.T) {
	// wantCounts are CUMULATIVE - each bucket includes all observations <= its bound
	tests := []struct {
		name       string
		buckets    []float64
		values     []float64
		wantSum    float64
		wantCount  uint64
		wantCounts []uint64 // cumulative counts per bucket
	}{
		{
			name:       "single value in first bucket",
			buckets:    []float64{0.1, 0.5, 1.0},
			values:     []float64{0.05},
			wantSum:    0.05,
			wantCount:  1,
			wantCounts: []uint64{1, 1, 1}, // value <= all bounds
		},
		{
			name:       "single value in middle bucket",
			buckets:    []float64{0.1, 0.5, 1.0},
			values:     []float64{0.3},
			wantSum:    0.3,
			wantCount:  1,
			wantCounts: []uint64{0, 1, 1}, // value > 0.1, <= 0.5 and 1.0
		},
		{
			name:       "single value in last bucket",
			buckets:    []float64{0.1, 0.5, 1.0},
			values:     []float64{0.8},
			wantSum:    0.8,
			wantCount:  1,
			wantCounts: []uint64{0, 0, 1}, // value > 0.1 and 0.5, <= 1.0
		},
		{
			name:       "value exceeds all buckets",
			buckets:    []float64{0.1, 0.5, 1.0},
			values:     []float64{5.0},
			wantSum:    5.0,
			wantCount:  1,
			wantCounts: []uint64{0, 0, 0}, // value > all bounds, only in +Inf
		},
		{
			name:      "multiple values in different buckets",
			buckets:   []float64{0.1, 0.5, 1.0},
			values:    []float64{0.05, 0.3, 0.8, 2.0},
			wantSum:   3.15,
			wantCount: 4,
			wantCounts: []uint64{
				1,
				2,
				3,
			}, // cumulative: 1 in <=0.1, 2 in <=0.5, 3 in <=1.0
		},
		{
			name:       "value exactly on bucket boundary",
			buckets:    []float64{0.1, 0.5, 1.0},
			values:     []float64{0.5},
			wantSum:    0.5,
			wantCount:  1,
			wantCounts: []uint64{0, 1, 1}, // value > 0.1, <= 0.5 and 1.0
		},
		{
			name:       "multiple values in same bucket",
			buckets:    []float64{0.1, 0.5, 1.0},
			values:     []float64{0.02, 0.03, 0.04},
			wantSum:    0.09,
			wantCount:  3,
			wantCounts: []uint64{3, 3, 3}, // all values <= all bounds
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHistogram("test_histogram", tt.buckets, nil)

			for _, v := range tt.values {
				h.Observe(v)
			}

			// Get series for empty label key
			s := h.series[""]
			if s == nil {
				t.Fatal("expected series for empty label key")
			}

			if s.Sum != tt.wantSum {
				t.Errorf("Sum = %v, want %v", s.Sum, tt.wantSum)
			}

			if s.Count != tt.wantCount {
				t.Errorf("Count = %v, want %v", s.Count, tt.wantCount)
			}

			for i, want := range tt.wantCounts {
				if s.Counts[i] != want {
					t.Errorf("Counts[%d] = %v, want %v", i, s.Counts[i], want)
				}
			}
		})
	}
}

func TestHistogram_ObserveConcurrent(t *testing.T) {
	h := NewHistogram("test_concurrent", []float64{0.1, 0.5, 1.0}, nil)

	const goroutines = 10

	const observationsPerGoroutine = 100

	var wg sync.WaitGroup

	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < observationsPerGoroutine; j++ {
				h.Observe(0.05) // All go in first bucket
			}
		}()
	}

	wg.Wait()

	s := h.series[""]
	expectedCount := uint64(goroutines * observationsPerGoroutine)

	if s.Count != expectedCount {
		t.Errorf("Count = %v, want %v", s.Count, expectedCount)
	}

	if s.Counts[0] != expectedCount {
		t.Errorf("Counts[0] = %v, want %v", s.Counts[0], expectedCount)
	}
}

func TestHistogram_Render(t *testing.T) {
	// Counts are now stored CUMULATIVE internally, so setup values must be cumulative
	tests := []struct {
		name      string
		histogram *Histogram
		setup     func(*Histogram)
		wantLines []string
	}{
		{
			name: "histogram with labels",
			histogram: NewHistogram(
				"http_request_duration_seconds",
				[]float64{0.1, 0.5, 1.0},
				Labels{"method": "GET"},
			),
			setup: func(h *Histogram) {
				// Cumulative counts: 5 in <=0.1, 8 in <=0.5, 10 in <=1.0
				h.series[""] = &histogramSeries{
					Counts: []uint64{5, 8, 10},
					Sum:    15.5,
					Count:  10,
				}
			},
			wantLines: []string{
				`http_request_duration_seconds_bucket{le="0.1",method="GET"} 5`,
				`http_request_duration_seconds_bucket{le="0.5",method="GET"} 8`,
				`http_request_duration_seconds_bucket{le="1",method="GET"} 10`,
				`http_request_duration_seconds_bucket{le="+Inf",method="GET"} 10`,
				`http_request_duration_seconds_sum{method="GET"} 15.5`,
				`http_request_duration_seconds_count{method="GET"} 10`,
			},
		},
		{
			name:      "histogram without labels",
			histogram: NewHistogram("requests_total", []float64{0.1, 0.5}, nil),
			setup: func(h *Histogram) {
				// Cumulative counts: 2 in <=0.1, 3 in <=0.5
				h.series[""] = &histogramSeries{
					Counts: []uint64{2, 3},
					Sum:    1.2,
					Count:  3,
				}
			},
			wantLines: []string{
				`requests_total_bucket{le="0.1"} 2`,
				`requests_total_bucket{le="0.5"} 3`,
				`requests_total_bucket{le="+Inf"} 3`,
				`requests_total_sum 1.2`,
				`requests_total_count 3`,
			},
		},
		{
			name: "histogram with multiple static labels",
			histogram: NewHistogram(
				"db_query_duration",
				[]float64{0.01},
				Labels{"database": "postgres", "operation": "select"},
			),
			setup: func(h *Histogram) {
				h.series[""] = &histogramSeries{
					Counts: []uint64{100},
					Sum:    0.5,
					Count:  100,
				}
			},
			wantLines: []string{
				`db_query_duration_bucket{database="postgres",le="0.01",operation="select"} 100`,
				`db_query_duration_bucket{database="postgres",le="+Inf",operation="select"} 100`,
				`db_query_duration_sum{database="postgres",operation="select"} 0.5`,
				`db_query_duration_count{database="postgres",operation="select"} 100`,
			},
		},
		{
			name: "empty histogram",
			histogram: NewHistogram(
				"empty",
				[]float64{0.1, 0.5, 1.0},
				Labels{"status": "ok"},
			),
			setup: func(h *Histogram) {},
			wantLines: []string{
				`empty_bucket{le="0.1",status="ok"} 0`,
				`empty_bucket{le="0.5",status="ok"} 0`,
				`empty_bucket{le="1",status="ok"} 0`,
				`empty_bucket{le="+Inf",status="ok"} 0`,
				`empty_sum{status="ok"} 0`,
				`empty_count{status="ok"} 0`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(tt.histogram)
			lines := tt.histogram.Render()

			if len(lines) != len(tt.wantLines) {
				t.Fatalf(
					"got %d lines, want %d lines",
					len(lines),
					len(tt.wantLines),
				)
			}

			for i, line := range lines {
				if line != tt.wantLines[i] {
					t.Errorf(
						"line %d:\ngot:  %q\nwant: %q",
						i,
						line,
						tt.wantLines[i],
					)
				}
			}
		})
	}
}

func TestHistogram_RenderCumulative(t *testing.T) {
	// Counts are now stored CUMULATIVE internally
	h := NewHistogram("test", []float64{1, 2, 3}, Labels{"foo": "bar"})
	h.series[""] = &histogramSeries{
		Counts: []uint64{10, 30, 60}, // already cumulative
		Sum:    100,
		Count:  60,
	}

	lines := h.Render()

	// Verify cumulative output matches internal cumulative storage
	if !strings.Contains(lines[0], "} 10") {
		t.Errorf("First bucket should be 10, got: %s", lines[0])
	}

	if !strings.Contains(lines[1], "} 30") {
		t.Errorf("Second bucket should be 30, got: %s", lines[1])
	}

	if !strings.Contains(lines[2], "} 60") {
		t.Errorf("Third bucket should be 60, got: %s", lines[2])
	}

	if !strings.Contains(lines[3], "} 60") {
		t.Errorf("+Inf bucket should equal Count (60), got: %s", lines[3])
	}
}

func TestHistogram_DynamicLabels(t *testing.T) {
	h := NewHistogram("request_duration", []float64{0.1, 0.5}, nil, "method")

	h.Observe(0.05, "GET")
	h.Observe(0.3, "GET")
	h.Observe(0.2, "POST")

	lines := h.Render()
	// Should have 2 series (GET and POST), each with 5 lines (2 buckets + inf + sum + count)
	if len(lines) != 10 {
		t.Fatalf("expected 10 lines, got %d: %v", len(lines), lines)
	}

	// Check that both methods are present
	foundGET := false
	foundPOST := false

	for _, line := range lines {
		if strings.Contains(line, `method="GET"`) {
			foundGET = true
		}

		if strings.Contains(line, `method="POST"`) {
			foundPOST = true
		}
	}

	if !foundGET {
		t.Error("missing GET method in output")
	}

	if !foundPOST {
		t.Error("missing POST method in output")
	}
}

func TestHistogram_RenderConcurrentSafety(t *testing.T) {
	h := NewHistogram("test_concurrent_render", []float64{0.1, 0.5, 1.0}, nil)

	var wg sync.WaitGroup

	const goroutines = 5

	// Concurrent writes
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for j := 0; j < 100; j++ {
				h.Observe(0.05)
			}
		}()
	}

	// Concurrent reads
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for range 100 {
				_ = h.Render()
			}
		}()
	}

	wg.Wait()

	// Verify final state is consistent
	s := h.series[""]
	if s.Count != s.Counts[0] {
		t.Errorf(
			"Inconsistent state: Count=%d, Counts[0]=%d",
			s.Count,
			s.Counts[0],
		)
	}
}
