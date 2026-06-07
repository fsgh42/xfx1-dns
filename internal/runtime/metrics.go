// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"fmt"
	"net/http"
	"strings"
)

type (

	// metricsProvider mirrors metrics.MetricsProvider,
	// to avoid import cycles
	metricsProvider interface {
		RenderAll() []string
	}
)

func newMetricsServer(port uint16, mp metricsProvider) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		lines := mp.RenderAll()
		w.Write([]byte(strings.Join(lines, "\n") + "\n"))
	})

	return &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
}
