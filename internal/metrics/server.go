// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/runtime"
)

type (
	MetricsServer struct {
		m      Metrics
		logger log.Logger
	}
)

const (
	headerValueContentType = "text/plain; charset=utf-8"
	pathMetrics            = "/metrics"
)

var headerKeyContentType = http.CanonicalHeaderKey("Content-Type")

func (ms *MetricsServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerKeyContentType, headerValueContentType)
	w.WriteHeader(http.StatusOK)

	lines := ms.m.RenderAll()

	const prometheusLineEndSignal = "\n"
	data := []byte(strings.Join(lines, "\n") + prometheusLineEndSignal)

	if _, err := w.Write(data); err != nil {
		ms.logger.Error(fmt.Sprintf("write metrics response: %s", err))
	}
}

func (m *MetricsServer) ListenAndServe(addr string, ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(pathMetrics, m.handleMetrics)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	m.logger.Info(fmt.Sprintf("serving metrics, addr: %s", addr))

	return runtime.ServeUntilCanceled(srv, ctx, m.logger)
}
