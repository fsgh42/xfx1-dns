// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"fmt"
	"net/http"
)

type (
	StatusMessage struct {
		Status     bool
		Message    string
		StatusCode int
	}
)

func (s StatusMessage) WriteStatus(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(s.StatusCode)
	w.Write([]byte(s.Message))
}

func newHealthServer(port uint16, r Runnable) *http.Server {
	const (
		routeHealth = "/health"
		routeReady  = "/ready"
	)

	mux := http.NewServeMux()

	mux.HandleFunc(
		routeHealth,
		func(w http.ResponseWriter, req *http.Request) {
			r.Healthy().WriteStatus(w, req)
		},
	)

	mux.HandleFunc(
		routeReady,
		func(w http.ResponseWriter, req *http.Request) {
			r.Ready().WriteStatus(w, req)
		},
	)

	listenAddr := fmt.Sprintf(":%d", port)

	return &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}
}

func StatusOK(msg string) StatusMessage {
	return StatusMessage{true, msg, http.StatusOK}
}

func StatusNotReady(msg string) StatusMessage {
	return StatusMessage{false, msg, http.StatusServiceUnavailable}
}

func StatusUnhealthy(msg string) StatusMessage {
	return StatusMessage{false, msg, http.StatusInternalServerError}
}
