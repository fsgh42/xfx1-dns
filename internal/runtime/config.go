// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"fmt"
	"slices"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

// ports by other k8s components known to cause issues
var badPorts = []uint16{
	10250, // kubelet API
	10256, // kube-proxy health check
	10257, // kube-controller-manager
	10259, // kube-scheduler
	10260, // kubelet health (some distros)
}

type (
	config struct {
		healthPort  uint16
		metricsPort uint16
		logger      log.Logger
		cancelCh    <-chan struct{} // optional: closes to trigger a clean shutdown
	}

	Option func(*config)
)

func WithHealthPort(hp uint16) Option {
	return func(c *config) {
		c.healthPort = hp
	}
}

func WithMetricsPort(mp uint16) Option {
	return func(c *config) {
		c.metricsPort = mp
	}
}

func WithLogger(lgr log.Logger) Option {
	return func(c *config) {
		c.logger = lgr
	}
}

// WithCancelChannel returns an Option that causes Run to cancel the runtime context
// (and return cleanly) when ch is closed. Useful for in-process reloads.
func WithCancelChannel(ch <-chan struct{}) Option {
	return func(c *config) {
		c.cancelCh = ch
	}
}

func (c *config) Validate() error {
	if c.healthPort <= 1024 { // avoid well known and unset ports
		return fmt.Errorf("invalid health port: %d", c.healthPort)
	}

	// metricsPort can be 0 if the associated
	// Runnable does not implement metrics.MetricsProvider
	if c.metricsPort != 0 && c.metricsPort <= 1024 {
		return fmt.Errorf("invalid metrics port: %d", c.metricsPort)
	}

	if slices.Index(badPorts, c.healthPort) != -1 {
		return fmt.Errorf("port %d is on the \"bad ports\" list", c.healthPort)
	}

	return nil
}
