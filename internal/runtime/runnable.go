// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"fmt"
	"sync"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

type (
	// Runnable is implemented by components running as k8s workload.
	Runnable interface {
		// Healthy signals health of a component.
		Healthy() StatusMessage
		// Ready signals readiness of a component.
		Ready() StatusMessage
		// Run implements the main loop of a Runnable.
		// If multiple parallel main loops have to be run, it is the job of the
		// implementing component to implement this.
		MainLoop(context.Context) error
	}
)

func Run(r Runnable, opts ...Option) error {
	logger := log.NewDefaultLogger("runtime")
	cfg := &config{
		healthPort: 0,      // invalid, must be set by caller
		logger:     logger, // components should overwrite this
	}

	for _, opt := range opts {
		opt(cfg)
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}

	CancelOnSignal(ctx, DefaultTerminationSignals, cancel, &wg)

	if cfg.cancelCh != nil {
		wg.Go(func() {
			select {
			case <-cfg.cancelCh:
				cancel()
			case <-ctx.Done():
			}
		})
	}

	wg.Go(
		func() {
			srv := newHealthServer(cfg.healthPort, r)
			if err := ServeUntilCanceled(srv, ctx, cfg.logger); err != nil {
				cfg.logger.Error(fmt.Sprintf("health: %v", err))
				cancel()
			}
		},
	)

	if mp, ok := r.(metricsProvider); ok && cfg.metricsPort > 0 {
		wg.Go(
			func() {
				srv := newMetricsServer(cfg.metricsPort, mp)
				if err := ServeUntilCanceled(srv, ctx, cfg.logger); err != nil {
					cfg.logger.Error(fmt.Sprintf("metrics: %v", err))
					cancel()
				}
			},
		)
	}

	err := r.MainLoop(ctx)

	cancel()
	wg.Wait()

	return err
}
