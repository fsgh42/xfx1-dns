// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
)

// streamOnce opens one watch stream and reads until EOF, error, or cancellation.
func streamOnce[T any](
	ctx context.Context,
	c client.K8sClient,
	p *api.ApiRequestParams,
	ch chan<- Event[T],
	logger log.Logger,
	parseErrors *metrics.Counter,
) {
	resp, err := c.QueryApiRaw(ctx, p)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var wire wireEvent[T]
		if err := json.Unmarshal(line, &wire); err != nil {
			logger.Error(fmt.Sprintf("watch: unmarshal event: %v", err))
			parseErrors.Inc()

			continue
		}

		// Discard BOOKMARK and ERROR events.
		switch wire.Type {
		case EventAdded, EventModified, EventDeleted:
		default:
			continue
		}

		if wire.Object == nil {
			continue
		}

		select {
		case <-ctx.Done():
			return
		case ch <- Event[T]{Type: wire.Type, Object: wire.Object}:
		}
	}
}
