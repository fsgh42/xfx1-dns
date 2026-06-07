// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package watch

import (
	"context"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
)

type (
	// EventType is the type of a k8s watch event.
	EventType string

	// Event is a typed k8s watch event.
	Event[T any] struct {
		Type   EventType
		Object *base.Object[T]
	}

	// wireEvent is the raw JSON structure returned by the k8s watch API.
	wireEvent[T any] struct {
		Type   EventType       `json:"type"`
		Object *base.Object[T] `json:"object"`
	}
)

const (
	EventAdded    EventType = "ADDED"
	EventModified EventType = "MODIFIED"
	EventDeleted  EventType = "DELETED"
)

// Watch starts a self-reconnecting streaming watch loop against the k8s API.
// It returns a channel of Event[T] with the given buffer size. The channel is
// closed when ctx is cancelled. BOOKMARK and ERROR wire events are silently
// discarded. On EOF or error the loop reconnects after a 1-second pause.
//
// The caller is responsible for registering T via api.RegisterSpec before calling Watch.
// Pass a params clone with Watch=true if you want watch semantics.
func Watch[T any](
	ctx context.Context,
	c client.K8sClient,
	p *api.ApiRequestParams,
	bufSize int,
	logger log.Logger,
	parseErrors *metrics.Counter,
) <-chan Event[T] {
	ch := make(chan Event[T], bufSize)
	params := p.Clone()
	params.Watch = true

	go func() {
		defer close(ch)

		for {
			if err := ctx.Err(); err != nil {
				return
			}

			streamOnce[T](ctx, c, params, ch, logger, parseErrors)
			// reconnect pause, interruptible by cancellation
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()

	return ch
}
