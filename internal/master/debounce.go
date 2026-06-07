// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only/

package master

import (
	"context"
	"time"
)

// debounce converts a stream of watch events into a debounced trigger channel.
// Fires after `quiet` milliseconds of no events, or after
// `deadline` from the first event in a burst — whichever comes first.
// The returned channel is closed when `ctx` is done or `events` is closed.
func debounce[T any](
	ctx context.Context,
	events <-chan T,
	quiet, deadline time.Duration,
) <-chan struct{} {
	out := make(chan struct{}, 1)

	go func() {
		defer close(out)

		var quietTimer, deadlineTimer *time.Timer

		stop := func(t *time.Timer) {
			if t != nil {
				t.Stop()
			}
		}

		fire := func() {
			stop(quietTimer)
			stop(deadlineTimer)

			quietTimer, deadlineTimer = nil, nil

			select {
			case out <- struct{}{}:
			default:
			}
		}

		for {
			var quietC, deadlineC <-chan time.Time

			if quietTimer != nil {
				quietC = quietTimer.C
			}

			if deadlineTimer != nil {
				deadlineC = deadlineTimer.C
			}

			select {
			case <-ctx.Done():
				return
			case _, ok := <-events:
				if !ok {
					return
				}

				// Reset quiet window.
				stop(quietTimer)
				quietTimer = time.NewTimer(quiet)

				// Start deadline only on first event of a burst.
				if deadlineTimer == nil {
					deadlineTimer = time.NewTimer(deadline)
				}
			case <-quietC:
				fire()
			case <-deadlineC:
				fire()
			}
		}
	}()

	return out
}
