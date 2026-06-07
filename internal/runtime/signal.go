// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var DefaultTerminationSignals = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT,
}

// CancelOnSignal will call the cancel function if any of the signals given are encountered.
// It also exits cleanly when ctx is cancelled, preventing a goroutine leak on in-process reloads.
// This function does not block.
func CancelOnSignal(
	ctx context.Context,
	signals []os.Signal,
	cancel context.CancelFunc,
	wg *sync.WaitGroup,
) {
	wg.Go(
		func() {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, signals...)
			defer signal.Stop(sigCh)

			select {
			case <-sigCh:
				cancel()
			case <-ctx.Done():
			}
		},
	)
}
