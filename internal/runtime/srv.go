// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

func ServeUntilCanceled(
	srv *http.Server,
	ctx context.Context,
	logger log.Logger,
) error {
	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error(fmt.Sprintf("server shutdown: %v", err))
		}
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}

	return nil
}
