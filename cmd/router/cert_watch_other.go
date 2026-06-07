// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"

	ilog "git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

// watchCertFiles is a no-op on non-Linux platforms. The router still reloads
// on DNSConfig changes; only filesystem-driven cert reload is unavailable.
func watchCertFiles(
	ctx context.Context,
	_, _ string,
	_ chan<- struct{},
	_ ilog.Logger,
) {
	<-ctx.Done()
}
