// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package runtime

import "git.xfx1.de/infrastructure/xfx1-dns/internal/log"

// Commit and Tag are injected at build time via -ldflags.
var (
	Commit = ""
	Tag    = ""
)

func LogBuildInfo(logger log.Logger) {
	if Commit == "" {
		return
	}

	ctx := log.Ctx{"commit": Commit}

	if Tag != "" {
		ctx["tag"] = Tag
	}

	logger.Info("build info", ctx)
}
