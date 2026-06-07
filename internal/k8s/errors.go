// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package k8s

import "errors"

var (
	ErrBadStatusCode          = errors.New("bad status code")
	ErrK8sApiBadEnv           = errors.New("env var not found")
	ErrUrlFormat              = errors.New("format URL")
	ErrIllegalApiRequestParam = errors.New("bad ApiRequestParam")
)
