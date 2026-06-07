// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
)

// K8sClient is the minimal client interface used by callers. It allows
// swapping in TestClient implementations for unit tests.
type K8sClient interface {
	QueryApi(ctx context.Context, p *api.ApiRequestParams) ([][]byte, error)
	QueryApiRaw(
		ctx context.Context,
		p *api.ApiRequestParams,
	) (*http.Response, error)
	ApplyOrUpdate(
		ctx context.Context,
		p *api.ApiRequestParams,
		ko base.KubernetesObject,
	) error
	Delete(ctx context.Context, p *api.ApiRequestParams) error
	PingApiRequest(ctx context.Context, authorized bool) (*http.Request, error)
}
