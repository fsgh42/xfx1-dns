// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/json"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
)

// MockClient is a K8sClient implementation for use in tests.
// ListResult holds pre-serialised items returned by QueryApi;
// nil/empty causes QueryApiWithParams to return ErrNoResults naturally.
type MockClient struct {
	ListResult [][]byte
	ListErr    error
	ApplyErr   error
	DeleteErr  error

	ApplyCalls  []MockApplyCall
	DeleteCalls []string
}

// MockApplyCall records one ApplyOrUpdate invocation.
type MockApplyCall struct {
	Params *api.ApiRequestParams
	Object base.KubernetesObject
}

// MockObjects serialises a slice of typed k8s objects into the [][]byte
// format expected by MockClient.ListResult (one entry per object).
func MockObjects[T any](objects ...*base.Object[T]) [][]byte {
	result := make([][]byte, 0, len(objects))

	for _, obj := range objects {
		data, _ := json.Marshal(obj)
		result = append(result, data)
	}

	return result
}

func (m *MockClient) QueryApi(
	_ context.Context,
	_ *api.ApiRequestParams,
) ([][]byte, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}

	return m.ListResult, nil
}

func (m *MockClient) QueryApiRaw(
	_ context.Context,
	_ *api.ApiRequestParams,
) (*http.Response, error) {
	return nil, nil
}

func (m *MockClient) ApplyOrUpdate(
	_ context.Context,
	p *api.ApiRequestParams,
	ko base.KubernetesObject,
) error {
	m.ApplyCalls = append(m.ApplyCalls, MockApplyCall{Params: p, Object: ko})
	return m.ApplyErr
}

func (m *MockClient) Delete(_ context.Context, p *api.ApiRequestParams) error {
	m.DeleteCalls = append(m.DeleteCalls, p.Name)
	return m.DeleteErr
}

func (m *MockClient) PingApiRequest(
	_ context.Context,
	_ bool,
) (*http.Request, error) {
	return nil, nil
}
