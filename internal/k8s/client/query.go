// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
)

// QueryApiRaw makes an API request based on the provided parameters, returns the raw response and an error (if any).
// Returns the result of Client.Do().
func (c *Client) QueryApiRaw(
	ctx context.Context,
	p *api.ApiRequestParams,
) (*http.Response, error) {
	url, err := p.URL(c.apiURL)
	if err != nil {
		return nil, err
	}

	req, err := c.makeRequest(ctx, url, http.MethodGet)
	if err != nil {
		return nil, err
	}

	return c.Doer.Do(req)
}

// queryApi makes an API request based on the provided parameters and returns the statusCode,
// the body data and an error (if any).
//
// This function DOES honor paginated Results.
func (c *Client) QueryApi(
	ctx context.Context,
	p *api.ApiRequestParams,
) ([][]byte, error) {
	url, err := p.URL(c.apiURL)
	if err != nil {
		return nil, err
	}

	req, err := c.makeRequest(ctx, url, http.MethodGet)
	if err != nil {
		return nil, err
	}

	statusCode, data, err := c.doPaginated(req)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", k8s.ErrBadStatusCode, statusCode)
	}

	return data, nil
}

var ErrNoResults = errors.New("no results")

// QueryApi infers ApiRequestParams from the registered type T and queries the K8s API.
// Returns the results as []*base.Object[T].
func QueryApi[T any](
	ctx context.Context,
	c K8sClient,
) ([]*base.Object[T], error) {
	p, err := api.ParamsFor[T]()
	if err != nil {
		return nil, err
	}

	return QueryApiWithParams[T](ctx, c, p)
}

// QueryApiWithParams queries the K8s API with the given parameters.
// Returns []*base.Object[T] where each item is a full K8s object with metadata and spec.
// Returns ErrNoResults if the API returned zero items.
func QueryApiWithParams[T any](
	ctx context.Context,
	c K8sClient,
	p *api.ApiRequestParams,
) ([]*base.Object[T], error) {
	raw, err := c.QueryApi(ctx, p)
	if err != nil {
		return nil, err
	}

	results := make([]*base.Object[T], 0, len(raw))

	for _, data := range raw {
		var obj base.Object[T]
		if err := json.Unmarshal(data, &obj); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}

		results = append(results, &obj)
	}

	if len(results) == 0 {
		return nil, ErrNoResults
	}

	return results, nil
}
