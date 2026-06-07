// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net/http"
)

// PingApiRequest returns an API request that indicates whether the k8s API is reachable or not.
func (c *Client) PingApiRequest(
	ctx context.Context,
	authorized bool,
) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, c.apiURL, nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	if authorized {
		req.Header.Set(
			headerAuthorization,
			headerValueBearer(string(c.apiToken)),
		)
	}

	// response shall be json
	req.Header.Set(headerAccept, headerValueAcceptJson)

	return req, nil
}
