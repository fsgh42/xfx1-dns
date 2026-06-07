// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"fmt"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
)

// Delete deletes the resource identified by p.Name. Accepts 200 OK or 404 Not Found
// (idempotent delete). Returns an error for other status codes.
func (c *Client) Delete(ctx context.Context, p *api.ApiRequestParams) error {
	url, err := p.URL(c.apiURL)
	if err != nil {
		return err
	}

	req, err := c.makeRequest(ctx, url, http.MethodDelete)
	if err != nil {
		return err
	}

	statusCode, _, err := c.do(req)
	if err != nil {
		return err
	}

	if statusCode == http.StatusOK || statusCode == http.StatusNotFound {
		return nil
	}

	return fmt.Errorf(
		"%w: DELETE returned %d",
		k8s.ErrBadStatusCode,
		statusCode,
	)
}
