// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/resources/base"
)

const (
	fieldManager = "xfx1-dns"
)

// ApplyOrUpdate implements the "upsert" of kubernetes objects.
// This is achieved by invoking a strategic merge via server-side-apply.
//
// will set p.FieldManager if unset.
func (c *Client) ApplyOrUpdate(
	ctx context.Context,
	p *api.ApiRequestParams,
	ko base.KubernetesObject,
) error {
	if p.FieldManager == "" {
		p.FieldManager = fieldManager
	}

	url, err := p.URL(c.apiURL)
	if err != nil {
		return err
	}

	req, err := c.makeRequest(ctx, url, http.MethodPatch)
	if err != nil {
		return err
	}

	// set header that enables server side apply,
	// the request then essentially works like an upsert.
	// The official docs specify that YAML shall be used here,
	// even if JSON is submitted (as every JSON document is valid YAML).
	//
	// https://kubernetes.io/docs/reference/using-api/server-side-apply/#serialization
	req.Header.Set(headerContentType, headerValueContentTypeApplyPatchYaml)

	data, err := json.Marshal(ko)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	c.logger.Debug(fmt.Sprintf("payload: %s", string(data)))

	req.Body = io.NopCloser(bytes.NewBuffer(data))

	statusCode, responseData, err := c.do(req)
	if err != nil {
		return err
	}

	if !(statusCode == http.StatusCreated || statusCode == http.StatusOK) {
		c.logger.Error(
			fmt.Sprintf(
				"api replied with unexpected status code: %d, url: %s",
				statusCode,
				url,
			),
		)
		c.logger.Debug(fmt.Sprintf("api response: %s", string(responseData)))

		return fmt.Errorf("%w: %d", k8s.ErrBadStatusCode, statusCode)
	}

	c.logger.Debug(fmt.Sprintf("created/updated: %s", string(data)))

	return nil
}
