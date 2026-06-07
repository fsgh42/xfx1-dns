// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s"
)

// Do executes an HTTP request against the kubernetes API, unpacks the response
// and returns StatusCode, body and an error (if any).
//
// This function does NOT honor paginated results.
// This function assumes the http.Request passed has a context assigned.
func (c *Client) do(req *http.Request) (int, []byte, error) {
	c.logger.Debug(fmt.Sprintf("%s %s", req.Method, req.URL))

	res, err := c.Doer.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, data, err
	}

	return res.StatusCode, data, nil
}

// Do executes an HTTP request against the kubernetes API and unpacks the response.
// It returns:
//   - the last observed StatusCode
//   - all bodies read so far
//   - the first error encountered (if any)
//
// This function DOES honor paginated results.
// This function assumes the http.Request passed has a context assigned.
func (c *Client) doPaginated(
	req *http.Request,
) (sc int, res [][]byte, lastErr error) {
	c.logger.Debug(fmt.Sprintf("%s %s", req.Method, req.URL))

	isPaginatedResponse := func(r *http.Response, data []byte) (bool, string) {
		if token := r.Header.Get(headerContinue); token != "" {
			return true, token
		}

		var paginatedResponse struct {
			Metadata struct {
				Continue string `json:"continue,omitempty"`
			} `json:"metadata"`
		}

		err := json.Unmarshal(data, &paginatedResponse)
		if err != nil {
			c.logger.Error(fmt.Sprintf("unmarshal paginated: %s", err))

			return false, ""
		}

		token := paginatedResponse.Metadata.Continue
		isPaginated := token != ""

		return isPaginated, token
	}

	nextReqWithContinueToken := func(token string) *http.Request {
		newReq := req.Clone(req.Context())
		q := newReq.URL.Query()
		q.Set(urlParamContinue, token)
		newReq.URL.RawQuery = q.Encode()

		return newReq
	}

	nextReq := req

	for {
		resp, err := c.Doer.Do(nextReq)
		if err != nil {
			lastErr = fmt.Errorf("request: %w", err)
			break
		}

		sc = resp.StatusCode

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf(
				"%w: %s",
				k8s.ErrBadStatusCode,
				http.StatusText(resp.StatusCode),
			)
			_ = resp.Body.Close()

			break
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("readBody: %w", err)
			_ = resp.Body.Close()

			break
		}

		// Unwrap list responses: extract individual items from .items[]
		var listResponse struct {
			Items []json.RawMessage `json:"items"`
		}

		if err := json.Unmarshal(data, &listResponse); err == nil &&
			listResponse.Items != nil {
			for _, item := range listResponse.Items {
				res = append(res, item)
			}
		} else {
			res = append(res, data)
		}

		_ = resp.Body.Close()

		if isPaginated, token := isPaginatedResponse(resp, data); isPaginated {
			nextReq = nextReqWithContinueToken(token)
			continue
		}

		break // no next request
	}

	return sc, res, lastErr
}
