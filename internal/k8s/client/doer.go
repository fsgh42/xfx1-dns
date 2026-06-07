// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import "net/http"

// HttpDoer is a minimal interface around http.Client.Do to allow test
// injection of fake clients in unit tests.
type HttpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}
