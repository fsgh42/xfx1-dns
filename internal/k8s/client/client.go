// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/env"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

type (
	Client struct {
		Doer     HttpDoer
		apiURL   string
		apiToken []byte
		logger   log.Logger
	}
)

// TestClient is a lightweight client intended for unit tests. It does not
// enforce presence of service account token or CA certs.
type TestClient struct {
	*Client
}

// NewTestClient creates a TestClient with an injected http.Client and API URL.
// Useful for testing with httptest.NewServer.
func NewTestClient(httpClient *http.Client, apiURL string) *TestClient {
	return &TestClient{
		Client: &Client{
			Doer:     httpClient,
			apiURL:   apiURL,
			apiToken: nil, // test client must not send Authorization header
			logger:   log.NewDefaultLogger("k8sclient"),
		},
	}
}

// NewDefaultK8sClient returns the default k8s API client. It reads the
// service account token and CA from the filesystem and will fatal on
// missing required files.
func NewDefaultK8sClient(timeout time.Duration) *Client {
	logger := log.New[log.Console, log.Logfmt]("k8sclient")

	apiToken, err := os.ReadFile(k8s.ApiTokenFile)
	if err != nil {
		logger.Info(
			fmt.Sprintf("cannot read k8s api token from %s", k8s.ApiTokenFile),
		)
	}

	apiCaCert, err := os.ReadFile(k8s.ApiCaFile)
	if err != nil {
		logger.Info(
			fmt.Sprintf("cannot read k8s ca file from %s", k8s.ApiCaFile),
		)
	}

	// the default client enforces existing CA cert
	if len(apiCaCert) == 0 {
		logger.Fatal("no API CA cert found, TLS verification disabled")
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(apiCaCert); !ok {
		logger.Fatal("failed to append CA cert to cert pool")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			RootCAs:            pool,
		},
		IdleConnTimeout: 0, // no limit as we potentially do long running watches
		// ResponseHeaderTimeout must not be set: it also applies to streaming
		// watch responses and would kill the connection after the first quiet
		// period, causing continuous reconnects and spurious rebuilds.
		// The dial timeout below is sufficient to catch hung connections.
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}

	apiUrl, err := env.KubeApiFromEnv()
	if err != nil {
		// This must always be set at program start so we can fail hard
		logger.Fatal(err.Error())
	}

	logger.Debug(fmt.Sprintf("using kubeapi host: %s", apiUrl))

	// trim whitespace/newlines from token
	apiToken = bytes.TrimSpace(apiToken)
	if len(apiToken) == 0 {
		logger.Fatal("no API token found")
	}

	client := &Client{
		Doer: &http.Client{
			// No Timeout here - it kills long-running watch connections.
			// ResponseHeaderTimeout on Transport handles initial response.
			Transport: tr,
		},
		apiURL:   apiUrl,
		apiToken: apiToken,
		logger:   logger,
	}

	return client
}

// MakeRequest prepares a http.Request based on the provided parameters
// and sets related Header fields, to it can be executed against the k8s API.
func (c *Client) makeRequest(
	ctx context.Context,
	url, method string,
) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	req.Header.Set(headerAuthorization, headerValueBearer(string(c.apiToken)))
	req.Header.Set(
		headerAccept,
		headerValueAcceptJson,
	) // tell server we want a json response

	return req, nil
}
