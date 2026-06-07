// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
)

// SecretData holds the decoded data fields of a k8s Secret.
// The k8s API returns Secret.data values as base64-encoded strings;
// GetSecret decodes them before returning.
type SecretData map[string][]byte

// GetSecret reads a single k8s Secret by name from the given namespace.
// Returns SecretData with base64-decoded values from the Secret's data field.
func GetSecret(
	ctx context.Context,
	c K8sClient,
	namespace, name string,
) (SecretData, error) {
	p := &api.ApiRequestParams{
		Group:        "", // empty group = core API (/api/v1/...)
		Version:      "v1",
		ResourceType: "secrets",
		Namespace:    namespace,
		Name:         name,
	}

	resp, err := c.QueryApiRaw(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"get secret %s/%s: status %d",
			namespace,
			name,
			resp.StatusCode,
		)
	}

	var obj struct {
		Data map[string]string `json:"data"` // base64-encoded by k8s API
	}

	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, fmt.Errorf("decode secret %s/%s: %w", namespace, name, err)
	}

	result := make(SecretData, len(obj.Data))

	for k, v := range obj.Data {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf(
				"secret %s/%s: field %q: bad base64: %w",
				namespace,
				name,
				k,
				err,
			)
		}

		result[k] = decoded
	}

	return result, nil
}
