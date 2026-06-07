// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s"
)

type (
	// ApiRequestParams contains the information required for k8s API resource URIs.
	// docs: https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-uris
	ApiRequestParams struct {
		Group         string
		Version       string
		Namespace     string
		ResourceType  string
		Name          string
		Watch         bool
		LabelSelector []string
		FieldSelector []string
		FieldManager  string
	}
)

// K8sApiRequestParams formats the arguments set in the associated instance to a URL
// that can be used on the kubernetes API as described it's documentation:
// https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-uris
func (rp *ApiRequestParams) URL(apiURL string) (string, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("%w: %w", k8s.ErrUrlFormat, err)
	}

	// Build path segments
	var pathParts []string
	if rp.Group != "" {
		pathParts = append(pathParts, "apis", rp.Group)
	} else {
		pathParts = append(pathParts, "api")
	}

	if rp.Version == "" {
		return "", fmt.Errorf(
			"%w: Version can't be empty",
			k8s.ErrIllegalApiRequestParam,
		)
	} else {
		pathParts = append(pathParts, rp.Version)
	}

	if rp.Namespace != "" {
		pathParts = append(pathParts, "namespaces", rp.Namespace)
	}

	if rp.ResourceType == "" {
		return "", fmt.Errorf(
			"%w: ResourceType can't be empty",
			k8s.ErrIllegalApiRequestParam,
		)
	} else {
		pathParts = append(pathParts, rp.ResourceType)
	}

	if rp.Name != "" {
		pathParts = append(pathParts, rp.Name)
	}

	u.Path = path.Join(u.Path, path.Join(pathParts...))

	// Build query params
	q := u.Query()
	if rp.Watch {
		q.Set("watch", "true")
	}

	if len(rp.LabelSelector) > 0 {
		q.Set("labelSelector", strings.Join(rp.LabelSelector, ","))
	}

	if len(rp.FieldSelector) > 0 {
		q.Set("fieldSelector", strings.Join(rp.FieldSelector, ","))
	}

	if rp.FieldManager != "" {
		q.Set("fieldManager", rp.FieldManager)
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

// Clone returns a deep copy of the ApiRequestParams
func (rp *ApiRequestParams) Clone() *ApiRequestParams {
	clone := *rp
	if rp.LabelSelector != nil {
		clone.LabelSelector = make([]string, len(rp.LabelSelector))
		copy(clone.LabelSelector, rp.LabelSelector)
	}

	if rp.FieldSelector != nil {
		clone.FieldSelector = make([]string, len(rp.FieldSelector))
		copy(clone.FieldSelector, rp.FieldSelector)
	}

	return &clone
}
