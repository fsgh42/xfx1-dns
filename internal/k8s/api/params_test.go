// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/url"
	"testing"
)

func TestFormatApiURL(t *testing.T) {
	apiURL := "https://kubernetes.default.svc.cluster.local:443"

	testCases := []struct {
		testName string
		params   *ApiRequestParams
		expected string
	}{
		{
			testName: "allNamespaces",
			params: &ApiRequestParams{
				Version:      "v1",
				ResourceType: "namespaces",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces",
		},
		{
			testName: "allPods",
			params: &ApiRequestParams{
				Version:      "v1",
				ResourceType: "pods",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/pods",
		},
		{
			testName: "allPodsNamespace",
			params: &ApiRequestParams{
				Version:      "v1",
				ResourceType: "pods",
				Namespace:    "default",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/pods",
		},
		{
			testName: "allDeployments",
			params: &ApiRequestParams{
				Group:        "apps",
				Version:      "v1",
				ResourceType: "deployments",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/apis/apps/v1/deployments",
		},
		{
			testName: "allDeploymentsNamespace",
			params: &ApiRequestParams{
				Group:        "apps",
				Version:      "v1",
				ResourceType: "deployments",
				Namespace:    "default",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/apis/apps/v1/namespaces/default/deployments",
		},
		{
			testName: "specificDeploymentNamespace",
			params: &ApiRequestParams{
				Group:        "apps",
				Version:      "v1",
				ResourceType: "deployments",
				Namespace:    "default",
				Name:         "test",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/apis/apps/v1/namespaces/default/deployments/test",
		},
		// with watch
		{
			testName: "allNamespaces",
			params: &ApiRequestParams{
				Version:      "v1",
				ResourceType: "namespaces",
				Watch:        true,
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces?watch=true",
		},
		{
			testName: "allPods",
			params: &ApiRequestParams{
				Version:      "v1",
				ResourceType: "pods",
				Watch:        true,
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/pods?watch=true",
		},
		{
			testName: "allPodsNamespace",
			params: &ApiRequestParams{
				Version:      "v1",
				ResourceType: "pods",
				Namespace:    "default",
				Watch:        true,
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/pods?watch=true",
		},
		{
			testName: "allDeployments",
			params: &ApiRequestParams{
				Group:        "apps",
				Version:      "v1",
				ResourceType: "deployments",
				Watch:        true,
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/apis/apps/v1/deployments?watch=true",
		},
		{
			testName: "allDeploymentsNamespace",
			params: &ApiRequestParams{
				Group:        "apps",
				Version:      "v1",
				ResourceType: "deployments",
				Namespace:    "default",
				Watch:        true,
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/apis/apps/v1/namespaces/default/deployments?watch=true",
		},
		{
			testName: "specificDeploymentNamespace",
			params: &ApiRequestParams{
				Group:        "apps",
				Version:      "v1",
				ResourceType: "deployments",
				Namespace:    "default",
				Name:         "test",
				Watch:        true,
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/apis/apps/v1/namespaces/default/deployments/test?watch=true",
		},
		// with labelFilters
		{
			testName: "LabelFilter",
			params: &ApiRequestParams{
				Version:       "v1",
				ResourceType:  "namespaces",
				LabelSelector: []string{"foo=test1"},
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces?labelSelector=foo=test1",
		},
		{
			testName: "LabelFilter",
			params: &ApiRequestParams{
				Version:       "v1",
				ResourceType:  "namespaces",
				LabelSelector: []string{"foo=test1", "bar=test2"},
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces?labelSelector=foo=test1,bar=test2",
		},
		{
			testName: "LabelFilter",
			params: &ApiRequestParams{
				Version:       "v1",
				ResourceType:  "namespaces",
				LabelSelector: []string{"foo=test1", "bar=test2", "!baz"},
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces?labelSelector=foo=test1,bar=test2,!baz",
		},
		// with fieldManager
		{
			testName: "fieldManager",
			params: &ApiRequestParams{
				Version:      "v1",
				ResourceType: "pods",
				Namespace:    "default",
				Name:         "mypod",
				FieldManager: "test",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/pods/mypod?fieldManager=test",
		},
		// combine query paramters
		{
			testName: "fieldManager",
			params: &ApiRequestParams{
				Version:       "v1",
				ResourceType:  "pods",
				Namespace:     "default",
				Name:          "mypod",
				Watch:         true,
				LabelSelector: []string{"foo=bar", "baz=bam"},
				FieldManager:  "test",
			},
			expected: "https://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/pods/mypod?watch=true&labelSelector=foo=bar,baz=bam&fieldManager=test",
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.testName,
			func(t *testing.T) {
				actual, err := tc.params.URL(apiURL)
				if err != nil {
					t.Fatal(err)
				}

				expected, err := url.Parse(tc.expected)
				if err != nil {
					t.Fatal(err)
				}

				got, err := url.Parse(actual)
				if err != nil {
					t.Fatal(err)
				}

				// Compare scheme, host, path
				if expected.Scheme != got.Scheme || expected.Host != got.Host ||
					expected.Path != got.Path {
					t.Errorf("path mismatch: wanted %s://%s%s, got %s://%s%s",
						expected.Scheme, expected.Host, expected.Path,
						got.Scheme, got.Host, got.Path)
				}

				// Compare query params (order-independent, decoded)
				expectedQ := expected.Query()
				gotQ := got.Query()

				if len(expectedQ) != len(gotQ) {
					t.Errorf(
						"query param count mismatch: wanted %d, got %d",
						len(expectedQ),
						len(gotQ),
					)
				}

				for k, v := range expectedQ {
					if gotV, ok := gotQ[k]; !ok {
						t.Errorf("missing query param: %s", k)
					} else if len(v) != len(gotV) || v[0] != gotV[0] {
						t.Errorf("query param %s: wanted %v, got %v", k, v, gotV)
					}
				}
			},
		)
	}
}
