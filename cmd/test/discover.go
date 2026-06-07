// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	k8sclient "git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
)

// discoverServers returns the list of DNS server addresses to test against.
// In internal mode: the configured ClusterIP service hostname.
// In external mode: all hostIPs (IPv4 + IPv6) from router pods.
func discoverServers(
	ctx context.Context,
	cfg *config,
	c k8sclient.K8sClient,
) ([]string, error) {
	if cfg.EndpointMode == "internal" {
		return []string{cfg.InternalSvc}, nil
	}

	return discoverRouterIPs(ctx, c, cfg.Namespace)
}

// podList is a minimal representation of the k8s PodList API response.
type podList struct {
	Items []struct {
		Status struct {
			HostIP  string `json:"hostIP"`
			HostIPs []struct {
				IP string `json:"ip"`
			} `json:"hostIPs"`
		} `json:"status"`
	} `json:"items"`
}

// discoverRouterIPs lists all router pod hostIPs (both IPv4 and IPv6) in namespace.
func discoverRouterIPs(
	ctx context.Context,
	c k8sclient.K8sClient,
	namespace string,
) ([]string, error) {
	p := &api.ApiRequestParams{
		Group:         "",
		Version:       "v1",
		ResourceType:  "pods",
		Namespace:     namespace,
		LabelSelector: []string{"app=xfx1-dns-router"},
	}

	resp, err := c.QueryApiRaw(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("list router pods: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list router pods: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pod list: %w", err)
	}

	var pl podList
	if err := json.Unmarshal(body, &pl); err != nil {
		return nil, fmt.Errorf("decode pod list: %w", err)
	}

	seen := make(map[string]bool)

	var servers []string

	for _, pod := range pl.Items {
		if len(pod.Status.HostIPs) > 0 {
			for _, h := range pod.Status.HostIPs {
				if h.IP != "" && !seen[h.IP] {
					seen[h.IP] = true

					servers = append(servers, h.IP)
				}
			}
		} else if pod.Status.HostIP != "" && !seen[pod.Status.HostIP] {
			seen[pod.Status.HostIP] = true

			servers = append(servers, pod.Status.HostIP)
		}
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf(
			"no router pods found in namespace %q",
			namespace,
		)
	}

	return servers, nil
}

// fetchTLSCert retrieves the tls.crt field from the named k8s Secret.
func fetchTLSCert(
	ctx context.Context,
	c k8sclient.K8sClient,
	namespace, secretName string,
) ([]byte, error) {
	data, err := k8sclient.GetSecret(ctx, c, namespace, secretName)
	if err != nil {
		return nil, err
	}

	cert, ok := data["tls.crt"]
	if !ok || len(cert) == 0 {
		return nil, fmt.Errorf("secret %q has no tls.crt field", secretName)
	}

	return cert, nil
}
