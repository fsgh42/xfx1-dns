// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package env

import (
	"fmt"
	"os"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s"
)

func KubeApiFromEnv() (string, error) {
	host := os.Getenv(k8s.EnvVarK8sApiHost)
	if host == "" {
		return "", fmt.Errorf(
			"%w: %s",
			k8s.ErrK8sApiBadEnv,
			k8s.EnvVarK8sApiHost,
		)
	}

	port := os.Getenv(k8s.EnvVarK8sApiPort)
	if port == "" {
		return "", fmt.Errorf(
			"%w: %s",
			k8s.ErrK8sApiBadEnv,
			k8s.EnvVarK8sApiPort,
		)
	}

	const proto = "https" // k8s API always speaks HTTPS in our use case
	k8sApiURL := fmt.Sprintf("%s://%s:%s", proto, host, port)

	return k8sApiURL, nil
}
