// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log"
	"os"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	k8sclient "git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	ilog "git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rfc2136"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/runtime"
)

func main() {
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		log.Fatal("NAMESPACE env var is not set")
	}

	logLevel, err := ilog.ReadLogLevelFromEnv()
	if err != nil {
		log.Fatal("invalid LOG_LEVEL: " + err.Error())
	}

	logger := ilog.NewDefaultLogger("rfc2136", logLevel)

	runtime.LogBuildInfo(logger)

	k8sClient := k8sclient.NewDefaultK8sClient(10 * time.Second)
	ctx := context.Background()

	// Load DNSConfig
	params, err := api.ParamsFor[crd.DNSConfigSpec]()
	if err != nil {
		log.Fatal("ParamsFor DNSConfigSpec: " + err.Error())
	}

	params.Namespace = namespace
	params.Name = crd.DNSConfigName

	objects, err := k8sclient.QueryApiWithParams[crd.DNSConfigSpec](
		ctx,
		k8sClient,
		params,
	)
	if err != nil {
		log.Fatal("query DNSConfig: " + err.Error())
	}

	if len(objects) == 0 {
		log.Fatal("DNSConfig not found in namespace " + namespace)
	}

	cfg := objects[0].Spec
	if cfg.Global.Zone == "" {
		log.Fatal("DNSConfig.global.zone is not set")
	}

	if cfg.RFC2136.TSIGSecret == "" {
		log.Fatal("DNSConfig.rfc2136.tsigSecret is not set")
	}

	gw := rfc2136.New(cfg, namespace, k8sClient, logger)

	if err := runtime.Run(gw,
		runtime.WithHealthPort(8081),
		runtime.WithMetricsPort(9090),
		runtime.WithLogger(logger),
	); err != nil {
		log.Fatal(err.Error())
	}
}
