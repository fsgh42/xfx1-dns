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
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/router"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/runtime"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/watch"
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

	logger := ilog.NewDefaultLogger("router", logLevel)

	runtime.LogBuildInfo(logger)

	k8sClient := k8sclient.NewDefaultK8sClient(10 * time.Second)
	ctx := context.Background()

	cfg := loadDNSConfig(ctx, k8sClient, namespace)

	if cfg.Router.ForwardTimeout != "" {
		if _, err := time.ParseDuration(cfg.Router.ForwardTimeout); err != nil {
			log.Fatalf(
				"invalid router.forwardTimeout %q: %v",
				cfg.Router.ForwardTimeout,
				err,
			)
		}
	}

	// Watch DNSConfig for changes; send new specs to cfgCh.
	cfgCh := make(chan crd.DNSConfigSpec, 1)

	go func() {
		watchParams, _ := api.ParamsFor[crd.DNSConfigSpec]()
		watchParams.Namespace = namespace
		watchParams.FieldSelector = []string{
			"metadata.name=" + crd.DNSConfigName,
		}

		cfgEvents := watch.Watch[crd.DNSConfigSpec](
			context.Background(),
			k8sClient,
			watchParams,
			1,
			logger,
			metrics.NewCounter("_", nil),
		)
		for ev := range cfgEvents {
			if ev.Type == watch.EventAdded {
				continue
			}
			cfgCh <- ev.Object.Spec
		}
	}()

	for {
		cancelCh := make(chan struct{})
		runtimeDone := make(chan struct{})
		certCh := make(chan struct{}, 1)
		reloadCh := make(chan struct {
			reason string
			cfg    crd.DNSConfigSpec
		}, 1)

		certCtx, cancelCertWatch := context.WithCancel(context.Background())
		go watchCertFiles(
			certCtx,
			cfg.Router.DoH.CertFile,
			cfg.Router.DoH.KeyFile,
			certCh,
			logger,
		)

		go func() {
			select {
			case newCfg := <-cfgCh:
				select {
				case reloadCh <- struct {
					reason string
					cfg    crd.DNSConfigSpec
				}{reason: reloadConfig, cfg: newCfg}:
				default:
				}

				close(cancelCh)
			case <-certCh:
				select {
				case reloadCh <- struct {
					reason string
					cfg    crd.DNSConfigSpec
				}{reason: reloadCert}:
				default:
				}

				close(cancelCh)
			case <-runtimeDone:
			}
		}()

		logger.Info(
			"starting router",
			ilog.Ctx{"slaves": cfg.Router.SlaveDiscoveryRecord},
		)

		if err := runtime.Run(router.New(cfg, logger),
			runtime.WithCancelChannel(cancelCh),
			runtime.WithHealthPort(8081),
			runtime.WithMetricsPort(9090),
			runtime.WithLogger(logger),
		); err != nil {
			log.Fatal(err.Error())
		}

		close(runtimeDone)
		cancelCertWatch()

		select {
		case reload := <-reloadCh:
			switch reload.reason {
			case reloadConfig:
				cfg = reload.cfg

				logger.Info("DNSConfig changed — router reloaded in-process")
			case reloadCert:
				logger.Info("TLS cert changed — router reloaded in-process")
			}
		default:
			return
		}
	}
}

const (
	reloadConfig = "config"
	reloadCert   = "cert"
)

func loadDNSConfig(
	ctx context.Context,
	k8sClient k8sclient.K8sClient,
	namespace string,
) crd.DNSConfigSpec {
	params, err := api.ParamsFor[crd.DNSConfigSpec]()
	if err != nil {
		log.Fatal("failed to get params for DNSConfigSpec: " + err.Error())
	}

	params.Namespace = namespace
	params.Name = crd.DNSConfigName

	objects, err := k8sclient.QueryApiWithParams[crd.DNSConfigSpec](
		ctx,
		k8sClient,
		params,
	)
	if err != nil {
		log.Fatal("failed to query DNSConfig CRD: " + err.Error())
	}

	if len(objects) == 0 {
		log.Fatal("DNSConfig CRD not found in namespace " + namespace)
	}

	cfg := objects[0].Spec
	if cfg.Global.Zone == "" {
		log.Fatal("DNSConfig.global.zone is not set")
	}

	return cfg
}
