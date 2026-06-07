// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crd"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	k8sclient "git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/client"
	ilog "git.xfx1.de/infrastructure/xfx1-dns/internal/log"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/master"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/metrics"
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

	logger := ilog.NewDefaultLogger("master", logLevel)

	runtime.LogBuildInfo(logger)

	k8sClient := k8sclient.NewDefaultK8sClient(10 * time.Second)
	ctx := context.Background()

	cfg := loadDNSConfig(ctx, k8sClient, namespace)
	if err := validateConfig(cfg); err != nil {
		log.Fatal(err.Error())
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
		reloadCh := make(chan crd.DNSConfigSpec, 1)

		// Bridge: when a new config arrives, trigger a clean shutdown so the
		// loop can start a fresh Master without restarting the pod.
		go func() {
			select {
			case newCfg := <-cfgCh:
				select {
				case reloadCh <- newCfg:
				default:
				}

				close(cancelCh)
			case <-runtimeDone:
				// runtime exited for another reason (SIGTERM, error); just exit.
				return
			}
		}()

		logger.Info(fmt.Sprintf("starting master for zone %s", cfg.Global.Zone))

		if err := runtime.Run(master.New(cfg, namespace, k8sClient, logger),
			runtime.WithCancelChannel(cancelCh),
			runtime.WithHealthPort(8081),
			runtime.WithMetricsPort(9090),
			runtime.WithLogger(logger),
		); err != nil {
			log.Fatal(err.Error())
		}

		close(runtimeDone)

		select {
		case pendingCfg := <-reloadCh:
			cfg = pendingCfg

			logger.Info("DNSConfig changed — master reloaded in-process")
		default:
			return // clean termination (SIGTERM/SIGINT)
		}
	}
}

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

func validateConfig(cfg crd.DNSConfigSpec) error {
	if cfg.Slave.PollInterval != "" {
		if _, err := parseDuration(cfg.Slave.PollInterval); err != nil {
			return fmt.Errorf(
				"invalid slave.pollInterval %q: %w",
				cfg.Slave.PollInterval,
				err,
			)
		}
	}

	if cfg.Router.ForwardTimeout != "" {
		if _, err := parseDuration(cfg.Router.ForwardTimeout); err != nil {
			return fmt.Errorf(
				"invalid router.forwardTimeout %q: %w",
				cfg.Router.ForwardTimeout,
				err,
			)
		}
	}

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
