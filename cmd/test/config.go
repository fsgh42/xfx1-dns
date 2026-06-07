// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	ilog "git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

type config struct {
	Namespace    string
	EndpointMode string // "internal" or "external"
	InternalSvc  string // hostname for internal mode
	DNSPort      int
	DoHPort      int
	DoTPort      int
	Timeout      time.Duration
	TLSInsecure  bool
	TLSSecret    string // k8s Secret name for router TLS cert
	Plain        bool
	DNSSEC       bool
	EDNS0        bool
	DoH          bool
	DoT          bool
	LogLevel     ilog.LogLevel
}

func configFromEnv() (*config, error) {
	ns := os.Getenv("NAMESPACE")
	if ns == "" {
		ns = "xfx1-dns"
	}

	mode := os.Getenv("ENDPOINT_MODE")
	if mode == "" {
		mode = "internal"
	}

	if mode != "internal" && mode != "external" {
		return nil, fmt.Errorf(
			"ENDPOINT_MODE must be 'internal' or 'external', got %q",
			mode,
		)
	}

	internalSvc := os.Getenv("INTERNAL_SVC")
	if internalSvc == "" {
		internalSvc = fmt.Sprintf("router.%s.svc.cluster.local", ns)
	}

	dnsPort, err := envInt("DNS_PORT", 53)
	if err != nil {
		return nil, err
	}

	dohPort, err := envInt("DOH_PORT", 443)
	if err != nil {
		return nil, err
	}

	dotPort, err := envInt("DOT_PORT", 853)
	if err != nil {
		return nil, err
	}

	timeoutStr := os.Getenv("TEST_TIMEOUT")
	if timeoutStr == "" {
		timeoutStr = "5s"
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, fmt.Errorf("TEST_TIMEOUT: %w", err)
	}

	tlsSecret := os.Getenv("TLS_SECRET")
	if tlsSecret == "" {
		tlsSecret = "xfx1-dns-router-tls"
	}

	// Default to INFO; other commands default to DEBUG via ReadLogLevelFromEnv.
	logLevel := ilog.LogLevelInfo
	if os.Getenv("LOG_LEVEL") != "" {
		logLevel, err = ilog.ReadLogLevelFromEnv()
		if err != nil {
			return nil, fmt.Errorf("LOG_LEVEL: %w", err)
		}
	}

	return &config{
		Namespace:    ns,
		EndpointMode: mode,
		InternalSvc:  internalSvc,
		DNSPort:      dnsPort,
		DoHPort:      dohPort,
		DoTPort:      dotPort,
		Timeout:      timeout,
		TLSInsecure:  envBool("TLS_INSECURE", false),
		TLSSecret:    tlsSecret,
		Plain:        envBool("PLAIN", true),
		DNSSEC:       envBool("DNSSEC", true),
		EDNS0:        envBool("EDNS0", true),
		DoH:          envBool("DOH", true),
		DoT:          envBool("DOT", true),
		LogLevel:     logLevel,
	}, nil
}

func envInt(name string, def int) (int, error) {
	s := os.Getenv(name)
	if s == "" {
		return def, nil
	}

	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envBool(name string, def bool) bool {
	s := os.Getenv(name)
	if s == "" {
		return def
	}

	return s == "1" || s == "true"
}
