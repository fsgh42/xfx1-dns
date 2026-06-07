// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package crd

import (
	"encoding/json"
	"testing"
)

func TestDNSConfigSpecParse(t *testing.T) {
	raw := `{
		"global": {
			"zone": "example.com.",
			"logLevel": "info"
		},
		"master": {
			"slaveDiscoveryRecord": "slaves.example.com."
		},
		"slave": {
			"masterAddr": "master.example.com.:8080",
			"pollInterval": "60s"
		},
		"router": {
			"slaveDiscoveryRecord": "slaves.example.com.",
			"forwardTimeout": "2s",
			"doh": {
				"certFile": "/etc/tls/tls.crt",
				"keyFile": "/etc/tls/tls.key"
			}
		}
	}`

	var cfg DNSConfigSpec
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if cfg.Global.Zone != "example.com." {
		t.Errorf("Zone = %q, want %q", cfg.Global.Zone, "example.com.")
	}

	if cfg.Global.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.Global.LogLevel, "info")
	}

	if cfg.Master.SlaveDiscoveryRecord != "slaves.example.com." {
		t.Errorf("SlaveDiscoveryRecord = %q", cfg.Master.SlaveDiscoveryRecord)
	}

	if cfg.Slave.PollInterval != "60s" {
		t.Errorf("PollInterval = %q, want %q", cfg.Slave.PollInterval, "60s")
	}

	if cfg.Router.ForwardTimeout != "2s" {
		t.Errorf(
			"ForwardTimeout = %q, want %q",
			cfg.Router.ForwardTimeout,
			"2s",
		)
	}

	if cfg.Router.DoH.CertFile != "/etc/tls/tls.crt" {
		t.Errorf("CertFile = %q", cfg.Router.DoH.CertFile)
	}
}

func TestDNSConfigSpecMissingOptionalFields(t *testing.T) {
	// Minimal config — missing optional fields should use zero values without error.
	raw := `{"global": {"zone": "example.com."}}`

	var cfg DNSConfigSpec

	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if cfg.Slave.PollInterval != "" {
		t.Errorf("expected empty PollInterval, got %q", cfg.Slave.PollInterval)
	}
}
