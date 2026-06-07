// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package crd

import (
	"git.xfx1.de/infrastructure/xfx1-dns/internal/k8s/api"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

const (
	DNSRecordGroup        = "xfx1.de"
	DNSRecordVersion      = "v2"
	DNSRecordKind         = "DNSRecord"
	DNSRecordResourceType = "dnsrecords"

	DNSConfigGroup        = "xfx1.de"
	DNSConfigVersion      = "v2"
	DNSConfigKind         = "DNSConfig"
	DNSConfigResourceType = "dnsconfigs"
	// DNSConfigName is the fixed name of the single DNSConfig CRD per namespace.
	DNSConfigName = "xfx1-dns"
)

func init() {
	// DNSRecord spec is rec.RR directly — no wrapper needed.
	api.RegisterSpec[rec.RR](&api.ResourceMeta{
		Group:        DNSRecordGroup,
		Version:      DNSRecordVersion,
		Kind:         DNSRecordKind,
		ResourceType: DNSRecordResourceType,
	})

	api.RegisterSpec[DNSConfigSpec](&api.ResourceMeta{
		Group:        DNSConfigGroup,
		Version:      DNSConfigVersion,
		Kind:         DNSConfigKind,
		ResourceType: DNSConfigResourceType,
	})
}

// DNSConfigSpec is the spec of the DNSConfig CRD.
type DNSConfigSpec struct {
	Global  GlobalConfig  `json:"global"`
	Master  MasterConfig  `json:"master"`
	Slave   SlaveConfig   `json:"slave"`
	Router  RouterConfig  `json:"router"`
	DNSSEC  DNSSECConfig  `json:"dnssec"`
	RFC2136 RFC2136Config `json:"rfc2136"`
}

// RFC2136Config holds settings for the RFC 2136 DNS UPDATE gateway.
type RFC2136Config struct {
	// ListenPort is the UDP/TCP port to listen on for DNS UPDATE messages. Default: 5053.
	ListenPort int `json:"listenPort"`
	// TSIGSecret is the name of the k8s Secret containing the TSIG key.
	TSIGSecret string `json:"tsigSecret"`
	// TSIGName is the TSIG key name (e.g. "acme-key.").
	TSIGName string `json:"tsigName"`
}

// DNSSECConfig holds DNSSEC signing configuration.
type DNSSECConfig struct {
	// Keys lists the Secrets containing signing keys.
	// If empty, DNSSEC is disabled.
	Keys []KeyRef `json:"keys"`

	// RRSIGValidityWindow is the duration for which newly produced RRSIG
	// records are valid (e.g. "168h" for 7 days). Defaults to 168h.
	// The master re-signs every 24 hours, so set this to at least 48h to
	// ensure there is always headroom before expiry.
	RRSIGValidityWindow string `json:"rrSigValidityWindow,omitempty"`
}

// KeyRef references a k8s Secret that contains a signing key pair.
type KeyRef struct {
	SecretRef string `json:"secretRef"` // name of k8s Secret in the deployment namespace
}

// GlobalConfig holds settings shared across all components.
type GlobalConfig struct {
	// Zone is the authoritative zone FQDN, e.g. "example.com.".
	Zone rec.Domain `json:"zone"`
	// LogLevel controls verbosity: "debug", "info", or "error".
	LogLevel string `json:"logLevel"`
}

// MasterConfig holds settings for the master component.
type MasterConfig struct {
	// SlaveDiscoveryRecord is the DNS name (headless Service FQDN) resolved to find slave IPs.
	SlaveDiscoveryRecord string `json:"slaveDiscoveryRecord"`
	// ResignInterval is how often DNSSEC records are re-signed. Go duration, default "24h".
	ResignInterval string `json:"resignInterval"`
	// MaxRecords is the maximum number of user records (excluding DNSSEC-synthesised
	// records) accepted in a single DB rebuild. Rebuilds that exceed this limit are
	// rejected: the error metric is incremented, the error is logged, and the
	// previous DB remains live. 0 uses the default of 100 000.
	MaxRecords int `json:"maxRecords,omitempty"`
}

// SlaveConfig holds settings for the slave component.
type SlaveConfig struct {
	// MasterAddr is the HTTP address of the master, e.g. "master.ns.svc.cluster.local.:8080".
	MasterAddr string `json:"masterAddr"`
	// PollInterval is how often the slave polls the master for DB updates. Go duration, e.g. "60s".
	PollInterval string `json:"pollInterval"`
	// ListenPort is the UDP/TCP port to listen on for DNS queries. Default: 5353.
	// Use 53 only if NET_BIND_SERVICE is granted; 5353 works rootless with hostPort NAT.
	ListenPort int `json:"listenPort,omitempty"`
	// SnapshotLocation is the path to a file where the slave persists the last-received database.
	// On startup the slave loads this file before attempting to poll the master, so it can serve
	// DNS immediately even if the master (or the k8s API server) is temporarily unavailable.
	// Requires a volume that survives pod restarts (hostPath or PVC); emptyDir is useless here.
	// Optional; leave empty to disable.
	SnapshotLocation string `json:"snapshotLocation,omitempty"`
}

// RouterConfig holds settings for the router component.
type RouterConfig struct {
	// SlaveDiscoveryRecord is the DNS name resolved on every query to find current slave IPs.
	SlaveDiscoveryRecord string `json:"slaveDiscoveryRecord"`
	// ForwardTimeout is the per-query deadline for slave responses. Go duration, e.g. "2s".
	ForwardTimeout string `json:"forwardTimeout"`
	// ListenPort is the UDP/TCP port the router listens on for DNS queries. Default: 5353.
	// Use 53 only if NET_BIND_SERVICE is granted; 5353 works rootless with hostPort NAT.
	ListenPort int `json:"listenPort,omitempty"`
	// DoHPort is the port the router listens on for DNS-over-HTTPS. Default: 8443.
	DoHPort int `json:"dohPort,omitempty"`
	// DoTPort is the port the router listens on for DNS-over-TLS. Default: 8853.
	DoTPort int `json:"dotPort,omitempty"`
	// SlavePort is the port slaves listen on for DNS queries. Must match slave.listenPort. Default: 5353.
	SlavePort int `json:"slavePort,omitempty"`
	// DoH holds TLS certificate paths for the DNS-over-HTTPS listener on port 443.
	DoH        DoHConfig        `json:"doh"`
	RateLimits RateLimitsConfig `json:"rateLimits,omitempty"`
	// MaxConnections bounds the number of concurrent TCP and DoH connections
	// accepted by the router. Zero uses the default of 10 000 per protocol.
	// Over-cap requests are rejected immediately: TCP closes without response,
	// DoH returns HTTP 503. UDP is connectionless and not capped.
	MaxConnections MaxConnectionsConfig `json:"maxConnections,omitempty"`
}

// MaxConnectionsConfig caps concurrent client connections per protocol.
type MaxConnectionsConfig struct {
	// TCP is the maximum number of concurrent client TCP (port 53) connections. 0 uses the default of 10 000.
	TCP int `json:"tcp,omitempty"`
	// DoH is the maximum number of concurrent in-flight DoH (port 443) requests. 0 uses the default of 10 000.
	DoH int `json:"doh,omitempty"`
	// DoT is the maximum number of concurrent DoT (port 853) connections. 0 uses the default of 10 000.
	DoT int `json:"dot,omitempty"`
}

// RateLimitsConfig groups per-protocol rate limit settings.
type RateLimitsConfig struct {
	UDP RateLimitConfig `json:"udp,omitempty"`
	TCP RateLimitConfig `json:"tcp,omitempty"`
	DoH RateLimitConfig `json:"doh,omitempty"`
	DoT RateLimitConfig `json:"dot,omitempty"`
	// Allowlist is a list of CIDR prefixes whose queries bypass rate limiting
	// on all four protocols. Intended for loopback and trusted internal ranges.
	// Empty (unset) applies sane defaults for all non-globally-routable ranges:
	// loopback, RFC 1918, IPv4/IPv6 link-local, CGNAT, IPv6 ULA. To disable
	// bypass entirely, set a non-matching CIDR (e.g. ["255.255.255.255/32"]).
	// Invalid CIDRs are logged and skipped at startup; they do not fail startup.
	Allowlist []string `json:"allowlist,omitempty"`
}

// RateLimitConfig configures rate limiting for one protocol at the router.
// Rate limiting is applied per source /24 (IPv4) or /48 (IPv6) prefix.
type RateLimitConfig struct {
	// Enabled activates rate limiting for this protocol. All other fields are ignored when false.
	Enabled bool `json:"enabled"`
	// BurstSize is the maximum token accumulation per prefix (burst allowance). Default: 200.
	BurstSize int `json:"burstSize,omitempty"`
	// RatePerSec is the sustained query rate per prefix in queries/second. Default: 50.
	RatePerSec float64 `json:"ratePerSec,omitempty"`
	// SlipRatio: every N-th dropped UDP query sends a TC=1 hint. UDP only; ignored for TCP/DoH.
	SlipRatio int `json:"slipRatio,omitempty"`
	// MaxBuckets caps the number of tracked source prefixes (0 = uncapped).
	// Defaults: UDP 500 000, TCP/DoH 100 000.
	MaxBuckets int `json:"maxBuckets,omitempty"`
	// MaxAge is how long a bucket is retained before normal GC evicts it.
	// Go duration string, e.g. "5m". Default: 5m.
	MaxAge string `json:"maxAge,omitempty"`
}

// DoHConfig holds TLS certificate paths for DNS-over-HTTPS.
type DoHConfig struct {
	// CertFile is the path to the TLS certificate PEM file inside the pod.
	CertFile string `json:"certFile"`
	// KeyFile is the path to the TLS private key PEM file inside the pod.
	KeyFile string `json:"keyFile"`
}
