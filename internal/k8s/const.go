// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package k8s

import (
	"math"
	"time"
)

const (
	EnvVarK8sApiHost = "KUBERNETES_SERVICE_HOST"
	EnvVarK8sApiPort = "KUBERNETES_SERVICE_PORT"

	ApiTokenFile   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	ApiCaFile      = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	DefaultTimeout = 5 * time.Second

	// InvalidNodeidx is the "invalid" element of possible node index values
	InvalidNodeidx = math.MaxUint64

	// AnnotationNodeIndex contains the node enumeration index.
	// The node index is used for local subnet calculation
	// and establishing mesh communication.
	// Changed from label to annotation to avoid Talos kubelet reconciliation removing it.
	AnnotationNodeIndex = "dns.xfx1.de/node-idx"

	// AnnotationLocalIPs contains JSON array of local endpoint IPs.
	// Format: ["ip1", "ip2", ...]
	// Used for mesh discovery.
	AnnotationLocalIPs = "dns.xfx1.de/local-ips"

	// AnnotationWgPubKey contains base64-encoded WireGuard public key.
	// Used for mesh discovery.
	AnnotationWgPubKey = "dns.xfx1.de/wg-pubkey"

	// AnnotationIpamIndex contains the on-node IPAM allocation index.
	// Used for state recovery after daemon restart.
	AnnotationIpamIndex = "dns.xfx1.de/ipam-index"

	// AnnotationNetNS contains the network namespace path.
	// Used for state recovery after daemon restart.
	AnnotationNetNS = "dns.xfx1.de/netns"

	// AnnotationHeartbeat contains the time a node last reconciled it's local state.
	// Periodically updated, the associated events are used for mesh node reconciliation.
	AnnotationHeartbeat = "dns.xfx1.de/heartbeat"
)
