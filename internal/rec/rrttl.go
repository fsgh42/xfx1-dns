// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

// RRttl is the TTL of a DNS resource record (seconds).
type RRttl uint32

// DefaultTTL is the default TTL applied to new RRs when no explicit TTL is set.
const DefaultTTL RRttl = 300
