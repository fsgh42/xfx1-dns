// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

// EDNSDOBit is the DO (DNSSEC OK) bit in the EDNS flags word (RFC 4035 §3.2.1).
// Clients set this bit to signal they can handle DNSSEC records in responses.
const EDNSDOBit uint16 = 0x8000

const dnskeyTTL = 3600
