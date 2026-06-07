// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rfc2136

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const maxCRNameLen = 253

// CRName computes the DNSRecord CR metadata.name for a given source, rrtype,
// FQDN, and canonical RDATA bytes (from opts.Payload()).
//
// Format: <source>-<rrtype>-<sanitized-name>-<hash8>
//
// sanitized-name: FQDN lowercased, trailing dot stripped, dots replaced by hyphens.
// hash8: first 8 hex chars of SHA-256 of rdataBytes.
//
// Returns an error if the computed name exceeds 253 characters.
func CRName(source, rrtype, fqdn string, rdataBytes []byte) (string, error) {
	sanitized := sanitizeFQDN(fqdn)
	hash := rdataHash(rdataBytes)

	name := fmt.Sprintf(
		"%s-%s-%s-%s",
		source,
		strings.ToLower(rrtype),
		sanitized,
		hash,
	)
	if len(name) > maxCRNameLen {
		return "", fmt.Errorf(
			"CR name overflow (%d chars): source=%s rrtype=%s fqdn=%s",
			len(name),
			source,
			rrtype,
			fqdn,
		)
	}

	return name, nil
}

// sanitizeFQDN converts an FQDN to a k8s-safe name component:
// lowercase, trailing dot stripped, dots and underscores replaced by hyphens,
// leading hyphens stripped (e.g. "_acme-challenge" → "acme-challenge").
func sanitizeFQDN(fqdn string) string {
	s := strings.ToLower(fqdn)
	s = strings.TrimSuffix(s, ".")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.TrimLeft(s, "-")

	return s
}

// rdataHash returns the first 8 hex characters of SHA-256(data).
func rdataHash(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])[:8]
}
