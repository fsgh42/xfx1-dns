// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNameTooLong        = errors.New("domain name length exceeds 255 octets")
	ErrLabelTooLong       = errors.New("label length exceeds 63 octets")
	ErrIllegalLabel       = errors.New("illegal label")
	ErrMissingTrailingDot = errors.New("domain name is missing a trailing dot")
)

// Domain is a fully-qualified DNS name with a trailing dot.
// e.g. "example.com." or "foo.example.com."
// Always stored and compared in lower case.
type Domain string

// NewDomain validates, lowercases, and ensures a trailing dot on the given name.
func NewDomain(s string) (Domain, error) {
	// auto-add trailing dot if absent
	if len(s) > 0 && s[len(s)-1] != '.' {
		s = s + "."
	}

	s = strings.ToLower(s)
	if err := validateFqdn(s); err != nil {
		return "", err
	}

	return Domain(s), nil
}

func validateFqdn(name string) error {
	if name == "." {
		return nil
	}

	if len(name) == 0 {
		return fmt.Errorf("%w: empty string", ErrMissingTrailingDot)
	}

	if name[len(name)-1] != '.' {
		return fmt.Errorf("%w: %s", ErrMissingTrailingDot, name)
	}

	if len(name) > 255 {
		return fmt.Errorf("%w: %s", ErrNameTooLong, name)
	}

	labels := strings.Split(name, ".")
	for idx, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("%w: %q", ErrLabelTooLong, label)
		}

		if len(label) < 1 {
			// last element after trailing dot split is always empty — ignore it
			if idx < len(labels)-1 {
				return fmt.Errorf("%w: %q", ErrIllegalLabel, label)
			}
		}
	}

	return nil
}

func (d Domain) String() string {
	return string(d)
}

// Write writes the DNS wire format (label encoding) to buf.
// e.g. "foo.example.com." → \x03foo\x07example\x03com\x00
func (d Domain) Write(buf *bytes.Buffer) error {
	labels := domainLabels(string(d))

	var data []byte

	for _, label := range labels {
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}

	data = append(data, byte(0))

	return binary.Write(buf, binary.BigEndian, data)
}

// domainLabels returns the non-empty labels of an FQDN.
// Assumes name ends with a dot.
func domainLabels(name string) []string {
	parts := strings.Split(name, ".")
	return parts[:len(parts)-1]
}

// CompareDomain performs a case-insensitive DNS canonical order comparison.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func CompareDomain(a, b Domain) int {
	al := strings.ToLower(string(a))
	bl := strings.ToLower(string(b))

	if al == bl {
		return 0
	}

	aLabels := domainLabels(al)
	bLabels := domainLabels(bl)

	commonLabelCount := 0

	for idx := 0; idx < len(aLabels); idx++ {
		thisIdx := len(aLabels) - 1 - idx

		otherIdx := len(bLabels) - 1 - idx
		if otherIdx < 0 {
			break
		}

		if aLabels[thisIdx] == bLabels[otherIdx] {
			commonLabelCount++
		} else {
			break
		}
	}

	aCount := len(aLabels)
	bCount := len(bLabels)

	if aCount == commonLabelCount && bCount > commonLabelCount {
		return -1
	}

	if bCount == commonLabelCount && aCount > commonLabelCount {
		return 1
	}

	aRest := aLabels[aCount-commonLabelCount-1]
	bRest := bLabels[bCount-commonLabelCount-1]

	return strings.Compare(aRest, bRest)
}

func (d Domain) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(d))
}

func (d *Domain) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}

	parsed, err := NewDomain(name)
	if err != nil {
		return err
	}

	*d = parsed

	return nil
}
