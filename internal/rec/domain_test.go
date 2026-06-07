// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewDomain(t *testing.T) {
	tests := []struct {
		input   string
		want    Domain
		wantErr bool
	}{
		{"example.com.", "example.com.", false},
		{
			"example.com",
			"example.com.",
			false,
		}, // auto-add trailing dot
		{"FOO.EXAMPLE.COM.", "foo.example.com.", false}, // lowercase
		{"FOO.EXAMPLE.COM", "foo.example.com.", false},
		{".", ".", false},
		{"", "", true},                       // empty
		{strings.Repeat("a", 256), "", true}, // too long
	}
	for _, tc := range tests {
		got, err := NewDomain(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NewDomain(%q): expected error, got nil", tc.input)
			}

			continue
		}

		if err != nil {
			t.Errorf("NewDomain(%q): unexpected error: %v", tc.input, err)
			continue
		}

		if got != tc.want {
			t.Errorf("NewDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestValidateFqdn_ErrorBranches(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"label too long", strings.Repeat("a", 64) + ".example.com."},
		{"empty non-terminal label", "foo..bar."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateFqdn(tc.input); err == nil {
				t.Errorf("validateFqdn(%q): expected error, got nil", tc.input)
			}
		})
	}
}

func TestCompareDomain(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"example.com.", "example.com.", 0},
		{"EXAMPLE.COM.", "example.com.", 0}, // case insensitive
		{"a.example.com.", "b.example.com.", -1},
		{"b.example.com.", "a.example.com.", 1},
		{"example.com.", "foo.example.com.", -1}, // parent < child
		{"foo.example.com.", "example.com.", 1},
	}
	for _, tc := range tests {
		a := Domain(tc.a)
		b := Domain(tc.b)
		got := CompareDomain(a, b)

		if got != tc.want {
			t.Errorf(
				"CompareDomain(%q, %q) = %d, want %d",
				tc.a,
				tc.b,
				got,
				tc.want,
			)
		}
	}
}

func TestDomainWrite(t *testing.T) {
	// "foo.example.com." → \x03foo\x07example\x03com\x00
	d := Domain("foo.example.com.")

	var buf bytes.Buffer

	if err := d.Write(&buf); err != nil {
		t.Fatal(err)
	}

	want := []byte{
		3,
		'f',
		'o',
		'o',
		7,
		'e',
		'x',
		'a',
		'm',
		'p',
		'l',
		'e',
		3,
		'c',
		'o',
		'm',
		0,
	}
	got := buf.Bytes()

	if string(got) != string(want) {
		t.Errorf("Domain.Write(%q) = %v, want %v", d, got, want)
	}
}

func TestDomainJSONRoundTrip(t *testing.T) {
	d := Domain("example.com.")

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}

	var d2 Domain
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatal(err)
	}

	if d != d2 {
		t.Errorf("JSON round-trip: got %q, want %q", d2, d)
	}
}

// FuzzNewDomain feeds arbitrary strings into the FQDN validator. Reachable from
// public clients via slave.handleDNS, which calls NewDomain on the QName
// extracted by query.New — and DNS labels can carry any octet, so this is the
// part of the validator that an attacker actually drives.
//
// Run with `task fuzz`. Under plain `go test` only the seed corpus runs.
func FuzzNewDomain(f *testing.F) {
	f.Add("example.com.")
	f.Add("example.com")
	f.Add(".")
	f.Add("")
	f.Add(strings.Repeat("a", 256))
	f.Add("foo..bar.")
	f.Add(strings.Repeat("a", 64) + ".example.com.")
	f.Add("\x00\xff\n.example.com.")

	f.Fuzz(func(t *testing.T, s string) {
		d, err := NewDomain(s)
		t.Logf("NewDomain(%q) = %q, err=%v", s, d, err)

		if err != nil {
			return
		}

		if len(d) == 0 {
			t.Fatalf("NewDomain(%q) returned empty domain with no error", s)
		}

		if d[len(d)-1] != '.' {
			t.Fatalf("NewDomain(%q) = %q, missing trailing dot", s, d)
		}

		if len(d) > 255 {
			t.Fatalf("NewDomain(%q) = %q, exceeds 255 octets", s, d)
		}
	})
}
