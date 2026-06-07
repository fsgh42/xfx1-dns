// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

const (
	red    = "\033[0;31m"
	green  = "\033[0;32m"
	yellow = "\033[1;33m"
	reset  = "\033[0m"
)

type result struct {
	label  string // DNSRecord CR name
	test   string // "plain-tcp", "plain-udp", "dnssec", "edns0", "doh", "dot"
	server string // target address
	pass   bool
	detail string // failure reason
}

func (r result) print() {
	if r.pass {
		fmt.Printf(
			"%sPASS%s [%s] %s @%s\n",
			green,
			reset,
			r.test,
			r.label,
			r.server,
		)
	} else {
		fmt.Printf("%sFAIL%s [%s] %s @%s — %s\n", red, reset, r.test, r.label, r.server, r.detail)
	}
}

func pass(label, test, server string) result {
	return result{label: label, test: test, server: server, pass: true}
}

func fail(label, test, server, detail string) result {
	return result{
		label:  label,
		test:   test,
		server: server,
		pass:   false,
		detail: detail,
	}
}

func info(msg string) {
	fmt.Printf("%sINFO%s %s\n", yellow, reset, msg)
}

// testOrder defines the print order across all test types.
func testOrder(test string) int {
	switch {
	case test == "plain-udp":
		return 0
	case strings.HasPrefix(test, "edns0"):
		return 1
	case test == "plain-tcp":
		return 2
	case test == "dnssec":
		return 3
	case test == "dnssec-nsec3":
		return 4
	case test == "dot":
		return 5
	case test == "doh":
		return 6
	default:
		return 7
	}
}

func printResults(results []result) int {
	slices.SortStableFunc(results, func(a, b result) int {
		if c := cmp.Compare(testOrder(a.test), testOrder(b.test)); c != 0 {
			return c
		}

		if c := cmp.Compare(a.label, b.label); c != 0 {
			return c
		}

		return cmp.Compare(a.server, b.server)
	})

	fails := 0

	for _, r := range results {
		r.print()

		if !r.pass {
			fails++
		}
	}

	return fails
}
