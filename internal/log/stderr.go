// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"fmt"
	"os"
)

// Stderr backend writes to stderr
type Stderr struct{}

func (Stderr) Write(data []byte) {
	fmt.Fprintln(os.Stderr, string(data))
}
