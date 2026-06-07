// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"fmt"
	"os"
)

// Console backend writes to stdout
type Console struct{}

func (Console) Write(data []byte) {
	fmt.Fprintln(os.Stdout, string(data))
}
