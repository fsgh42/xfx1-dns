// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

// Null backend discards all messages
type Null struct{}

func (Null) Write([]byte) {}
