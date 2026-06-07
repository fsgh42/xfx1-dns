// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import "time"

type LogMsg struct {
	Level     LogLevel  `json:"level"`
	Msg       string    `json:"msg"`
	Component string    `json:"component,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Caller    string    `json:"caller"`
	Context   Ctx       `json:"context,omitempty"`
}
