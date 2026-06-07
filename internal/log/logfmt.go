// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"fmt"
	"strings"
)

type Logfmt struct{}

func (Logfmt) Format(msg *LogMsg) []byte {
	var b strings.Builder

	fmt.Fprintf(
		&b,
		"time=%s ",
		msg.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
	)
	fmt.Fprintf(&b, "level=%s ", msg.Level)

	if msg.Component != "" {
		fmt.Fprintf(&b, "component=%s ", msg.Component)
	}

	fmt.Fprintf(&b, "caller=%s ", msg.Caller)
	fmt.Fprintf(&b, "msg=%q", msg.Msg)

	for _, k := range msg.Context.sortedKeys() {
		fmt.Fprintf(&b, " %s=%v", k, msg.Context[k])
	}

	return []byte(b.String())
}
