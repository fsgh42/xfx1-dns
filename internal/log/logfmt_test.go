// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"strings"
	"testing"
)

func TestLogfmtFormatter(t *testing.T) {
	var buf Buffer
	logger := &logger[*Buffer, Logfmt]{
		backend:   &buf,
		level:     LogLevelDebug,
		component: "test",
	}

	logger.Info("hello", Ctx{"key": "value"})

	output := string(buf.Data)
	if !strings.Contains(output, "level=info") {
		t.Errorf("expected 'level=info' in output, got %q", output)
	}

	if !strings.Contains(output, "component=test") {
		t.Errorf("expected 'component=test' in output, got %q", output)
	}

	if !strings.Contains(output, `msg="hello"`) {
		t.Errorf("expected 'msg=\"hello\"' in output, got %q", output)
	}

	if !strings.Contains(output, "key=value") {
		t.Errorf("expected 'key=value' in output, got %q", output)
	}
}
