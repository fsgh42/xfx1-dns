// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func (l *logger[B, F]) log(level LogLevel, msg string, ctx []Ctx) {
	if level < l.level {
		return
	}

	m := &LogMsg{
		Level:     level,
		Msg:       msg,
		Component: l.component,
		Timestamp: time.Now(),
		Context:   mergeCtx(ctx),
	}

	pc, file, line, ok := runtime.Caller(2)
	if !ok {
		m.Caller = "n/a"
	} else {
		fn := runtime.FuncForPC(pc)
		m.Caller = fmt.Sprintf("%s:%d/%s", filepath.Base(file), line, fn.Name())
	}

	l.backend.Write(l.formatter.Format(m))
}

func (l *logger[B, F]) Debug(
	msg string,
	ctx ...Ctx,
) {
	l.log(LogLevelDebug, msg, ctx)
}

func (l *logger[B, F]) Info(
	msg string,
	ctx ...Ctx,
) {
	l.log(LogLevelInfo, msg, ctx)
}

func (l *logger[B, F]) Error(
	msg string,
	ctx ...Ctx,
) {
	l.log(LogLevelError, msg, ctx)
}

// Fatal logs an error message and immediately exits the process with status code 1.
// WARNING: This function calls os.Exit(1) directly, which means:
//   - Deferred functions will NOT be executed
//   - Resources may not be cleaned up properly
//   - Open files may not be flushed
//
// Use Fatal only for unrecoverable errors during initialization or startup.
// For recoverable errors during runtime, use Error() and return errors up the call stack.
func (l *logger[B, F]) Fatal(msg string, ctx ...Ctx) {
	l.log(LogLevelError, msg, ctx)
	os.Exit(1)
}
