// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

type (
	// Backend is the constraint for log output backends
	Backend interface {
		Write([]byte)
	}

	// Logger is the interface consumers use
	Logger interface {
		Debug(msg string, ctx ...Ctx)
		Info(msg string, ctx ...Ctx)
		Error(msg string, ctx ...Ctx)
		Fatal(msg string, ctx ...Ctx)
	}

	// logger is the generic implementation
	logger[B Backend, F Formatter] struct {
		backend   B
		formatter F
		level     LogLevel
		component string
	}
)

func New[B Backend, F Formatter](component string, level ...LogLevel) Logger {
	var lvl LogLevel

	if len(level) > 0 {
		lvl = level[0]
	} else {
		lvl = LogLevelDefault
	}

	return &logger[B, F]{
		level:     lvl,
		component: component,
	}
}

// NewDefaultLogger creates a logger with the default backend (Console) and formatter (Logfmt).
// Change this function to switch the default logger configuration in one place.
func NewDefaultLogger(component string, level ...LogLevel) Logger {
	return New[Console, Logfmt](component, level...)
}
