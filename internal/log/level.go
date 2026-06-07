// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelError
)

var (
	LogLevelDefault    = readLogLevelFromEnv()
	ErrInvalidLogLevel = errors.New("invalid log level")

	levelNames = map[LogLevel]string{
		LogLevelDebug: "debug",
		LogLevelInfo:  "info",
		LogLevelError: "error",
	}

	levelFromName = map[string]LogLevel{
		"debug": LogLevelDebug,
		"info":  LogLevelInfo,
		"error": LogLevelError,
	}
)

func (l LogLevel) String() string {
	if name, ok := levelNames[l]; ok {
		return name
	}

	return fmt.Sprintf("unknown(%d)", l)
}

func ReadLogLevelFromEnv() (LogLevel, error) {
	ll := os.Getenv("LOG_LEVEL")
	if ll == "" {
		return LogLevelDebug, nil
	}

	ll = strings.ToLower(ll)
	if level, ok := levelFromName[ll]; ok {
		return level, nil
	}

	return 0, fmt.Errorf("%w: %s", ErrInvalidLogLevel, ll)
}

// readLogLevelFromEnv reads the log level from env vars.
// panics on any error encountered.
func readLogLevelFromEnv() LogLevel {
	ll, err := ReadLogLevelFromEnv()
	if err != nil {
		panic(err)
	}

	return ll
}
