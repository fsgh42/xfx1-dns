// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import (
	"encoding/json"
	"testing"
)

// Buffer backend captures output for testing
type Buffer struct {
	Data []byte
}

func (b *Buffer) Write(data []byte) {
	b.Data = data
}

func TestLoggerDebug(t *testing.T) {
	var buf Buffer
	logger := &logger[*Buffer, JSON]{
		backend:   &buf,
		level:     LogLevelDebug,
		component: "test",
	}

	logger.Debug("hello world")

	var msg LogMsg
	if err := json.Unmarshal(buf.Data, &msg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if msg.Level != LogLevelDebug {
		t.Errorf("expected level %s, got %s", LogLevelDebug, msg.Level)
	}

	if msg.Msg != "hello world" {
		t.Errorf("expected msg 'hello world', got %q", msg.Msg)
	}

	if msg.Component != "test" {
		t.Errorf("expected component 'test', got %q", msg.Component)
	}
}

func TestLoggerWithContext(t *testing.T) {
	var buf Buffer
	logger := &logger[*Buffer, JSON]{
		backend:   &buf,
		level:     LogLevelDebug,
		component: "test",
	}

	logger.Info("user action", Ctx{"user": "alice", "action": "login"})

	var msg LogMsg
	if err := json.Unmarshal(buf.Data, &msg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if msg.Context["user"] != "alice" {
		t.Errorf("expected user 'alice', got %v", msg.Context["user"])
	}

	if msg.Context["action"] != "login" {
		t.Errorf("expected action 'login', got %v", msg.Context["action"])
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	tests := []struct {
		name      string
		loggerLvl LogLevel
		msgLvl    string
		shouldLog bool
	}{
		{"debug at debug level", LogLevelDebug, "debug", true},
		{"info at debug level", LogLevelDebug, "info", true},
		{"error at debug level", LogLevelDebug, "error", true},
		{"debug at info level", LogLevelInfo, "debug", false},
		{"info at info level", LogLevelInfo, "info", true},
		{"error at info level", LogLevelInfo, "error", true},
		{"debug at error level", LogLevelError, "debug", false},
		{"info at error level", LogLevelError, "info", false},
		{"error at error level", LogLevelError, "error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf Buffer
			logger := &logger[*Buffer, JSON]{
				backend:   &buf,
				level:     tt.loggerLvl,
				component: "test",
			}

			buf.Data = nil

			switch tt.msgLvl {
			case "debug":
				logger.Debug("test")
			case "info":
				logger.Info("test")
			case "error":
				logger.Error("test")
			}

			logged := len(buf.Data) > 0
			if logged != tt.shouldLog {
				t.Errorf(
					"expected logged=%v, got logged=%v",
					tt.shouldLog,
					logged,
				)
			}
		})
	}
}
