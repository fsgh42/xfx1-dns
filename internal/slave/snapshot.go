// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
)

// ErrSnapshotCorrupt is returned by parseSnapshot when the snapshot bytes
// cannot be deserialised into a DB. The underlying JSON error is intentionally
// not wrapped to prevent database field values from appearing in log output.
var ErrSnapshotCorrupt = errors.New("corrupt snapshot")

// parseSnapshot deserialises a DB from raw bytes.
// Returns ErrSnapshotCorrupt on any decode failure.
func parseSnapshot(data []byte) (*db.DB, error) {
	var d db.DB
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, ErrSnapshotCorrupt
	}

	return &d, nil
}

// encodeSnapshot serialises d to JSON bytes.
func encodeSnapshot(d *db.DB) ([]byte, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	return data, nil
}

// loadSnapshot reads a file and calls parseSnapshot.
func loadSnapshot(path string) (*db.DB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseSnapshot(data)
}

// saveSnapshot encodes d and atomically writes it to path via a temp-file
// rename, so a crash mid-write never leaves a corrupt file.
func saveSnapshot(path string, d *db.DB) error {
	data, err := encodeSnapshot(d)
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}
