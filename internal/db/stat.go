// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package db

type (
	DBStats struct {
		RRCount int
	}
)

func (db *DB) RRCount() int {
	return db.count
}
