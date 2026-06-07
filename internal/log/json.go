// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package log

import "encoding/json"

type JSON struct{}

func (JSON) Format(msg *LogMsg) []byte {
	data, err := json.Marshal(msg)
	if err != nil {
		panic(err)
	}

	return data
}
