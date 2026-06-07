// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"fmt"
	"slices"
	"strings"
)

type (
	Labels map[string]string
)

// string returns the labels formatted for prometheus text format
func (lbs Labels) string(extra Labels) string {
	if len(lbs)+len(extra) == 0 {
		return ""
	}

	t := []string{}

	for k, v := range lbs {
		t = append(t, fmt.Sprintf(`%s="%s"`, k, v))
	}

	for k, v := range extra {
		t = append(t, fmt.Sprintf(`%s="%s"`, k, v))
	}

	// labels is small - so for now we don't mind sorting on each call
	slices.Sort(t)

	return fmt.Sprintf("{%s}", strings.Join(t, ","))
}

func (lbs Labels) String() string {
	return lbs.string(nil)
}

func (lbs Labels) StringWithExtra(extra Labels) string {
	return lbs.string(extra)
}
