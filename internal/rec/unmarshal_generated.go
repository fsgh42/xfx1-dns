// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

// Code generated — DO NOT EDIT.

package rec

import (
	"encoding/json"
	"fmt"
)

// rroptsUnmarshalJSON dispatches JSON unmarshalling to the correct concrete RRopts type.
func rroptsUnmarshalJSON(rrtype RRtype, data json.RawMessage) (RRopts, error) {
	switch rrtype {
	case TypeA:
		var opts RRoptsA
		return &opts, json.Unmarshal(data, &opts)
	case TypeAAAA:
		var opts RRoptsAAAA
		return &opts, json.Unmarshal(data, &opts)
	case TypeNS:
		var opts RRoptsNS
		return &opts, json.Unmarshal(data, &opts)
	case TypeCNAME:
		var opts RRoptsCNAME
		return &opts, json.Unmarshal(data, &opts)
	case TypeSOA:
		var opts RRoptsSOA
		return &opts, json.Unmarshal(data, &opts)
	case TypePTR:
		var opts RRoptsPTR
		return &opts, json.Unmarshal(data, &opts)
	case TypeMX:
		var opts RRoptsMX
		return &opts, json.Unmarshal(data, &opts)
	case TypeTXT:
		var opts RRoptsTXT
		return &opts, json.Unmarshal(data, &opts)
	case TypeSRV:
		var opts RRoptsSRV
		return &opts, json.Unmarshal(data, &opts)
	case TypeCAA:
		var opts RRoptsCAA
		return &opts, json.Unmarshal(data, &opts)
	case TypeRRSIG:
		var opts RRoptsRRSIG
		return &opts, json.Unmarshal(data, &opts)
	case TypeDNSKEY:
		var opts RRoptsDNSKEY
		return &opts, json.Unmarshal(data, &opts)
	case TypeDS:
		var opts RRoptsDS
		return &opts, json.Unmarshal(data, &opts)
	case TypeNSEC3:
		var opts RRoptsNSEC3
		return &opts, json.Unmarshal(data, &opts)
	case TypeNSEC3PARAM:
		var opts RRoptsNSEC3PARAM
		return &opts, json.Unmarshal(data, &opts)
	default:
		return nil, fmt.Errorf("unknown rrtype: %s", rrtype)
	}
}
