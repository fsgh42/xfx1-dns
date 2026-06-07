// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package rec

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ParseRdata converts raw DNS wire-format rdata to the appropriate RRopts.
func ParseRdata(rrtype RRtype, rdata []byte) (RRopts, error) {
	switch rrtype {
	case TypeA:
		return ParseA(rdata)
	case TypeAAAA:
		return ParseAAAA(rdata)
	case TypeTXT:
		return ParseTXT(rdata)
	case TypeCNAME:
		return ParseCNAME(rdata)
	case TypeNS:
		return ParseNS(rdata)
	case TypePTR:
		return ParsePTR(rdata)
	case TypeMX:
		return ParseMX(rdata)
	case TypeSRV:
		return ParseSRV(rdata)
	case TypeCAA:
		return ParseCAA(rdata)
	default:
		return nil, fmt.Errorf(
			"unsupported RR type for rdata decoding: %s",
			rrtype,
		)
	}
}

// ParseA parses a 4-byte IPv4 address from DNS wire format.
func ParseA(rdata []byte) (*RRoptsA, error) {
	if len(rdata) != 4 {
		return nil, fmt.Errorf("A rdata must be 4 bytes, got %d", len(rdata))
	}

	return &RRoptsA{Target: net.IP(append([]byte(nil), rdata...))}, nil
}

// ParseAAAA parses a 16-byte IPv6 address from DNS wire format.
func ParseAAAA(rdata []byte) (*RRoptsAAAA, error) {
	if len(rdata) != 16 {
		return nil, fmt.Errorf(
			"AAAA rdata must be 16 bytes, got %d",
			len(rdata),
		)
	}

	return &RRoptsAAAA{Target: net.IP(append([]byte(nil), rdata...))}, nil
}

// ParseTXT parses one or more length-prefixed strings from DNS wire format.
func ParseTXT(rdata []byte) (*RRoptsTXT, error) {
	var txt strings.Builder

	offset := 0
	for offset < len(rdata) {
		segLen := int(rdata[offset])
		offset++

		if offset+segLen > len(rdata) {
			return nil, fmt.Errorf("TXT rdata truncated")
		}

		txt.WriteString(string(rdata[offset : offset+segLen]))
		offset += segLen
	}

	return &RRoptsTXT{Txt: txt.String()}, nil
}

// ParseCNAME parses a DNS name from CNAME rdata wire format.
func ParseCNAME(rdata []byte) (*RRoptsCNAME, error) {
	name, _, err := parseDNSName(rdata, 0)
	if err != nil {
		return nil, fmt.Errorf("CNAME rdata: %w", err)
	}

	return &RRoptsCNAME{Cname: Domain(name)}, nil
}

// ParseNS parses a DNS name from NS rdata wire format.
func ParseNS(rdata []byte) (*RRoptsNS, error) {
	name, _, err := parseDNSName(rdata, 0)
	if err != nil {
		return nil, fmt.Errorf("NS rdata: %w", err)
	}

	return &RRoptsNS{Ns: Domain(name)}, nil
}

// ParsePTR parses a DNS name from PTR rdata wire format.
func ParsePTR(rdata []byte) (*RRoptsPTR, error) {
	name, _, err := parseDNSName(rdata, 0)
	if err != nil {
		return nil, fmt.Errorf("PTR rdata: %w", err)
	}

	return &RRoptsPTR{Ptr: Domain(name)}, nil
}

// ParseMX parses a 2-byte preference and DNS name from MX rdata wire format.
func ParseMX(rdata []byte) (*RRoptsMX, error) {
	if len(rdata) < 3 {
		return nil, fmt.Errorf("MX rdata too short: %d bytes", len(rdata))
	}

	pref := binary.BigEndian.Uint16(rdata[0:2])

	name, _, err := parseDNSName(rdata, 2)
	if err != nil {
		return nil, fmt.Errorf("MX rdata: %w", err)
	}

	return &RRoptsMX{Preference: pref, Mx: Domain(name)}, nil
}

// ParseSRV parses priority, weight, port, and target from SRV rdata wire format.
func ParseSRV(rdata []byte) (*RRoptsSRV, error) {
	if len(rdata) < 7 {
		return nil, fmt.Errorf("SRV rdata too short: %d bytes", len(rdata))
	}

	priority := binary.BigEndian.Uint16(rdata[0:2])
	weight := binary.BigEndian.Uint16(rdata[2:4])
	port := binary.BigEndian.Uint16(rdata[4:6])

	target, _, err := parseDNSName(rdata, 6)
	if err != nil {
		return nil, fmt.Errorf("SRV rdata: %w", err)
	}

	return &RRoptsSRV{
		Priority: priority,
		Weight:   weight,
		Port:     port,
		Target:   Domain(target),
	}, nil
}

// ParseCAA parses flags, tag, and value from CAA rdata wire format.
func ParseCAA(rdata []byte) (*RRoptsCAA, error) {
	if len(rdata) < 2 {
		return nil, fmt.Errorf("CAA rdata too short: %d bytes", len(rdata))
	}

	flags := rdata[0]
	tagLen := int(rdata[1])

	if 2+tagLen > len(rdata) {
		return nil, fmt.Errorf("CAA rdata truncated")
	}

	tag := string(rdata[2 : 2+tagLen])
	value := string(rdata[2+tagLen:])

	return &RRoptsCAA{Flags: flags, Tag: tag, Value: value}, nil
}

// parseDNSName parses a DNS label-encoded name starting at data[offset].
// Returns the name as a dotted FQDN with trailing dot, and bytes consumed.
// Compression pointers are rejected — rdata slices are self-contained.
func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string

	start := offset

	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("name parse overrun")
		}

		length := int(data[offset])

		if length == 0 {
			offset++
			break
		}

		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf(
				"invalid label length byte: %02x",
				data[offset],
			)
		}

		offset++

		if offset+length > len(data) {
			return "", 0, fmt.Errorf("name label overrun")
		}

		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	var name string
	if len(labels) == 0 {
		name = "."
	} else {
		name = strings.Join(labels, ".") + "."
	}

	return name, offset - start, nil
}
