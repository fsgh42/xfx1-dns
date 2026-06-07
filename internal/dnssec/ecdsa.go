// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ecdsaDERToFixedSize converts an ASN.1 DER-encoded ECDSA signature to the
// fixed-size R || S format required by DNS (RFC 6605 §4).
// Algorithm 13 (P-256): 32+32 = 64 bytes. Algorithm 14 (P-384): 48+48 = 96 bytes.
func ecdsaDERToFixedSize(derSig []byte, algorithm uint8) ([]byte, error) {
	var parsed struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(derSig, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal DER: %w", err)
	}

	var size int

	switch algorithm {
	case 13:
		size = 32
	case 14:
		size = 48
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm %d", algorithm)
	}

	rBytes := parsed.R.Bytes()
	sBytes := parsed.S.Bytes()

	if len(rBytes) > size || len(sBytes) > size {
		return nil, fmt.Errorf("R or S too large for algorithm %d", algorithm)
	}

	out := make([]byte, size*2)
	// Right-align R and S into their fixed-size slots (zero-padded on the left)
	copy(out[size-len(rBytes):size], rBytes)
	copy(out[2*size-len(sBytes):2*size], sBytes)

	return out, nil
}

// ECDSAFixedSizeToDER converts a fixed-size R || S ECDSA signature back to ASN.1 DER.
// Used for signature verification with crypto/ecdsa.VerifyASN1.
func ECDSAFixedSizeToDER(fixedSig []byte, algorithm uint8) ([]byte, error) {
	var size int

	switch algorithm {
	case 13:
		size = 32
	case 14:
		size = 48
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm %d", algorithm)
	}

	if len(fixedSig) != size*2 {
		return nil, fmt.Errorf(
			"expected %d bytes, got %d",
			size*2,
			len(fixedSig),
		)
	}

	r := new(big.Int).SetBytes(fixedSig[:size])
	s := new(big.Int).SetBytes(fixedSig[size:])

	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
