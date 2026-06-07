// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	gocrypto "crypto"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// verifyRRSIG verifies an RRSIG signature against the signed data and public key.
// Used in tests to confirm cryptographic correctness.
func verifyRRSIG(
	rrsig *RRSIGRecord,
	rrset []*rec.RR,
	key *SigningKey,
) (bool, error) {
	if len(rrset) == 0 {
		return false, fmt.Errorf("empty RRset")
	}

	owner := rrset[0].Name
	ttl := rrset[0].TTL

	wireType := rrsig.TypeCovered

	// Rebuild RRSIG RDATA without signature (same as SignRRset)
	var rrsigRdata bytes.Buffer

	binary.Write(&rrsigRdata, binary.BigEndian, wireType)
	rrsigRdata.WriteByte(rrsig.Algorithm)
	rrsigRdata.WriteByte(rrsig.Labels)
	binary.Write(&rrsigRdata, binary.BigEndian, rrsig.OrigTTL)
	binary.Write(&rrsigRdata, binary.BigEndian, rrsig.Expiration)
	binary.Write(&rrsigRdata, binary.BigEndian, rrsig.Inception)
	binary.Write(&rrsigRdata, binary.BigEndian, rrsig.KeyTag)

	signerDomain := rec.Domain(rrsig.SignerName)
	if err := signerDomain.Write(&rrsigRdata); err != nil {
		return false, err
	}

	sorted := make([]*rec.RR, len(rrset))
	copy(sorted, rrset)
	slices.SortFunc(sorted, func(a, b *rec.RR) int {
		return bytes.Compare(a.Opts.Payload(), b.Opts.Payload())
	})

	for _, rr := range sorted {
		var rrWire bytes.Buffer

		ownerLower := rec.Domain(strings.ToLower(string(rr.Name)))
		if err := ownerLower.Write(&rrWire); err != nil {
			return false, err
		}

		binary.Write(&rrWire, binary.BigEndian, wireType)
		binary.Write(&rrWire, binary.BigEndian, uint16(1)) // class IN
		binary.Write(&rrWire, binary.BigEndian, uint32(ttl))

		payload := rr.Opts.Payload()
		binary.Write(&rrWire, binary.BigEndian, uint16(len(payload)))
		rrWire.Write(payload)
		rrsigRdata.Write(rrWire.Bytes())
	}

	_ = owner // assigned above, used implicitly via rr.Name in the loop

	data := rrsigRdata.Bytes()
	sig := rrsig.Signature

	switch rrsig.Algorithm {
	case 15: // ED25519
		pubKey, ok := key.PrivateKey.Key.Public().(ed25519.PublicKey)
		if !ok {
			return false, fmt.Errorf("key is not ED25519")
		}

		return ed25519.Verify(pubKey, data, sig), nil

	case 13, 14: // ECDSA
		pubKey, ok := key.PrivateKey.Key.Public().(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key is not ECDSA")
		}

		var hashOpt gocrypto.Hash
		if rrsig.Algorithm == 13 {
			hashOpt = gocrypto.SHA256
		} else {
			hashOpt = gocrypto.SHA384
		}

		h := hashOpt.New()
		h.Write(data)
		digest := h.Sum(nil)

		derSig, err := ECDSAFixedSizeToDER(sig, rrsig.Algorithm)
		if err != nil {
			return false, err
		}

		return ecdsa.VerifyASN1(pubKey, digest, derSig), nil

	default:
		return false, fmt.Errorf("unsupported algorithm %d", rrsig.Algorithm)
	}
}
