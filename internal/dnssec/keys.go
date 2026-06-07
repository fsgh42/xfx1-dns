// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/crypto"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

// SigningKey is a parsed, ready-to-use signing key with its associated DNSKEY record.
type SigningKey struct {
	DNSKEY     *crypto.DNSKEYRecord // parsed public key metadata
	PrivateKey *crypto.PrivateKey   // parsed private key
}

// IsKSK reports whether this key should sign only the DNSKEY RRset.
func (sk *SigningKey) IsKSK() bool { return sk.DNSKEY.IsKSK() }

// IsZSK reports whether this key should sign all non-DNSKEY RRsets.
func (sk *SigningKey) IsZSK() bool { return sk.DNSKEY.IsZSK() }

// KeySecret holds the raw Secret data for one signing key.
// Master reads this from the k8s Secret before calling LoadKeys.
type KeySecret struct {
	KeyType    string // "zsk" or "ksk"
	PrivateKey string // value of the "privateKey" Secret field
}

// LoadKeys parses a slice of key secrets into signing keys.
// zone is the zone apex (e.g. "xfx1.de.") used as the DNSKEY owner name.
// Collects all parse errors with errors.Join — does not short-circuit
// on the first failure. Returns nil slice + non-nil error if any key fails.
func LoadKeys(secrets []KeySecret, zone rec.Domain) ([]*SigningKey, error) {
	var (
		keys []*SigningKey
		errs []error
	)

	for i, sec := range secrets {
		key, err := parseOneKey(sec, zone)
		if err != nil {
			errs = append(errs, fmt.Errorf("key %d: %w", i, err))
			continue
		}

		keys = append(keys, key)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return keys, nil
}

func parseOneKey(sec KeySecret, zone rec.Domain) (*SigningKey, error) {
	var flags uint16

	switch sec.KeyType {
	case "ksk":
		flags = 257
	case "zsk":
		flags = 256
	default:
		return nil, fmt.Errorf(
			"invalid keyType %q: must be \"zsk\" or \"ksk\"",
			sec.KeyType,
		)
	}

	priv, err := crypto.ParsePrivateKey(sec.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	pubBytes, err := derivedPublicKeyBytes(priv)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	dnskey := &crypto.DNSKEYRecord{
		Owner:     string(zone),
		TTL:       dnskeyTTL,
		Flags:     flags,
		Protocol:  3,
		Algorithm: priv.Algorithm,
		PublicKey: pubBytes,
	}

	return &SigningKey{DNSKEY: dnskey, PrivateKey: priv}, nil
}

// derivedPublicKeyBytes returns the DNS wire-format public key bytes for the
// given private key, per RFC 4034 §2.1.
func derivedPublicKeyBytes(priv *crypto.PrivateKey) ([]byte, error) {
	switch priv.Algorithm {
	case 15: // ED25519
		pub, ok := priv.Key.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected ed25519.PublicKey")
		}

		return []byte(pub), nil

	case 13, 14: // ECDSAP256SHA256, ECDSAP384SHA384
		pub, ok := priv.Key.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected *ecdsa.PublicKey")
		}

		size := 32
		if priv.Algorithm == 14 {
			size = 48
		}

		xBytes := pub.X.Bytes()
		yBytes := pub.Y.Bytes()
		out := make([]byte, size*2)
		// right-align each coordinate into its fixed-size slot
		copy(out[size-len(xBytes):size], xBytes)
		copy(out[2*size-len(yBytes):2*size], yBytes)

		return out, nil

	case 8: // RSASHA256 — RFC 3110 §2: exponent length + exponent + modulus
		pub, ok := priv.Key.Public().(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PublicKey")
		}

		eBytes := big.NewInt(int64(pub.E)).Bytes()
		mBytes := pub.N.Bytes()

		var out []byte
		if len(eBytes) > 255 {
			// two-byte length prefix
			out = append(out, 0)

			var lenBuf [2]byte

			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(eBytes)))
			out = append(out, lenBuf[:]...)
		} else {
			out = append(out, byte(len(eBytes)))
		}

		out = append(out, eBytes...)
		out = append(out, mBytes...)

		return out, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm %d", priv.Algorithm)
	}
}
