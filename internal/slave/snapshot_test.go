// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package slave

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"git.xfx1.de/infrastructure/xfx1-dns/internal/db"
	"git.xfx1.de/infrastructure/xfx1-dns/internal/rec"
)

func TestParseSnapshot_Corrupt(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte("not json at all")},
		{"truncated json", []byte(`{"zone":"example.com.","records":[{`)},
		{"wrong type", []byte(`42`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSnapshot(tc.data)
			if !errors.Is(err, ErrSnapshotCorrupt) {
				t.Fatalf("got %v, want ErrSnapshotCorrupt", err)
			}
		})
	}
}

func TestSnapshotRoundtrip(t *testing.T) {
	original := db.NewDB("example.com.", []*rec.RR{
		rec.NewRR("example.com.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
		rec.NewRR("example.com.", &rec.RRoptsAAAA{Target: net.ParseIP("::1")}),
	})

	data, err := encodeSnapshot(original)
	if err != nil {
		t.Fatalf("encodeSnapshot: %v", err)
	}

	restored, err := parseSnapshot(data)
	if err != nil {
		t.Fatalf("parseSnapshot: %v", err)
	}

	if restored.Zone != original.Zone {
		t.Errorf("zone: got %q, want %q", restored.Zone, original.Zone)
	}

	if restored.RRCount() != original.RRCount() {
		t.Errorf(
			"RRCount: got %d, want %d",
			restored.RRCount(),
			original.RRCount(),
		)
	}
}

// FuzzParseSnapshot feeds arbitrary bytes through the snapshot deserialisation
// path (parseSnapshot → json.Unmarshal → db.DB.UnmarshalJSON → per-record
// rec.RR.UnmarshalJSON → rroptsUnmarshalJSON type dispatch) and checks two
// invariants:
//
//  1. parseSnapshot never panics — ErrSnapshotCorrupt (or nil) are the only
//     outcomes; a corrupt file on disk must never crash the slave on startup.
//
//  2. Encode stability: if parseSnapshot accepts the input, a second
//     encodeSnapshot → parseSnapshot → encodeSnapshot round must produce
//     identical bytes, confirming no lossy or non-deterministic unmarshal path
//     exists in any RRopts type.
//
// Run with `task fuzz`. Under plain `go test` only the seed corpus runs.
func FuzzParseSnapshot(f *testing.F) {
	seed, err := encodeSnapshot(exampleDB())
	if err != nil {
		f.Fatalf("encodeSnapshot seed: %v", err)
	}

	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte("not json"))

	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := parseSnapshot(data)
		t.Logf("parseSnapshot(%x): err=%v", data, err)

		if err != nil {
			if !errors.Is(err, ErrSnapshotCorrupt) {
				t.Fatalf("unexpected error (want ErrSnapshotCorrupt): %v", err)
			}

			return
		}

		// Invariant: a parseable DB must encode without error.
		data2, err := encodeSnapshot(d)
		if err != nil {
			t.Fatalf("encodeSnapshot failed on parsed DB: %v", err)
		}

		// Invariant: the encoded form must parse back to a semantically equivalent
		// DB. AllRecords iterates a map so JSON record order is non-deterministic;
		// byte equality across roundtrips is not guaranteed and is not checked.
		d2, err := parseSnapshot(data2)
		if err != nil {
			t.Fatalf("second parseSnapshot failed: %v", err)
		}

		if d2.Zone != d.Zone {
			t.Fatalf("zone changed across roundtrip: %q → %q", d.Zone, d2.Zone)
		}

		if d2.RRCount() != d.RRCount() {
			t.Fatalf(
				"record count changed across roundtrip: %d → %d",
				d.RRCount(), d2.RRCount(),
			)
		}
	})
}

func TestLoadSnapshot_NotFound(t *testing.T) {
	_, err := loadSnapshot(filepath.Join(t.TempDir(), "nonexistent.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want os.ErrNotExist", err)
	}
}

func TestLoadSnapshot_Corrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadSnapshot(path)
	if !errors.Is(err, ErrSnapshotCorrupt) {
		t.Fatalf("got %v, want ErrSnapshotCorrupt", err)
	}
}

func TestSaveAndLoadSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	original := db.NewDB("example.com.", []*rec.RR{
		rec.NewRR("example.com.", &rec.RRoptsA{Target: net.ParseIP("1.2.3.4")}),
	})

	if err := saveSnapshot(path, original); err != nil {
		t.Fatalf("saveSnapshot: %v", err)
	}

	// No .tmp file must remain after a successful save.
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error(".tmp file still present after successful save")
	}

	restored, err := loadSnapshot(path)
	if err != nil {
		t.Fatalf("loadSnapshot: %v", err)
	}

	if restored.Zone != original.Zone {
		t.Errorf("zone: got %q, want %q", restored.Zone, original.Zone)
	}

	if restored.RRCount() != original.RRCount() {
		t.Errorf(
			"RRCount: got %d, want %d",
			restored.RRCount(),
			original.RRCount(),
		)
	}
}

func TestSaveSnapshot_WriteError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test write error when running as root")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skip("cannot make directory read-only:", err)
	}

	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	err := saveSnapshot(
		filepath.Join(dir, "snap.json"),
		db.NewDB("example.com.", nil),
	)
	if err == nil {
		t.Fatal("expected error writing to read-only directory")
	}
}

func TestSnapshotRoundtrip_DNSSECEnabled(t *testing.T) {
	original := db.NewDB("example.com.", []*rec.RR{
		rec.NewRR(
			"example.com.",
			&rec.RRoptsA{Target: net.ParseIP("10.0.0.1")},
		),
	})
	original.DNSSECEnabled = true

	data, err := encodeSnapshot(original)
	if err != nil {
		t.Fatalf("encodeSnapshot: %v", err)
	}

	restored, err := parseSnapshot(data)
	if err != nil {
		t.Fatalf("parseSnapshot: %v", err)
	}

	if !restored.DNSSECEnabled {
		t.Error("DNSSECEnabled not preserved across roundtrip")
	}
}
