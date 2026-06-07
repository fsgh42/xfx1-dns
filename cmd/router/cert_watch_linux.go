// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	ilog "git.xfx1.de/infrastructure/xfx1-dns/internal/log"
)

// watchCertFiles watches the parent directories of the TLS cert/key paths via
// inotify and signals changeCh on any change. Watches the directories rather
// than the files because k8s Secrets rotate by atomically swapping a `..data`
// symlink — the file's inode changes on rotation, so a file-level watch goes
// silent after the first swap. Returns when ctx is cancelled.
func watchCertFiles(
	ctx context.Context,
	certFile, keyFile string,
	changeCh chan<- struct{},
	logger ilog.Logger,
) {
	if certFile == "" && keyFile == "" {
		return
	}

	fd, err := syscall.InotifyInit()
	if err != nil {
		logger.Error("inotify init: " + err.Error())
		return
	}

	inotifyFile := os.NewFile(uintptr(fd), "inotify")
	defer inotifyFile.Close()

	const mask = syscall.IN_CREATE | syscall.IN_MOVED_TO |
		syscall.IN_MODIFY | syscall.IN_CLOSE_WRITE

	seen := map[string]struct{}{}

	for _, p := range []string{certFile, keyFile} {
		if p == "" {
			continue
		}

		dir := filepath.Dir(p)
		if _, ok := seen[dir]; ok {
			continue
		}

		if _, err := syscall.InotifyAddWatch(fd, dir, mask); err != nil {
			logger.Error("inotify add watch " + dir + ": " + err.Error())
			return
		}

		seen[dir] = struct{}{}
	}

	if len(seen) == 0 {
		return
	}

	// Closing the fd from the cancel goroutine unblocks the Read below.
	go func() {
		<-ctx.Done()
		inotifyFile.Close()
	}()

	buf := make([]byte, 4096)

	for {
		n, err := inotifyFile.Read(buf)
		if err != nil || n <= 0 {
			return
		}

		// We don't parse the event payload — any event in a watched dir is
		// reason enough to re-load TLS. Cert-manager / kubelet swap a parent
		// symlink on rotation, so event names don't always match cert paths.
		logger.Info("TLS cert change detected — triggering router reload")

		select {
		case changeCh <- struct{}{}:
		default:
		}
	}
}
