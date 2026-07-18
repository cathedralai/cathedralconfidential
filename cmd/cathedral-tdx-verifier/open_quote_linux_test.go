//go:build linux

package main

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenQuoteFileRejectsFifoWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quote.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		file, err := openQuoteFile(path)
		if file != nil {
			_ = file.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO quote path unexpectedly opened")
		}
	case <-time.After(time.Second):
		t.Fatal("opening a FIFO quote path blocked")
	}
}
