//go:build !linux

package main

import "os"

// Production artifacts are Linux-only and use O_NOFOLLOW. This fallback keeps
// unit tests and offline claim-vector tooling portable.
func openQuoteFile(path string) (*os.File, error) {
	return os.Open(path)
}
