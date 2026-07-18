//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

func isolatedClaimOutput() (*os.File, error) {
	return nil, errors.New("unsupported verifier platform")
}
