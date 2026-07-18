//go:build linux || darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func isolatedClaimOutput() (*os.File, error) {
	saved, err := unix.Dup(int(os.Stdout.Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(saved)
	nullOutput, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		_ = unix.Close(saved)
		return nil, err
	}
	if err := unix.Dup2(int(nullOutput.Fd()), int(os.Stdout.Fd())); err != nil {
		_ = nullOutput.Close()
		_ = unix.Close(saved)
		return nil, err
	}
	if err := nullOutput.Close(); err != nil {
		_ = unix.Close(saved)
		return nil, err
	}
	return os.NewFile(uintptr(saved), "cathedral-claims-stdout"), nil
}
