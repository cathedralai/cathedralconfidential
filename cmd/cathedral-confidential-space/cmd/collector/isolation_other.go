//go:build !linux

package main

import "errors"

func runIsolationProbe() error       { return errors.New("isolation probe requires Linux") }
func runSandboxChild([]string) error { return errors.New("sandbox child requires Linux") }
