//go:build !linux

package supervisor

import (
	"context"
	"errors"
)

// Production tmpfs mounting and non-root process isolation are intentionally
// unavailable off Linux. Tests use explicit in-memory implementations of the
// interfaces; there is no fake production-success adapter.

type LinuxTmpfsStore struct {
	BasePath string
	Bytes    int64
}

func (LinuxTmpfsStore) Mount(context.Context, string) (SecretMount, error) {
	return nil, errors.New("production protected tmpfs is available only on Linux")
}

type LinuxSandbox struct {
	UnsharePath                 string
	SetprivPath                 string
	IsolationHelperPath         string
	CgroupPath                  string
	MemoryMaxBytes              int64
	PidsMax                     int64
	CPUQuotaMicros              int64
	AllowedEntrypoint           []string
	PlatformNetworkPolicySHA256 string
}

func (LinuxSandbox) VerifyIsolation(context.Context) error {
	return errors.New("production child namespace isolation is available only on Linux")
}

func (LinuxSandbox) Run(context.Context, []string, string, int64) (SandboxResult, error) {
	return SandboxResult{}, errors.New("production child namespace isolation is available only on Linux")
}
