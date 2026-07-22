//go:build linux

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

type LinuxTmpfsStore struct {
	BasePath string
	Bytes    int64
}

type linuxTmpfsMount struct {
	root   string
	closed bool
}

func (store LinuxTmpfsStore) Mount(_ context.Context, attemptID string) (SecretMount, error) {
	maximum := contract.MaxProtectedPlaintextBytes + contract.ProtectedTmpfsReserveBytes + 262144
	if store.BasePath != "/run/cathedral-cc-gpu/secrets" || store.Bytes < contract.ProtectedTmpfsReserveBytes || store.Bytes > maximum || filepath.Base(attemptID) != attemptID {
		return nil, errors.New("production tmpfs configuration is invalid")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("production supervisor must start as root to mount tmpfs before dropping workload privileges")
	}
	if err := os.MkdirAll(store.BasePath, 0o700); err != nil {
		return nil, err
	}
	root := filepath.Join(store.BasePath, attemptID)
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, err
	}
	flags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
	options := "size=" + strconv.FormatInt(store.Bytes, 10) + ",mode=0700"
	if err := syscall.Mount("tmpfs", root, "tmpfs", flags, options); err != nil {
		_ = os.Remove(root)
		return nil, errors.New("dedicated protected tmpfs mount failed")
	}
	return &linuxTmpfsMount{root: root}, nil
}

func (mount *linuxTmpfsMount) Root() string { return mount.root }

func (mount *linuxTmpfsMount) PrepareForWorkload() error {
	if mount.closed {
		return errors.New("protected tmpfs is closed")
	}
	entries, err := os.ReadDir(mount.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errors.New("protected input path is not a bounded regular 0600 file")
		}
		if err := os.Chown(filepath.Join(mount.root, entry.Name()), 65532, 65532); err != nil {
			return err
		}
	}
	outputRoot := filepath.Join(mount.root, "outputs")
	if err := os.Mkdir(outputRoot, 0o700); err != nil {
		return err
	}
	if err := os.Chown(outputRoot, 65532, 65532); err != nil {
		return err
	}
	return os.Chown(mount.root, 65532, 65532)
}

func (mount *linuxTmpfsMount) Close() error {
	if mount.closed {
		return errors.New("protected tmpfs was already closed")
	}
	mount.closed = true
	var first error
	_ = filepath.WalkDir(mount.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if first == nil {
				first = walkErr
			}
			return nil
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				if first == nil {
					first = err
				}
				return nil
			}
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				if first == nil {
					first = err
				}
				return nil
			}
			zeroBlock := make([]byte, 64*1024)
			remaining := info.Size()
			for remaining > 0 {
				chunk := int64(len(zeroBlock))
				if remaining < chunk {
					chunk = remaining
				}
				if _, err := file.Write(zeroBlock[:chunk]); err != nil {
					if first == nil {
						first = err
					}
					break
				}
				remaining -= chunk
			}
			if err := file.Sync(); err != nil && first == nil {
				first = err
			}
			_ = file.Close()
		}
		return nil
	})
	entries, err := os.ReadDir(mount.root)
	if err != nil && first == nil {
		first = err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(mount.root, entry.Name())); err != nil && first == nil {
			first = err
		}
	}
	if err := syscall.Unmount(mount.root, 0); err != nil && first == nil {
		first = err
	}
	if err := os.Remove(mount.root); err != nil && first == nil {
		first = err
	}
	return first
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

func (sandbox LinuxSandbox) VerifyIsolation(ctx context.Context) error {
	if err := sandbox.validate(); err != nil {
		return err
	}
	if err := sandbox.prepareCgroup(); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, sandbox.UnsharePath,
		"--net", "--mount", "--pid", "--ipc", "--uts", "--fork", "--kill-child=KILL", "--mount-proc=/proc",
		sandbox.IsolationHelperPath, "isolation-probe")
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/nonexistent", "HOME=/nonexistent"}
	if err := sandbox.startInCgroup(command, &syscall.SysProcAttr{}); err != nil {
		return errors.New("isolated child namespace preflight could not start")
	}
	if err := command.Wait(); err != nil {
		return errors.New("isolated child namespace still exposes network or metadata")
	}
	return nil
}

func (sandbox LinuxSandbox) validate() error {
	if sandbox.UnsharePath != "/usr/bin/unshare" || sandbox.SetprivPath != "/usr/bin/setpriv" || sandbox.IsolationHelperPath != "/opt/cathedral/bin/cathedral-confidential-space-collector" || !contract.ValidDigest(sandbox.PlatformNetworkPolicySHA256) || len(sandbox.AllowedEntrypoint) == 0 || sandbox.CgroupPath == "" || !filepath.IsAbs(sandbox.CgroupPath) || !strings.HasPrefix(filepath.Clean(sandbox.CgroupPath), "/sys/fs/cgroup/cathedral-cc-gpu/") || sandbox.MemoryMaxBytes < 256*1024*1024 || sandbox.MemoryMaxBytes > 256*1024*1024*1024 || sandbox.PidsMax < 8 || sandbox.PidsMax > 4096 || sandbox.CPUQuotaMicros < 1000 || sandbox.CPUQuotaMicros > 1000000 {
		return errors.New("sandbox namespace or cgroup policy is not pinned")
	}
	return nil
}

func (sandbox LinuxSandbox) prepareCgroup() error {
	if err := os.Mkdir(sandbox.CgroupPath, 0o755); err != nil && !os.IsExist(err) {
		return errors.New("workload cgroup could not be created")
	}
	values := map[string]string{
		"memory.max": strconv.FormatInt(sandbox.MemoryMaxBytes, 10),
		"pids.max":   strconv.FormatInt(sandbox.PidsMax, 10),
		"cpu.max":    strconv.FormatInt(sandbox.CPUQuotaMicros, 10) + " 100000",
	}
	for name, value := range values {
		if err := os.WriteFile(filepath.Join(sandbox.CgroupPath, name), []byte(value), 0o644); err != nil {
			return errors.New("workload cgroup limit could not be enforced")
		}
	}
	return nil
}

func (sandbox LinuxSandbox) startInCgroup(command *exec.Cmd, attributes *syscall.SysProcAttr) error {
	// clone3 places the unshare parent in the cgroup before it can run or fork.
	// Writing cgroup.procs after Start is racy: unshare --fork may otherwise
	// create a descendant in the caller's unbounded cgroup first.
	descriptor, err := syscall.Open(sandbox.CgroupPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("workload cgroup directory could not be opened")
	}
	defer syscall.Close(descriptor)
	cloned := *attributes
	cloned.UseCgroupFD = true
	cloned.CgroupFD = descriptor
	command.SysProcAttr = &cloned
	if err := command.Start(); err != nil {
		return errors.New("workload process could not start inside its bounded cgroup")
	}
	return nil
}

func (sandbox LinuxSandbox) Run(ctx context.Context, entrypoint []string, secretRoot string, maximumOutputBytes int64) (SandboxResult, error) {
	if sandbox.validate() != nil || !equalStrings(entrypoint, sandbox.AllowedEntrypoint) {
		return SandboxResult{}, errors.New("sandbox entrypoint or platform network enforcement receipt is not pinned")
	}
	outputRoot := filepath.Join(secretRoot, "outputs")
	if info, err := os.Stat(outputRoot); err != nil || !info.IsDir() {
		return SandboxResult{}, errors.New("prepared workload output directory is absent")
	}
	args := []string{
		"--net", "--mount", "--pid", "--ipc", "--uts", "--fork", "--kill-child=KILL", "--mount-proc=/proc",
		sandbox.IsolationHelperPath, "sandbox-child", sandbox.SetprivPath, secretRoot, sandbox.PlatformNetworkPolicySHA256, "--",
	}
	args = append(args, entrypoint...)
	command := exec.CommandContext(ctx, sandbox.UnsharePath, args...)
	command.Dir = secretRoot
	command.Env = []string{
		"LANG=C", "LC_ALL=C", "PATH=/nonexistent", "HOME=/nonexistent",
		"CATHEDRAL_INPUT_DIR=" + secretRoot, "CATHEDRAL_OUTPUT_DIR=" + outputRoot,
		"CATHEDRAL_NETWORK_POLICY_SHA256=" + sandbox.PlatformNetworkPolicySHA256,
	}
	processAttributes := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	command.Stderr = &limitedWriter{buffer: &stderr, maximum: 64 * 1024}
	err := sandbox.startInCgroup(command, processAttributes)
	if err == nil {
		waitErr := command.Wait()
		if err == nil {
			err = waitErr
		}
	}
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return SandboxResult{}, errors.New("fixed workload execution failed")
		}
		exitCode = exitError.ExitCode()
	}
	outputs, err := readOutputs(outputRoot, maximumOutputBytes)
	if err != nil {
		return SandboxResult{}, err
	}
	return SandboxResult{ExitCode: exitCode, Outputs: outputs}, nil
}

type limitedWriter struct {
	buffer  *bytes.Buffer
	maximum int
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	original := len(value)
	remaining := writer.maximum - writer.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = writer.buffer.Write(value)
	}
	return original, nil
}

func readOutputs(root string, maximum int64) (map[string][]byte, error) {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) == 0 || len(entries) > 64 {
		return nil, errors.New("workload output directory is invalid")
	}
	outputs := map[string][]byte{}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 {
			return nil, errors.New("workload output is not a regular file")
		}
		total += info.Size()
		if total > maximum {
			return nil, errors.New("workload outputs exceed their bound")
		}
		raw, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		outputs[entry.Name()] = raw
	}
	return outputs, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
