//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cathedral-ai/cathedral-confidential-space/internal/contract"
)

func runIsolationProbe() error {
	if err := applyMountIsolation(""); err != nil {
		return err
	}
	return verifyIsolation(false)
}

func verifyIsolation(writableWork bool) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("isolated network inventory failed")
	}
	for _, networkInterface := range interfaces {
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return errors.New("isolated network address inventory failed")
		}
		for _, address := range addresses {
			if !strings.HasPrefix(address.String(), "127.") && address.String() != "::1/128" {
				return errors.New("isolated namespace exposes a non-loopback address")
			}
		}
	}
	connection, dialErr := net.DialTimeout("tcp", "169.254.169.254:80", 250*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("isolated namespace can reach metadata")
	}
	routes, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return errors.New("isolated route table is unreadable")
	}
	if len(strings.Split(strings.TrimSpace(string(routes)), "\n")) > 1 {
		return errors.New("isolated namespace contains an IPv4 route")
	}
	for _, path := range []string{"/run", "/tmp", "/var/tmp", "/dev/shm", "/dev/mqueue"} {
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) != 0 {
			return errors.New("isolated namespace exposes host runtime or temporary files")
		}
	}
	return verifyReadOnlyMounts(writableWork)
}

func applyMountIsolation(secretRoot string) error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return errors.New("sandbox mount propagation could not be made private")
	}
	if err := syscall.Mount("/", "/", "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return errors.New("sandbox root bind isolation failed")
	}
	if err := remountAllReadOnly(); err != nil {
		return err
	}
	if secretRoot != "" {
		workInfo, workErr := os.Stat("/work")
		secretInfo, secretErr := os.Stat(secretRoot)
		if workErr != nil || secretErr != nil || !workInfo.IsDir() || !secretInfo.IsDir() {
			return errors.New("fixed /work mountpoint or protected tmpfs is absent")
		}
		if err := syscall.Mount(secretRoot, "/work", "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return errors.New("protected tmpfs could not be bound to fixed /work")
		}
		if err := syscall.Mount("", "/work", "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
			return errors.New("protected /work mount flags could not be enforced")
		}
	}
	for _, path := range []string{"/run", "/tmp", "/var/tmp", "/dev/shm", "/dev/mqueue"} {
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return errors.New("runtime mask mountpoint is absent")
		}
		if err := syscall.Mount("tmpfs", path, "tmpfs", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=4096,mode=0555"); err != nil {
			return errors.New("host runtime or temporary directory could not be masked")
		}
	}
	return nil
}

func mountPoints() ([]string, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, errors.New("sandbox mount inventory is unreadable")
	}
	seen := map[string]bool{}
	points := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, errors.New("sandbox mount inventory is malformed")
		}
		point := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(fields[4])
		if !filepath.IsAbs(point) || seen[point] {
			continue
		}
		seen[point] = true
		points = append(points, point)
	}
	sort.Slice(points, func(left, right int) bool {
		return len(points[left]) > len(points[right])
	})
	return points, nil
}

func remountAllReadOnly() error {
	points, err := mountPoints()
	if err != nil {
		return err
	}
	for _, point := range points {
		if err := syscall.Mount("", point, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, ""); err != nil {
			return errors.New("sandbox recursive mount tree could not be made read-only")
		}
	}
	return nil
}

func verifyReadOnlyMounts(writableWork bool) error {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return errors.New("sandbox mount inventory is unreadable")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return errors.New("sandbox mount inventory is malformed")
		}
		point := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(fields[4])
		if writableWork && (point == "/work" || strings.HasPrefix(point, "/work/")) {
			continue
		}
		readOnly := false
		for _, option := range strings.Split(fields[5], ",") {
			if option == "ro" {
				readOnly = true
				break
			}
		}
		if !readOnly {
			return errors.New("sandbox contains a writable mount outside the protected work directory")
		}
	}
	return nil
}

func runSandboxChild(arguments []string) error {
	if len(arguments) != 6 || arguments[3] != "--" || arguments[0] != "/usr/bin/setpriv" || !filepath.IsAbs(arguments[1]) || !contract.ValidDigest(arguments[2]) || arguments[4] != "/usr/bin/python3" || arguments[5] != "/opt/cathedral/bin/cathedral-job" {
		return errors.New("sandbox child arguments are invalid")
	}
	if err := applyMountIsolation(arguments[1]); err != nil {
		return err
	}
	if err := verifyIsolation(true); err != nil {
		return err
	}
	setprivArguments := []string{
		arguments[0], "--reuid=65532", "--regid=65532", "--clear-groups", "--no-new-privs",
		"--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--",
	}
	setprivArguments = append(setprivArguments, arguments[4:]...)
	return syscall.Exec(arguments[0], setprivArguments, []string{
		"LANG=C", "LC_ALL=C", "PATH=/nonexistent", "HOME=/nonexistent",
		"PYTHONDONTWRITEBYTECODE=1", "CATHEDRAL_INPUT_DIR=/work", "CATHEDRAL_OUTPUT_DIR=/work/outputs",
		"CATHEDRAL_NETWORK_POLICY_SHA256=" + arguments[2],
	})
}
