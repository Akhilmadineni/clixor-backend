package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
)

const maxRuntimeConfigBytes = 256 * 1024

var runtimeConfigKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadAPIEnvironmentFile loads a root-owned, read-only tmpfs file before Load.
// Docker receives only the nonsecret file path; values never enter container
// configuration metadata. The process environment remains root-observable at
// runtime and is deliberately part of the host/Docker trust boundary.
func LoadAPIEnvironmentFile(path string) error {
	return loadEnvironmentFile(path, func(key string) bool {
		if !strings.HasPrefix(key, "CLUSTER_") {
			return false
		}
		// These values define how the file is loaded and which ingress hop may
		// assert the client address. They are fixed by the reviewed container
		// model and must never be overridden by a secret bundle.
		return key != "CLUSTER_CONFIG_FILE" && key != "CLUSTER_TRUSTED_PROXY_CIDRS"
	})
}

// LoadMigrationEnvironmentFile is narrower because migrations need only pool
// configuration and the database URL.
func LoadMigrationEnvironmentFile(path string) error {
	allowed := map[string]struct{}{
		"CLUSTER_DATABASE_URL":       {},
		"CLUSTER_DATABASE_MAX_CONNS": {},
		"CLUSTER_DATABASE_MIN_CONNS": {},
		"CLUSTER_TLS_CA_FILE":        {},
	}
	return loadEnvironmentFile(path, func(key string) bool {
		_, ok := allowed[key]
		return ok
	})
}

func loadEnvironmentFile(path string, allowed func(string) bool) error {
	if path == "" {
		return errors.New("runtime configuration file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("runtime configuration file is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("runtime configuration must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxRuntimeConfigBytes {
		return errors.New("runtime configuration file size is invalid")
	}
	if info.Mode().Perm() != 0o440 {
		return errors.New("runtime configuration file must have mode 0440")
	}
	if path == "/run/secrets/api.env" || path == "/run/secrets/migrate.env" {
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || metadata.Uid != 0 || metadata.Gid != 65532 {
			return errors.New("runtime configuration file has unsafe ownership")
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("runtime configuration file cannot be read")
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 16*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsRune(line, '\r') || strings.ContainsRune(line, '\x00') {
			return errors.New("runtime configuration contains unsupported bytes")
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !runtimeConfigKey.MatchString(key) || !allowed(key) {
			return errors.New("runtime configuration contains a disallowed assignment")
		}
		if _, duplicate := values[key]; duplicate {
			return fmt.Errorf("runtime configuration contains duplicate key %s", key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return errors.New("runtime configuration cannot be parsed")
	}
	if len(values) == 0 {
		return errors.New("runtime configuration contains no assignments")
	}
	for key, value := range values {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("load runtime configuration key %s", key)
		}
	}
	return nil
}
