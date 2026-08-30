package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvironmentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.env")
	if err := os.WriteFile(path, []byte("CLUSTER_ENV=staging\nCLUSTER_SECRET=literal-$()-value\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Unsetenv("CLUSTER_ENV")
		os.Unsetenv("CLUSTER_SECRET")
	})
	if err := LoadAPIEnvironmentFile(path); err != nil {
		t.Fatal(err)
	}
	if value := os.Getenv("CLUSTER_SECRET"); value != "literal-$()-value" {
		t.Fatalf("value was evaluated or changed: %q", value)
	}
}

func TestLoadEnvironmentFileRejectsUnsafeInputWithoutLeakingValue(t *testing.T) {
	secret := "must-not-appear-in-error"
	cases := map[string]string{
		"duplicate":              "CLUSTER_ENV=one\nCLUSTER_ENV=" + secret + "\n",
		"foreign namespace":      "AWS_SECRET_ACCESS_KEY=" + secret + "\n",
		"loader path override":   "CLUSTER_CONFIG_FILE=" + secret + "\n",
		"trusted proxy override": "CLUSTER_TRUSTED_PROXY_CIDRS=" + secret + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.env")
			if err := os.WriteFile(path, []byte(content), 0o440); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o440); err != nil {
				t.Fatal(err)
			}
			err := LoadAPIEnvironmentFile(path)
			if err == nil {
				t.Fatal("unsafe input was accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error leaked a secret value")
			}
		})
	}
}

func TestLoadEnvironmentFileRejectsWritableMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.env")
	if err := os.WriteFile(path, []byte("CLUSTER_ENV=staging\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LoadAPIEnvironmentFile(path); err == nil {
		t.Fatal("writable runtime configuration was accepted")
	}
}
