package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckRegistrationWhileProbeHoldsRunLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "instance")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	saved := credentials{
		Manager:    "https://manager.example.com",
		NodeID:     "probe-test",
		Credential: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Enrolled:   true,
	}
	if err := writePrivateJSON(credentialsFile, saved); err != nil {
		t.Fatal(err)
	}
	lock, err := lockDirectory()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	args := func(command, manager, node string) []string {
		return []string{command, "--manager", manager, "--node", node, "--dir", dir}
	}
	if err := execute(args("register", saved.Manager, saved.NodeID)); !errors.Is(err, errLocked) {
		t.Fatalf("register with running probe returned %v, want directory in use", err)
	}
	if err := execute(args("check-registration", saved.Manager, saved.NodeID)); err != nil {
		t.Fatalf("read-only registration check failed for running probe: %v", err)
	}
	if err := execute(args("check-registration", saved.Manager, "another-probe")); err == nil {
		t.Error("read-only registration check accepted a different node")
	}
	if err := execute(args("check-registration", "https://another.example.com", saved.NodeID)); err == nil {
		t.Error("read-only registration check accepted a different manager")
	}

	current, err := loadCredentials()
	if err != nil || current != saved {
		t.Fatalf("read-only registration check changed the saved credentials: %v", err)
	}
}
