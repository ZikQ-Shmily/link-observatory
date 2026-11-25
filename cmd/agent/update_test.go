package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestManagedUpdateUsesVerifiedLocalInstallerAndRecordsFailure(t *testing.T) {
	t.Chdir(t.TempDir())
	script := "#!/bin/bash\n" + updateInstallerMarker + "\nprintf '%s\\n' \"$@\"\nexit 1\n"
	if err := os.WriteFile(returnInstaller, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	offer := protocol.UpdateOffer{ID: strings.Repeat("a", 32), Version: "v2.2.0", InstallerSHA256: strings.Repeat("b", 64)}
	if err := startManagedUpdate("return-test", offer); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var attempt updateAttempt
		if err := readPrivateJSON(updateAttemptFile, &attempt); err == nil && attempt.Failed {
			log, err := os.ReadFile("update.log")
			want := "--update\n--managed-version\nv2.2.0\n--installer-sha256\n" + offer.InstallerSHA256 + "\n"
			if err != nil || attempt.ID != offer.ID || string(log) != want {
				t.Fatalf("unexpected update invocation or attempt state: %+v %q %v", attempt, log, err)
			}
			return
		}
	}
	t.Fatal("failed installer result was not saved")
}

func TestSelectUpdateInstallerByNodeRole(t *testing.T) {
	t.Chdir(t.TempDir())
	script := []byte("#!/bin/bash\n" + updateInstallerMarker + "\n")
	write := func(path string, contents []byte) {
		t.Helper()
		if err := os.WriteFile(path, contents, 0700); err != nil {
			t.Fatal(err)
		}
	}
	check := func(node, want string) {
		t.Helper()
		if got := selectUpdateInstaller(node); got != want {
			t.Errorf("installer for %s = %q, want %q", node, got, want)
		}
	}

	check("return-test", "")
	write(returnInstaller, script)
	check("return-test", returnInstaller)
	check("probe-test", "")

	write(localInstaller, script)
	check("return-test", returnInstaller)
	check("probe-test", localInstaller)

	write(returnInstaller, []byte("#!/bin/bash\n"))
	check("return-test", localInstaller)
	if err := os.Remove(returnInstaller); err != nil {
		t.Fatal(err)
	}
	check("return-test", localInstaller)
	if err := os.Symlink(localInstaller, returnInstaller); err != nil {
		t.Fatal(err)
	}
	check("return-test", localInstaller)
}
