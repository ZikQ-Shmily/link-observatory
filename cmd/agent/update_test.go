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
	if hasUpdateInstaller() {
		t.Fatal("missing installer advertised as update capable")
	}
	script := "#!/bin/bash\n" + updateInstallerMarker + "\nprintf '%s\\n' \"$@\"\nexit 1\n"
	if err := os.WriteFile(localInstaller, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if !hasUpdateInstaller() {
		t.Fatal("valid local installer was not detected")
	}
	offer := protocol.UpdateOffer{ID: strings.Repeat("a", 32), Version: "v2.2.0", InstallerSHA256: strings.Repeat("b", 64)}
	if err := startManagedUpdate(offer); err != nil {
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
