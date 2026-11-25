package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"link-observatory/internal/protocol"
)

const (
	localInstaller        = "./install.sh"
	returnInstaller       = "./install-return.sh"
	updateAttemptFile     = "update-attempt.json"
	updateInstallerMarker = "# Link Observatory managed updates v1."
)

type updateAttempt struct {
	ID     string
	Failed bool
}

func selectUpdateInstaller(nodeID string) string {
	if strings.HasPrefix(nodeID, "return-") && hasUpdateInstaller(returnInstaller) {
		return returnInstaller
	}
	if hasUpdateInstaller(localInstaller) {
		return localInstaller
	}
	return ""
}

func hasUpdateInstaller(installer string) bool {
	info, err := os.Lstat(installer)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 ||
		!ownedByCurrentUser(info) {
		return false
	}
	file, err := os.Open(installer)
	if err != nil {
		return false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 512))
	return err == nil && strings.Contains(string(data), "\n"+updateInstallerMarker+"\n")
}

func runManagedUpdates(ctx context.Context, state credentials) {
	client := newManagerClient(state)
	defer client.http.CloseIdleConnections()
	ticker := time.NewTicker(configPollInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		var attempt updateAttempt
		if err := readPrivateJSON(updateAttemptFile, &attempt); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("read managed update attempt: %v", err)
			return
		}
		poll := protocol.UpdatePoll{Ready: selectUpdateInstaller(state.NodeID) != "", Version: version}
		if attempt.Failed && protocol.ValidUpdateID(attempt.ID) {
			poll.FailedID = attempt.ID
		}
		var offer *protocol.UpdateOffer
		err := client.request(ctx, http.MethodPost, protocol.UpdatePollPath, poll, &offer, true)
		if authFailure(err) {
			return
		}
		if err == nil && ctx.Err() == nil && poll.Ready && offer != nil && offer.Valid() &&
			offer.ID != attempt.ID && protocol.NewerVersion(offer.Version, version) {
			if err := startManagedUpdate(state.NodeID, *offer); err != nil {
				log.Printf("start managed update: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func startManagedUpdate(nodeID string, offer protocol.UpdateOffer) error {
	if !offer.Valid() {
		return errors.New("invalid managed update offer")
	}
	installer := selectUpdateInstaller(nodeID)
	if installer == "" {
		return errors.New("no compatible local installer")
	}
	// Persist the attempt before starting the installer to deduplicate polls
	// and process restarts. The installer can outlive this agent's shutdown.
	attempt := updateAttempt{ID: offer.ID}
	if err := writePrivateJSON(updateAttemptFile, attempt); err != nil {
		return err
	}
	logFile, err := os.OpenFile("update.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		attempt.Failed = true
		if saveErr := writePrivateJSON(updateAttemptFile, attempt); saveErr != nil {
			log.Printf("save managed update failure: %v", saveErr)
		}
		return err
	}
	defer logFile.Close()
	const wrapper = "if /bin/bash \"$1\" --update --managed-version \"$2\" --installer-sha256 \"$3\"; then exit 0; fi\n" +
		"umask 077\nfile=$(mktemp .update-attempt.XXXXXXXX) || exit 1\n" +
		"printf '{\"ID\":\"%s\",\"Failed\":true}\\n' \"$4\" > \"$file\" && mv -f -- \"$file\" update-attempt.json\n"
	command := exec.Command("/bin/bash", "-c", wrapper, "link-observatory-update", installer, offer.Version, offer.InstallerSHA256, offer.ID)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		attempt.Failed = true
		if saveErr := writePrivateJSON(updateAttemptFile, attempt); saveErr != nil {
			log.Printf("save managed update failure: %v", saveErr)
		}
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}
