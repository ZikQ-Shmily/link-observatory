package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestManagedUpdateQueuesAndConfirmsPerInstance(t *testing.T) {
	s := newPasswordTestServer(t)
	s.cfg.releaseURL = officialReleaseDownloadPrefix + "v2.2.0"
	s.cfg.installHash = strings.Repeat("a", 64)
	const auth = "test-probe-key"
	s.state.Nodes["probe"] = nodeRecord{ID: "probe", Credential: digest(auth), Version: "v2.0.1"}
	s.state.RouteRunners = map[string]nodeRecord{
		"runner": {ID: "runner", Credential: digest(auth), Version: "v2.1.0", ReturnTarget: "target"},
	}
	s.state.Targets["target"] = targetRecord{Target: protocol.Target{ID: "target"}, ReturnRunner: "runner"}

	handler := s.routes()
	login := passwordRequest(handler, http.MethodPost, "/api/admin/login", s.cfg.publicURL, nil, map[string]string{"password": bootstrapPassword})
	cookie := passwordSession(t, login)
	queue := func(endpoint string, status int) {
		t.Helper()
		w := passwordRequest(handler, http.MethodPost, "/api/admin/"+endpoint, s.cfg.publicURL, cookie, nil)
		passwordStatus(t, w, status)
	}
	poll := func(id string, ready bool, version, failed string) *protocol.UpdateOffer {
		t.Helper()
		raw, err := json.Marshal(protocol.UpdatePoll{Version: version, Ready: ready, FailedID: failed})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, protocol.UpdatePollPath, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Node-ID", id)
		r.Header.Set("Authorization", "Bearer "+auth)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		passwordStatus(t, w, 200)
		var offer *protocol.UpdateOffer
		if err := json.Unmarshal(w.Body.Bytes(), &offer); err != nil {
			t.Fatal(err)
		}
		return offer
	}
	queue("nodes/probe/update", http.StatusConflict)
	if poll("runner", true, "v2.1.0", "") != nil {
		t.Fatal("unexpected update")
	}
	queue("targets/target/return-update", http.StatusAccepted)
	task := poll("runner", true, "v2.1.0", "")
	if task == nil || !task.Valid() || task.Version != "v2.2.0" {
		t.Fatalf("invalid runner offer: %+v", task)
	}
	if poll("probe", true, "v2.1.0", "") != nil {
		t.Fatal("probe received a task for a different instance")
	}
	queue("targets/target/return-update", http.StatusAccepted)
	if repeated := poll("runner", true, "v2.1.0", ""); repeated == nil || *repeated != *task {
		t.Fatalf("running task changed: %+v", repeated)
	}
	if offer := poll("runner", true, "v2.1.0", task.ID); offer != nil || s.state.RouteRunners["runner"].Update.Status != "failed" {
		t.Fatal("failed update was not recorded")
	}
	queue("targets/target/return-update", http.StatusAccepted)
	retry := poll("runner", true, "v2.1.0", "")
	if retry == nil || retry.ID == task.ID {
		t.Fatal("retry did not get a new task ID")
	}
	poll("runner", true, "v2.2.0", "")
	persisted, err := loadState(s.filename, time.Now())
	if err != nil || persisted.RouteRunners["runner"].Update.Status != "succeeded" {
		t.Fatalf("success did not persist: %v", err)
	}
	queue("targets/target/return-update", http.StatusConflict)
}

func TestLegacyMailSelectionsGroupBothOutcomes(t *testing.T) {
	s := newPasswordTestServer(t)
	s.state.Mail = mailSettings{Enabled: true, Events: []mailKind{mailProbeRecovery, mailTCPFailure, mailICMPRecovery}}
	if err := writeState(s.filename, s.state); err != nil {
		t.Fatal(err)
	}
	saved, err := loadState(s.filename, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []mailKind{mailProbeOffline, mailProbeRecovery, mailTCPFailure, mailTCPRecovery, mailICMPFailure, mailICMPRecovery} {
		if !saved.Mail.wants(kind) {
			t.Errorf("expected %s to be enabled", kind)
		}
	}
	if len(saved.Mail.Events) != 3 || saved.Mail.wants(mailRouteChange) {
		t.Fatalf("unexpected migration result: %v", saved.Mail.Events)
	}
}
