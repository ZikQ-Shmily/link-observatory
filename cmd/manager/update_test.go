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
	queue := func(endpoint string, status int) *updateView {
		t.Helper()
		w := passwordRequest(handler, http.MethodPost, "/api/admin/"+endpoint, s.cfg.publicURL, cookie, nil)
		passwordStatus(t, w, status)
		if status != http.StatusAccepted {
			return nil
		}
		var view updateView
		if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		return &view
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
	queued := queue("targets/target/return-update", http.StatusAccepted)
	task := poll("runner", true, "v2.1.0", "")
	if task == nil || !task.Valid() || task.Version != "v2.2.0" || queued.ID != task.ID || queued.Status != "queued" {
		t.Fatalf("invalid runner offer: %+v", task)
	}
	if poll("probe", true, "v2.1.0", "") != nil {
		t.Fatal("probe received a task for a different instance")
	}
	if active := queue("targets/target/return-update", http.StatusAccepted); active.ID != queued.ID || active.Status != "running" {
		t.Fatalf("unexpected in-flight task: %+v", active)
	}
	if repeated := poll("runner", true, "v2.1.0", ""); repeated == nil || *repeated != *task {
		t.Fatalf("running task changed: %+v", repeated)
	}
	if offer := poll("runner", true, "v2.1.0", task.ID); offer != nil || s.state.RouteRunners["runner"].Update.Status != "failed" {
		t.Fatal("failed update was not recorded")
	}
	queued = queue("targets/target/return-update", http.StatusAccepted)
	retry := poll("runner", true, "v2.1.0", "")
	if retry == nil || retry.ID == task.ID || queued.ID != retry.ID {
		t.Fatal("retry did not get a new task ID")
	}
	confirmedAfter := time.Now().Unix()
	poll("runner", true, "v2.2.0", "")
	persisted, err := loadState(s.filename, time.Now())
	completed := persisted.RouteRunners["runner"].Update
	if err != nil || completed.Status != "succeeded" || completed.CompletedAt < confirmedAfter {
		t.Fatalf("success did not persist: %v", err)
	}
	if view := completed.view(time.Now()); view == nil || view.Status != "succeeded" || view.ID != retry.ID {
		t.Fatalf("unexpected completed task: %+v", view)
	}
	runner := s.state.RouteRunners["runner"]
	runner.Update.CompletedAt -= 5
	s.state.RouteRunners["runner"] = runner
	poll("runner", true, "v2.2.0", "")
	if s.state.RouteRunners["runner"].Update.CompletedAt != runner.Update.CompletedAt {
		t.Fatal("repeat poll extended completion feedback")
	}
	queue("targets/target/return-update", http.StatusConflict)
}

func TestUpdateSuccessFeedbackExpires(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	task := updateTask{Status: "succeeded", Offer: protocol.UpdateOffer{Version: "v2.1.4"}, CompletedAt: now.Unix()}
	deadline := now.Add(updateSuccessFeedbackTTL)
	if got := task.view(deadline.Add(-time.Nanosecond)); got == nil ||
		got.Status != "succeeded" || got.Version != task.Offer.Version || got.SuccessUntil != deadline.Unix() {
		t.Fatalf("missing recent success feedback: %+v", got)
	}
	if got := task.view(deadline); got != nil {
		t.Fatalf("expired success feedback: %+v", got)
	}
	task.CompletedAt = 0
	if got := task.view(now); got != nil {
		t.Fatalf("legacy success should not be displayed: %+v", got)
	}
}

func TestInstalledVersionSuppressesResolvedUpdateFeedback(t *testing.T) {
	s := newPasswordTestServer(t)
	now := time.Now()
	s.sessions["admin"] = now.Add(time.Hour)
	const credential = "test-agent-key"
	task := updateTask{Status: "failed", Offer: protocol.UpdateOffer{Version: "v2.2.0"}}
	timeout := task
	timeout.Status, timeout.ExpiresAt = "running", now.Add(-time.Minute).Unix()
	s.state.Nodes["probe"] = nodeRecord{ID: "probe", Credential: digest(credential), Version: "v2.1.9", Update: task}
	s.state.Targets["target"] = targetRecord{Target: protocol.Target{ID: "target"}, ReturnRunner: "runner"}
	s.state.RouteRunners = map[string]nodeRecord{
		"runner": {ID: "runner", Credential: digest(credential), Version: "v2.1.9", ReturnTarget: "target", Update: timeout},
	}

	views := func() (*updateView, *updateView) {
		t.Helper()
		state := adminTestRequest(t, s, http.MethodGet, "/api/admin/state", nil, http.StatusOK)
		var admin adminView
		if err := json.Unmarshal(state.Body.Bytes(), &admin); err != nil {
			t.Fatal(err)
		}
		routes := adminTestRequest(t, s, http.MethodGet, "/api/admin/targets/target/routes", nil, http.StatusOK)
		var target struct {
			Update *updateView `json:"runner_update"`
		}
		if err := json.Unmarshal(routes.Body.Bytes(), &target); err != nil {
			t.Fatal(err)
		}
		return admin.Nodes[0].Update, target.Update
	}
	probe, runner := views()
	if probe == nil || probe.Status != "failed" || runner == nil || runner.Status != "expired" {
		t.Fatalf("missing unresolved feedback: probe=%+v runner=%+v", probe, runner)
	}
	for id, version := range map[string]string{"probe": "v2.2.0", "runner": "v2.3.0"} {
		req := scheduleRequest(t, http.MethodPost, "/api/agent/report", protocol.Report{Version: version})
		req.Header.Set("X-Node-ID", id)
		req.Header.Set("Authorization", "Bearer "+credential)
		reply := httptest.NewRecorder()
		s.routes().ServeHTTP(reply, req)
		passwordStatus(t, reply, http.StatusNoContent)
	}
	probe, runner = views()
	if probe != nil || runner != nil {
		t.Fatalf("resolved update feedback is still visible: probe=%+v runner=%+v", probe, runner)
	}
	if s.state.Nodes["probe"].Update != task || s.state.RouteRunners["runner"].Update != timeout {
		t.Fatal("reporting the installed version altered the recorded update tasks")
	}
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
