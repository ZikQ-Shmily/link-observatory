package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestBatchManagedUpdatesQueueEligibleAgents(t *testing.T) {
	s := newPasswordTestServer(t)
	now := time.Now()
	s.sessions["admin"] = now.Add(time.Hour)
	const version, endpoint = "v2.2.0", "/api/admin/updates"
	releaseURL := officialReleaseDownloadPrefix + version
	s.cfg.releaseURL = releaseURL
	s.cfg.installHash = strings.Repeat("a", 64)
	ready := nodeRecord{ID: "probe-ready", LastSeen: now.Unix(), ManagedUpdates: true, Credential: "registered", Version: "v2.1.5"}
	active := updateTask{Status: "running", ExpiresAt: now.Add(time.Minute).Unix()}
	s.state.Nodes[ready.ID] = ready
	addProbe := func(id string, edit func(*nodeRecord)) {
		node := ready
		node.ID = id
		edit(&node)
		s.state.Nodes[id] = node
	}
	addProbe("probe-active", func(node *nodeRecord) { node.Update = active })
	addProbe("probe-current", func(node *nodeRecord) { node.Version = version })
	addProbe("probe-newer", func(node *nodeRecord) { node.Version = "v2.3.0" })
	addProbe("probe-offline", func(node *nodeRecord) { node.LastSeen = now.Add(-offlineAfter - time.Second).Unix() })
	addProbe("probe-unseen", func(node *nodeRecord) { node.LastSeen = 0 })
	addProbe("probe-legacy", func(node *nodeRecord) { node.ManagedUpdates = false })
	addProbe("probe-pending", func(node *nodeRecord) { node.Credential = "" })
	addProbe("probe-version-unknown", func(node *nodeRecord) { node.Version = "dev" })
	runner := ready
	runner.ID, runner.ReturnTarget = "runner-ready", "target"
	orphan := runner
	orphan.ID = "runner-orphan"
	s.state.RouteRunners = map[string]nodeRecord{runner.ID: runner, orphan.ID: orphan}
	s.state.Targets[runner.ReturnTarget] = targetRecord{Target: protocol.Target{ID: runner.ReturnTarget}, ReturnRunner: runner.ID}

	handler := s.routes()
	session := s.cookie("admin", 60)
	passwordStatus(t, passwordRequest(handler, http.MethodPost, endpoint, s.cfg.publicURL, nil, nil), http.StatusUnauthorized)
	passwordStatus(t, passwordRequest(handler, http.MethodPost, endpoint, "https://other.example.com", session, nil), http.StatusForbidden)
	s.cfg.releaseURL = releaseURL + "-rc.1"
	adminTestRequest(t, s, http.MethodPost, endpoint, nil, http.StatusConflict)
	s.cfg.releaseURL = releaseURL

	filename := s.filename
	s.filename = filepath.Join(filepath.Dir(filename), "missing", "state.json")
	adminTestRequest(t, s, http.MethodPost, endpoint, nil, http.StatusInternalServerError)
	if s.state.Nodes[ready.ID].Update.Status != "" || s.state.RouteRunners[runner.ID].Update.Status != "" {
		t.Fatal("uncommitted update tasks escaped into the running state")
	}
	s.filename = filename
	queue := func(status int) bulkUpdateSummary {
		t.Helper()
		reply := adminTestRequest(t, s, http.MethodPost, endpoint, nil, status)
		var summary bulkUpdateSummary
		if err := json.Unmarshal(reply.Body.Bytes(), &summary); err != nil {
			t.Fatal(err)
		}
		return summary
	}
	summary := queue(http.StatusAccepted)
	skipped := summary.Skipped
	if summary.Version != version || summary.Queued.Probes != 1 || summary.Queued.ReturnRunners != 1 ||
		skipped.UpToDate != 2 || skipped.Active != 1 || skipped.Offline != 2 || skipped.Unsupported != 1 ||
		skipped.Unregistered != 1 || skipped.VersionUnavailable != 1 {
		t.Fatalf("unexpected batch summary: %+v", summary)
	}
	saved, err := loadState(filename, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	probeTask, runnerTask := saved.Nodes[ready.ID].Update, saved.RouteRunners[runner.ID].Update
	for _, task := range []updateTask{probeTask, runnerTask} {
		if task.Status != "queued" || !task.Batch || !task.Offer.Valid() || task.Offer.Version != version || task.Offer.InstallerSHA256 != s.cfg.installHash ||
			task.ExpiresAt < now.Add(batchUpdateWait).Unix() {
			t.Fatalf("invalid saved update task: %+v", task)
		}
	}
	if probeTask.Offer.ID == runnerTask.Offer.ID || saved.RouteRunners[orphan.ID].Update.Status != "" {
		t.Fatal("batch assigned a duplicate ID or queued an unbound return runner")
	}
	second := queue(http.StatusOK)
	if second.Queued.Probes != 0 || second.Queued.ReturnRunners != 0 || second.Skipped.Active != 3 ||
		s.state.Nodes[ready.ID].Update != probeTask || s.state.RouteRunners[runner.ID].Update != runnerTask || s.state.Nodes["probe-active"].Update != active {
		t.Fatalf("retry queued or changed an active task: %+v", second)
	}
}

func TestBatchManagedUpdatesSerializeClaims(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	queuedAt := now.Add(-updateTimeout - time.Minute)
	const old, version = "v2.1.5", "v2.2.0"
	makeAgent := func(id, returnTarget, key string, batch bool, start time.Time) nodeRecord {
		offer := protocol.UpdateOffer{ID: strings.Repeat(key, 32), Version: version, InstallerSHA256: strings.Repeat("a", 64)}
		return nodeRecord{ID: id, ReturnTarget: returnTarget, Version: old, Update: queuedUpdate(offer, start, batch)}
	}
	state := diskState{
		Nodes: map[string]nodeRecord{
			"batch":   makeAgent("batch", "", "b", true, queuedAt),
			"single1": makeAgent("single1", "", "c", false, now),
			"single2": makeAgent("single2", "", "d", false, now),
		},
		RouteRunners: map[string]nodeRecord{"runner": makeAgent("runner", "target", "e", true, queuedAt)},
	}
	poll := func(id, installed string, at time.Time) *protocol.UpdateOffer {
		node, _ := state.lookupAgent(id)
		offer := state.applyUpdatePoll(&node, protocol.UpdatePoll{Version: installed, Ready: true}, at)
		state.setAgent(node)
		return offer
	}
	if poll("single1", old, now) == nil || poll("single2", old, now) == nil {
		t.Fatal("queued batch work prevented single-only claims")
	}
	if poll("batch", old, now) != nil {
		t.Fatal("batch claimed while single updates were running")
	}
	if task := state.Nodes["batch"].Update; task.Status != "queued" || task.ExpiresAt != queuedAt.Add(batchUpdateWait).Unix() {
		t.Fatalf("waiting batch task changed: %+v", task)
	}
	poll("single1", version, now)
	poll("single2", version, now)
	claimAt := now.Add(updateLockReleaseGrace)
	if poll("batch", old, claimAt.Add(-time.Nanosecond)) != nil {
		t.Fatal("batch claimed before the completed worker's lock release grace")
	}
	first := poll("batch", old, claimAt)
	deadline := claimAt.Add(updateTimeout).Unix()
	if first == nil || state.Nodes["batch"].Update.ExpiresAt != deadline {
		t.Fatal("claim did not start a fresh execution deadline after waiting")
	}
	state.setAgent(makeAgent("single3", "", "f", false, claimAt))
	if poll("runner", old, claimAt) != nil || poll("single3", old, claimAt) != nil {
		t.Fatal("another agent claimed while the batch worker was running")
	}
	completedAt := claimAt.Add(time.Minute)
	if resumed := poll("batch", old, completedAt); resumed == nil || *resumed != *first || state.Nodes["batch"].Update.ExpiresAt != deadline {
		t.Fatal("running worker did not resume its original offer and deadline")
	}
	poll("batch", version, completedAt)
	if poll("runner", old, completedAt) != nil || poll("single3", old, completedAt) != nil {
		t.Fatal("agent claimed during the batch worker's lock release grace")
	}
	if poll("runner", old, completedAt.Add(updateLockReleaseGrace)) == nil {
		t.Fatal("next batch task did not claim after the prior worker completed")
	}
}

func TestBatchManagedUpdateSupersededByReportedVersion(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	offer := protocol.UpdateOffer{ID: strings.Repeat("b", 32), Version: "v2.2.0", InstallerSHA256: strings.Repeat("a", 64)}
	node := nodeRecord{Version: "v2.1.5", Update: queuedUpdate(offer, now, true)}
	const newer = "v2.3.0"
	state := diskState{}
	if assigned := state.applyUpdatePoll(&node, protocol.UpdatePoll{Version: newer, Ready: true}, now); assigned != nil ||
		node.Version != newer || node.Update.Status != "superseded" || node.Update.Offer != offer || node.Update.view(now) != nil || node.Update.active(now) {
		t.Fatalf("newer version did not retire the old batch offer: %+v", node)
	}
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
