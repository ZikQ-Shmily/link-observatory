package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestProbeScheduleUpdatePreservesHistoryAndNegotiatesConfig(t *testing.T) {
	now := time.Now()
	filename := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(filename, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := loadState(filename, now)
	if err != nil {
		t.Fatal(err)
	}
	oldInterval := protocol.DefaultIntervalSeconds
	if state.ProbeIntervalSeconds != oldInterval {
		t.Fatalf("legacy snapshot interval = %d", state.ProbeIntervalSeconds)
	}
	history := roundStatus{At: time.Unix(state.LastEvaluated, 0).UTC(), Status: verdictSuspectedPort}
	state.Targets["t"] = targetRecord{
		Target: protocol.Target{ID: "t"}, CreatedAt: now.Add(-time.Hour),
		History: []roundStatus{history}, CandidateWindows: 2, RecoveryWindows: 1, CandidateStatus: verdictSuspectedPort,
	}
	state.Events = append(state.Events, eventRecord{ID: "e", TargetID: "t", State: "active"})
	state.Nodes["probe"] = nodeRecord{ID: "probe", Credential: digest("credential"), LastSeen: now.Add(-4 * time.Minute).Unix()}
	s := &server{
		state: state, filename: filename,
		sessions: map[string]time.Time{"admin": now.Add(time.Hour)},
	}

	request := func(method, path string, body any, scheduled bool, status int) *httptest.ResponseRecorder {
		t.Helper()
		req := scheduleRequest(t, method, path, body)
		req.AddCookie(s.cookie("admin", 60))
		if scheduled {
			req.Header.Set(protocol.ScheduleHeader, "1")
		}
		got := httptest.NewRecorder()
		s.routes().ServeHTTP(got, req)
		if got.Code != status {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, got.Code, status, got.Body)
		}
		return got
	}
	readConfig := func(scheduled bool) protocol.Config {
		t.Helper()
		reply := request(http.MethodGet, "/api/agent/config", nil, scheduled, 200)
		var config protocol.Config
		if err := json.Unmarshal(reply.Body.Bytes(), &config); err != nil {
			t.Fatal(err)
		}
		return config
	}
	if config := readConfig(true); config.IntervalSeconds != oldInterval || config.ScheduleStart != 0 {
		t.Fatalf("initial config = %+v", config)
	}

	const settingsPath = "/api/admin/settings"
	request(http.MethodPut, settingsPath, map[string]int{"probe_interval_seconds": 61}, false, 400)
	const interval = 300
	change := map[string]int{"probe_interval_seconds": interval}
	request(http.MethodPut, settingsPath, change, false, 204)
	start := s.state.ScheduleStart
	if start%interval != 0 || start <= now.Unix() || s.state.LastEvaluated != start-interval {
		t.Fatalf("invalid transition start/checkpoint: %d/%d", start, s.state.LastEvaluated)
	}
	checkpoint := start - interval
	if got := s.state.Targets["t"]; got.CandidateWindows != 0 || got.RecoveryWindows != 0 || got.CandidateStatus != "" {
		t.Fatalf("old counters carried across cadence: %+v", got)
	}
	if config := readConfig(false); config.IntervalSeconds != oldInterval || config.ScheduleStart != 0 {
		t.Fatalf("legacy config changed: %+v", config)
	}
	if config := readConfig(true); config.IntervalSeconds != interval || config.ScheduleStart != start {
		t.Fatalf("schedule-aware config = %+v", config)
	}

	reply := request(http.MethodGet, "/api/admin/state", nil, false, 200)
	var view adminView
	if err := json.Unmarshal(reply.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.ProbeIntervalSeconds != interval || view.ProbeScheduleStart != start || view.Nodes[0].State != "offline" ||
		view.Targets[0].Verdict != verdictInsufficient {
		t.Fatalf("unexpected admin view after schedule change: %+v", view)
	}

	persisted, err := loadState(filename, now)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ProbeIntervalSeconds != interval || persisted.ScheduleStart != start ||
		persisted.Events[0].State != "active" || !persisted.Targets["t"].History[0].At.Equal(history.At) {
		t.Fatalf("transition did not preserve persisted state: %+v", persisted)
	}

	s.evaluateClosedWindows(time.Unix(start+interval-1, 0))
	if s.state.LastEvaluated != checkpoint || len(s.state.Targets["t"].History) != 1 {
		t.Fatal("evaluated inside the transition window")
	}
	s.evaluateClosedWindows(time.Unix(start+interval, 0))
	rounds := s.state.Targets["t"].History
	if len(rounds) != 2 || rounds[1].At.Unix() != start || s.state.Events[0].State != "active" {
		t.Fatalf("incorrect evaluation across transition: %+v %+v", rounds, s.state.Events)
	}
	request(http.MethodPut, settingsPath, change, false, 204)
	if s.state.ScheduleStart != start || s.state.LastEvaluated != start {
		t.Fatal("saving the same cadence reset the active schedule")
	}
}

func TestLegacyReportsUseOnlyCurrentCadence(t *testing.T) {
	now := time.Now()
	const interval = 300
	window := protocol.WindowStart(now.Unix(), interval)
	s := &server{
		filename: filepath.Join(t.TempDir(), "state.json"),
		state: diskState{
			ProbeIntervalSeconds: interval, ScheduleStart: window,
			Nodes:   map[string]nodeRecord{"probe": {ID: "probe", Credential: digest("credential")}},
			Targets: map[string]targetRecord{"t": {Target: protocol.Target{ID: "t"}}},
			Samples: make(map[string]map[string]sampleSeries),
		},
	}
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	sample := func(at int64) protocol.Result {
		return protocol.Result{TargetID: "t", Window: at, TCP: ok, ICMP: ok}
	}
	report := func(results ...protocol.Result) {
		t.Helper()
		req := scheduleRequest(t, http.MethodPost, "/api/agent/report", protocol.Report{Results: results})
		got := httptest.NewRecorder()
		s.routes().ServeHTTP(got, req)
		if got.Code != 204 {
			t.Fatalf("legacy report = %d: %s", got.Code, got.Body)
		}
	}
	report(sample(window-interval), sample(window-protocol.DefaultIntervalSeconds))
	if len(s.state.Samples["probe"]["t"].Results) != 0 || s.state.Nodes["probe"].LastSeen < now.Unix() {
		t.Fatal("off-schedule samples should be ignored while their heartbeat is kept")
	}
	report(sample(window-interval), sample(window-protocol.DefaultIntervalSeconds), sample(window))
	results := s.state.Samples["probe"]["t"].Results
	if len(results) != 1 || results[0].Window != window {
		t.Fatalf("legacy report accepted samples outside active cadence: %+v", results)
	}
}

func scheduleRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	var content []byte
	if body != nil {
		var err error
		content, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(content))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Node-ID", "probe")
	req.Header.Set("Authorization", "Bearer credential")
	return req
}
