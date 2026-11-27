package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestProbeHostMetricsReports(t *testing.T) {
	const auth = "agent-credential"
	const probeID, runnerID = "probe", "runner"
	now := time.Now().UTC()
	s := newPasswordTestServer(t)
	s.sessions["admin"] = now.Add(time.Hour)
	s.state.Nodes[probeID] = nodeRecord{ID: probeID, Credential: digest(auth)}
	s.state.RouteRunners = map[string]nodeRecord{
		runnerID: {ID: runnerID, ReturnTarget: "target", Credential: digest(auth)},
	}
	s.state.Targets["target"] = targetRecord{Target: protocol.Target{ID: "target", IP: "192.0.2.1", Port: 443}}
	router := s.routes()
	agentRequest := func(id, method, path string, input any, status int) *httptest.ResponseRecorder {
		t.Helper()
		req := scheduleRequest(t, method, path, input)
		req.Header.Set("X-Node-ID", id)
		req.Header.Set("Authorization", "Bearer "+auth)
		reply := httptest.NewRecorder()
		router.ServeHTTP(reply, req)
		passwordStatus(t, reply, status)
		return reply
	}
	for _, id := range []string{probeID, runnerID} {
		reply := agentRequest(id, http.MethodGet, "/api/agent/config", nil, http.StatusOK)
		var config protocol.Config
		if err := json.Unmarshal(reply.Body.Bytes(), &config); err != nil {
			t.Fatal(err)
		}
		if config.HostMetrics != (id == probeID) {
			t.Fatalf("host metrics capability for %s = %t", id, config.HostMetrics)
		}
	}

	post := func(id string, input any) {
		t.Helper()
		agentRequest(id, http.MethodPost, "/api/agent/report", input, http.StatusNoContent)
	}
	cpu := 0.0
	observed := now.Add(-time.Minute)
	valid := protocol.HostMetrics{
		ObservedAt: observed, OS: " Debian 12 ", Arch: "arm64", CPUCores: 4, CPUUsage: &cpu,
		Memory: &protocol.MetricCapacity{TotalBytes: 8192, UsedBytes: 4500},
		Disk:   &protocol.MetricCapacity{TotalBytes: 16384, UsedBytes: 9000},
	}
	post(probeID, protocol.Report{Metrics: &valid})
	post(runnerID, protocol.Report{Metrics: &valid})
	if s.state.RouteRunners[runnerID].Metrics != nil {
		t.Fatal("return runner unexpectedly stored host metrics")
	}

	for _, stamp := range []time.Time{observed.Add(-time.Second), observed, now.Add(time.Hour)} {
		superseded := valid
		superseded.ObservedAt, superseded.OS = stamp, "Old or future data"
		post(probeID, protocol.Report{Metrics: &superseded})
	}
	post(probeID, protocol.Report{})
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	sample := protocol.Result{TargetID: "target", Window: protocol.WindowStart(now.Unix(), protocol.DefaultIntervalSeconds), TCP: ok, ICMP: ok}
	post(probeID, map[string]any{
		"results": []protocol.Result{sample},
		"metrics": map[string]string{"observed_at": "not a timestamp", "cpu_cores": "not a number"},
	})
	if got := s.state.Samples[probeID]["target"].Results; len(got) != 1 || got[0].TCP.Status != "ok" {
		t.Fatalf("malformed optional metrics interfered with probe results: %+v", got)
	}

	persisted, err := loadState(s.filename, now)
	if err != nil {
		t.Fatal(err)
	}
	s.state = persisted
	unauth := httptest.NewRecorder()
	router.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/api/admin/state", nil))
	passwordStatus(t, unauth, http.StatusUnauthorized)
	reply := adminTestRequest(t, s, http.MethodGet, "/api/admin/state", nil, http.StatusOK)
	var state adminView
	if err := json.Unmarshal(reply.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	got := state.Nodes[0].Metrics
	if got == nil || !got.ObservedAt.Equal(observed) || got.OS != "Debian 12" || got.Arch != valid.Arch ||
		got.CPUCores != 4 || got.CPUUsage == nil || *got.CPUUsage != 0 ||
		got.Memory == nil || *got.Memory != *valid.Memory || got.Disk == nil || *got.Disk != *valid.Disk {
		t.Fatalf("unexpected persisted or exposed metrics: %+v", got)
	}
}

func TestHostMetricsKeepsValidFields(t *testing.T) {
	now := time.Now().UTC()
	invalidUsage := 110.0
	report := protocol.HostMetrics{
		ObservedAt: now, OS: "Debian\n12", Arch: "amd64", CPUCores: -8, CPUUsage: &invalidUsage,
		Memory: &protocol.MetricCapacity{TotalBytes: 64, UsedBytes: 65},
		Disk:   &protocol.MetricCapacity{TotalBytes: 500},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	got := latestHostMetrics(nil, raw, now)
	if got == nil || got.OS != "" || got.Arch != report.Arch || got.CPUCores != 0 ||
		got.CPUUsage != nil || got.Memory != nil || got.Disk == nil || *got.Disk != *report.Disk {
		t.Fatalf("unexpected validation result: %+v", got)
	}
}
