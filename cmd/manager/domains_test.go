package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestHostnameTargetConfigCompatibilityAndResolvedObservation(t *testing.T) {
	now := time.Now()
	filename := filepath.Join(t.TempDir(), "state.json")
	state, err := loadState(filename, now)
	if err != nil {
		t.Fatal(err)
	}
	state.ProbeIntervalSeconds = 300
	state.Targets["literal"] = targetRecord{Target: protocol.Target{ID: "literal", IP: "192.0.2.1", Port: 443}}
	state.Nodes["probe"] = nodeRecord{ID: "probe", Credential: digest("credential")}
	s := &server{
		state: state, filename: filename,
		sessions: map[string]time.Time{"admin": now.Add(time.Hour)},
	}
	routes := s.routes()
	request := func(method, path string, body any, headers map[string]string, status int, reply any) {
		t.Helper()
		req := scheduleRequest(t, method, path, body)
		req.AddCookie(s.cookie("admin", 60))
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		got := httptest.NewRecorder()
		routes.ServeHTTP(got, req)
		if got.Code != status {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, got.Code, status, got.Body)
		}
		if reply != nil {
			if err := json.Unmarshal(got.Body.Bytes(), reply); err != nil {
				t.Fatal(err)
			}
		}
	}
	targetBody := map[string]any{"name": "Example API", "ip": " API.Example.COM. ", "port": 443}
	var target targetView
	request(http.MethodPost, "/api/admin/targets", targetBody, nil, http.StatusCreated, &target)
	if target.IP != "api.example.com" {
		t.Fatalf("target address was not normalized: %q", target.IP)
	}
	targetBody["ip"] = "api.example.com"
	request(http.MethodPost, "/api/admin/targets", targetBody, nil, http.StatusConflict, nil)

	var config protocol.Config
	request(http.MethodGet, "/api/agent/config", nil, map[string]string{protocol.ScheduleHeader: "1"}, http.StatusOK, &config)
	if config.IntervalSeconds != 300 || len(config.Targets) != 1 || config.Targets[0].ID != "literal" {
		t.Fatalf("hostname target leaked into unsupported config: %+v", config)
	}
	request(http.MethodGet, "/api/agent/config", nil, map[string]string{protocol.HostnamesHeader: "1"}, http.StatusOK, &config)
	if config.IntervalSeconds != protocol.DefaultIntervalSeconds || len(config.Targets) != 2 {
		t.Fatalf("hostname support incorrectly depended on dynamic scheduling: %+v", config)
	}

	probe := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	result := protocol.Result{TargetID: target.ID, Window: protocol.WindowStart(target.CreatedAt.Unix(), 300), TCP: probe, ICMP: probe}
	result.ResolvedIP = "api.example.com"
	request(http.MethodPost, "/api/agent/report", protocol.Report{Results: []protocol.Result{result}}, nil, http.StatusBadRequest, nil)
	result.ResolvedIP = "::ffff:192.0.2.2"
	request(http.MethodPost, "/api/agent/report", protocol.Report{Results: []protocol.Result{result}}, nil, http.StatusNoContent, nil)
	view := describeTarget(s.state, s.state.Targets[target.ID], target.CreatedAt)
	if len(view.Latest) != 1 || view.Latest[0].ResolvedIP != "192.0.2.2" {
		t.Fatalf("the canonical resolved IP was not returned: %+v", view.Latest)
	}
}

func TestHostnameIncidentsNeedComparableDestination(t *testing.T) {
	const step = protocol.DefaultIntervalSeconds
	const firstIP, secondIP = "192.0.2.1", "192.0.2.2"
	start := int64(1800000000)
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	timeout := protocol.Probe{Status: "timeout", Sent: 1}
	target := targetRecord{Target: protocol.Target{ID: "t", IP: "api.example.com"}}
	state := diskState{
		Nodes: map[string]nodeRecord{
			"a": {Group: "mainland", ISP: "East"},
			"b": {Group: "mainland", ISP: "West"},
			"c": {Group: "overseas", ISP: "Singapore"},
		},
		Targets: map[string]targetRecord{"t": target},
		Samples: make(map[string]map[string]sampleSeries),
	}
	addWindow := func(offset int64, domesticIP, overseasIP string, failed bool) windowEvidence {
		window := start + offset*step
		for id, node := range state.Nodes {
			resolvedIP, result := domesticIP, ok
			if failed {
				result = timeout
			}
			if node.Group == "overseas" {
				resolvedIP, result = overseasIP, ok
			}
			if state.Samples[id] == nil {
				state.Samples[id] = make(map[string]sampleSeries)
			}
			series := state.Samples[id]
			series["t"] = updateSeries(series["t"], protocol.Result{
				TargetID: "t", Window: window, ResolvedIP: resolvedIP, TCP: result, ICMP: result,
			}, window, step)
		}
		return assess(state, "t", window)
	}

	if evidence := addWindow(1, firstIP, secondIP, true); evidence.status != verdictInsufficient {
		t.Fatalf("DNS answer mismatch became blocking evidence: %+v", evidence)
	}
	if evidence := addWindow(2, firstIP, "", true); evidence.status != verdictInsufficient {
		t.Fatalf("a sample without a DNS destination became evidence: %+v", evidence)
	}
	evidence := addWindow(3, firstIP, firstIP, true)
	if evidence.status != verdictBothTimeout {
		t.Fatalf("same-IP TCP and ICMP timeouts were not detected: %+v", evidence)
	}
	recordWindow(&state, &target, evidence, start+3*step, step)
	for offset := int64(4); offset <= 6; offset++ {
		evidence := addWindow(offset, secondIP, secondIP, true)
		status := recordWindow(&state, &target, evidence, start+offset*step, step)
		if offset < 6 && (status != verdictInsufficient || len(state.Events) != 0) {
			t.Fatalf("streak carried over from a different IP at window %d", offset)
		}
	}
	if len(state.Events) != 1 || state.Events[0].ResolvedIP != secondIP || state.Events[0].Verdict != verdictBothTimeout {
		t.Fatalf("same-IP incident was not recorded: %+v", state.Events)
	}

	for offset := int64(7); offset <= 10; offset++ {
		ip := firstIP
		if offset >= 9 {
			ip = secondIP
		}
		evidence := addWindow(offset, ip, ip, false)
		recordWindow(&state, &target, evidence, start+offset*step, step)
		if offset < 10 && state.Events[0].State != "active" {
			t.Fatalf("different or single recovery prematurely resolved incident at window %d", offset)
		}
	}
	if state.Events[0].State != "resolved" {
		t.Fatalf("same-IP recovery was not applied: %+v", state.Events[0])
	}
}
