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

func TestEditKeepsIdentityAndRejectsOldEndpointResults(t *testing.T) {
	now := time.Now().UTC()
	window := protocol.WindowStart(now.Unix(), 60)
	reading := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	old := protocol.Result{TargetID: "first", Window: window, TCP: reading, ICMP: reading}
	state := diskState{
		ProbeIntervalSeconds: 60,
		Nodes: map[string]nodeRecord{"probe": {
			ID: "probe", Name: "Original", Location: "Jiangsu", ISP: "China Telecom",
			Group: "mainland", Credential: digest("credential"), LastSeen: now.Unix(),
		}},
		Targets: map[string]targetRecord{
			"first": {
				Target:    protocol.Target{ID: "first", Name: "Original", IP: "192.0.2.1", Port: 443},
				CreatedAt: now.Add(-time.Hour), History: []roundStatus{{At: now, Status: verdictOK}}, CandidateWindows: 2,
			},
			"second": {Target: protocol.Target{ID: "second", Name: "Another", IP: "192.0.2.2", Port: 443}},
		},
		Samples: map[string]map[string]sampleSeries{"probe": {"first": {Results: []protocol.Result{old}}}},
		Events:  []eventRecord{{TargetID: "first", TargetName: "Original", State: "active"}},
	}
	s := &server{
		state: state, filename: filepath.Join(t.TempDir(), "state.json"),
		sessions: map[string]time.Time{"admin": now.Add(time.Hour)},
	}
	routes := s.routes()
	request := func(method, path string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := scheduleRequest(t, method, path, body)
		req.AddCookie(s.cookie("admin", 60))
		resp := httptest.NewRecorder()
		routes.ServeHTTP(resp, req)
		if resp.Code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, resp.Code, want, resp.Body)
		}
		return resp
	}
	node := map[string]string{"name": "Renamed", "location": "Shanghai", "isp": "China Telecom", "group": "mainland"}
	request(http.MethodPut, "/api/admin/nodes/probe", node, http.StatusOK)
	if got := s.state.Nodes["probe"]; got.Name != "Renamed" || got.Location != "Shanghai" ||
		got.Credential != state.Nodes["probe"].Credential || len(s.state.Samples["probe"]["first"].Results) != 1 {
		t.Fatalf("metadata edit changed node identity or samples: %+v", got)
	}

	input := protocol.Target{Name: "New name", IP: "192.0.2.1", Port: 443}
	request(http.MethodPut, "/api/admin/targets/first", input, http.StatusOK)
	got := s.state.Targets["first"]
	if got.Name != input.Name || got.wireID() != "first" || len(got.History) != 1 || len(s.state.Samples["probe"]["first"].Results) != 1 {
		t.Fatalf("rename changed monitoring state: %+v", got)
	}
	input.IP = "192.0.2.2"
	request(http.MethodPut, "/api/admin/targets/first", input, http.StatusConflict)
	input.Port = 8443
	request(http.MethodPut, "/api/admin/targets/first", input, http.StatusOK)
	got = s.state.Targets["first"]
	if got.ID != "first" || got.wireID() == "first" || len(got.History) != 0 || len(s.state.Samples["probe"]["first"].Results) != 0 {
		t.Fatalf("endpoint edit did not reset old measurements: %+v", got)
	}
	if event := s.state.Events[0]; event.State != "superseded" || event.EndedAt == nil || event.TargetAddress != "192.0.2.1:443" {
		t.Fatalf("incorrect historical event after endpoint change: %+v", event)
	}
	resp := request(http.MethodGet, "/api/agent/config", nil, http.StatusOK)
	var config protocol.Config
	if err := json.Unmarshal(resp.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, target := range config.Targets {
		found = found || target.ID == got.wireID() && target.IP == input.IP && target.Port == input.Port
	}
	if !found {
		t.Fatalf("edited target missing from agent config: %+v", config.Targets)
	}
	old.Window = protocol.WindowStart(time.Now().Unix(), 60)
	request(http.MethodPost, "/api/agent/report", protocol.Report{Results: []protocol.Result{old}}, http.StatusNoContent)
	if len(s.state.Samples["probe"]["first"].Results) != 0 {
		t.Fatal("queued result for old address was accepted")
	}
	old.TargetID = got.wireID()
	request(http.MethodPost, "/api/agent/report", protocol.Report{Results: []protocol.Result{old}}, http.StatusNoContent)
	if len(s.state.Samples["probe"]["first"].Results) != 1 {
		t.Fatal("new result did not join the stable target record")
	}

	node["group"], node["isp"] = "overseas", "Other ISP"
	request(http.MethodPut, "/api/admin/nodes/probe", node, http.StatusOK)
	request(http.MethodPost, "/api/agent/report", protocol.Report{Results: []protocol.Result{old}}, http.StatusNoContent)
	if len(s.state.Samples["probe"]["first"].Results) != 0 || s.state.Nodes["probe"].Group != "overseas" {
		t.Fatal("old sample was attributed to the new probe group")
	}
}
