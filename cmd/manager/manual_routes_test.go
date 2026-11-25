package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestManualTraceWhenPeriodicTracingDisabled(t *testing.T) {
	const (
		targetID = "target-a"
		probeID  = "probe-a"
		runnerID = "return-a"
		otherID  = "other"
		endpoint = "203.0.113.42"
		egress   = "8.8.4.4"
		path     = "/api/admin/targets/" + targetID + "/routes"
	)
	s := newPasswordTestServer(t)
	now := time.Now()
	s.sessions["admin"] = now.Add(time.Hour)
	s.state.Nodes[probeID] = nodeRecord{
		ID: probeID, Credential: digest(probeID), LastSeen: now.Unix(),
		Egress4: egressAddress{IP: egress, At: now.Unix()},
	}
	s.state.Nodes[otherID] = nodeRecord{ID: otherID, Credential: digest(otherID), LastSeen: now.Unix()}
	s.state.RouteRunners = map[string]nodeRecord{
		runnerID: {ID: runnerID, Credential: digest(runnerID), LastSeen: now.Unix(), ReturnTarget: targetID},
	}
	target := targetRecord{
		Target:       protocol.Target{ID: targetID, IP: endpoint, Port: 443},
		ReturnRunner: runnerID,
		Route:        routeSettings{Enabled: false, Minutes: 360},
	}
	s.state.Targets[targetID] = target
	window := protocol.WindowStart(now.Unix(), 360*60) - 360*60
	scheduled := protocol.RouteResult{
		Job: protocol.RouteJob{
			TargetID: targetID, Generation: target.routeGeneration(), ProbeID: probeID,
			Direction: protocol.RouteOut, Family: 4, Address: endpoint, SourceIP: egress, Window: window,
		},
		IP:   endpoint,
		Hops: []protocol.RouteHop{{TTL: 1, IP: "198.51.100.7"}, {TTL: 2, IP: endpoint}},
	}
	key := routeKey(scheduled.Job)
	baseline := routeSeries{Baseline: scheduled, Latest: scheduled, UpdatedAt: window}
	s.state.Routes = map[string]routeSeries{key: baseline}

	handler := s.routes()
	agentPost := func(id, endpoint string, input any, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := scheduleRequest(t, http.MethodPost, endpoint, input)
		req.Header.Set("X-Node-ID", id)
		req.Header.Set("Authorization", "Bearer "+id)
		reply := httptest.NewRecorder()
		handler.ServeHTTP(reply, req)
		passwordStatus(t, reply, want)
		return reply
	}
	poll := func(id string) []protocol.RouteJob {
		t.Helper()
		reply := agentPost(id, protocol.RoutePollPath, protocol.RoutePoll{Manual: true, Ready: true}, http.StatusOK)
		var jobs []protocol.RouteJob
		if err := json.Unmarshal(reply.Body.Bytes(), &jobs); err != nil {
			t.Fatal(err)
		}
		return jobs
	}
	start := func() *httptest.ResponseRecorder {
		t.Helper()
		return adminTestRequest(t, s, http.MethodPost, path+"/trace", nil, http.StatusAccepted)
	}
	type progress struct {
		State       string `json:"state"`
		RequestedAt int64  `json:"requested_at"`
		Done        int    `json:"done"`
		Total       int    `json:"total"`
	}
	readView := func(want progress) []protocol.RouteResult {
		t.Helper()
		reply := adminTestRequest(t, s, http.MethodGet, path, nil, http.StatusOK)
		var view struct {
			Enabled bool                   `json:"enabled"`
			Manual  *progress              `json:"manual"`
			Routes  []protocol.RouteResult `json:"routes"`
		}
		if err := json.Unmarshal(reply.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if view.Enabled || view.Manual == nil || *view.Manual != want {
			t.Fatalf("unexpected route trace view: %s; want disabled periodic trace and %+v", reply.Body, want)
		}
		return view.Routes
	}
	if jobs := poll(probeID); len(jobs) != 0 {
		t.Fatalf("disabled target gave the probe routine jobs: %+v", jobs)
	}
	if jobs := poll(runnerID); len(jobs) != 0 {
		t.Fatalf("disabled target gave the return runner routine jobs: %+v", jobs)
	}

	var running progress
	if err := json.Unmarshal(start().Body.Bytes(), &running); err != nil {
		t.Fatal(err)
	}
	if running.State != "running" || running.RequestedAt < now.Unix() || running.Total != 2 || running.Done != 0 {
		t.Fatalf("unexpected initial manual trace progress: %+v", running)
	}
	readView(running)

	forwardJobs, returnJobs := poll(probeID), poll(runnerID)
	if len(forwardJobs) != 1 || len(returnJobs) != 1 {
		t.Fatalf("expected one job from each agent, got forward %+v and return %+v", forwardJobs, returnJobs)
	}
	forward, reverse := forwardJobs[0], returnJobs[0]
	if forward.ManualID == "" || reverse.ManualID != forward.ManualID ||
		forward.Direction != protocol.RouteOut || reverse.Direction != protocol.RouteBack ||
		forward.Address != endpoint || reverse.Address != egress ||
		forward.ProbeID != probeID || reverse.ProbeID != probeID || forward.TargetID != targetID || reverse.TargetID != targetID {
		t.Fatalf("incorrect manual trace jobs: forward %+v, return %+v", forward, reverse)
	}
	forwardResult := protocol.RouteResult{
		Job: forward, IP: endpoint, Hops: []protocol.RouteHop{{TTL: 1, IP: "198.51.100.9"}, {TTL: 2, IP: endpoint}},
	}
	agentPost(otherID, protocol.RouteResultPath, forwardResult, http.StatusConflict)
	agentPost(probeID, protocol.RouteResultPath, forwardResult, http.StatusNoContent)
	agentPost(probeID, protocol.RouteResultPath, forwardResult, http.StatusNoContent)

	running.Done = 1
	var repeat progress
	if err := json.Unmarshal(start().Body.Bytes(), &repeat); err != nil {
		t.Fatal(err)
	}
	if repeat != running {
		t.Fatalf("repeated start changed the in-flight request: %+v, expected %+v", repeat, running)
	}
	readView(running)

	reverseResult := protocol.RouteResult{
		Job: reverse, IP: egress, Hops: []protocol.RouteHop{{TTL: 1, IP: egress}},
	}
	agentPost(runnerID, protocol.RouteResultPath, reverseResult, http.StatusNoContent)
	agentPost(runnerID, protocol.RouteResultPath, reverseResult, http.StatusNoContent)
	running.State, running.Done = "completed", 2
	results := readView(running)
	if len(results) != 2 {
		t.Fatalf("manual trace results missing from route view: %+v", results)
	}
	for _, result := range results {
		if result.Job.ManualID != forward.ManualID {
			t.Fatalf("route view presented an outdated result: %+v", result)
		}
	}
	if len(s.state.Routes) != 1 || !reflect.DeepEqual(s.state.Routes[key], baseline) || len(s.state.RouteChanges) != 0 {
		t.Fatal("a manual trace altered the scheduled observations or baselines")
	}
}

func TestLongRouteIntervalsAreAppliedPerTarget(t *testing.T) {
	const path = "/api/admin/targets/target-a/routes"
	s := newPasswordTestServer(t)
	s.sessions["admin"] = time.Now().Add(time.Hour)
	s.state.Targets["target-a"] = targetRecord{Target: protocol.Target{ID: "target-a"}}
	s.state.Targets["target-b"] = targetRecord{
		Target: protocol.Target{ID: "target-b"},
		Route:  routeSettings{Enabled: true, Minutes: 15},
	}
	for _, minutes := range []int{360, 720, 1440, 2880} {
		settings := routeSettings{Enabled: true, Minutes: minutes}
		adminTestRequest(t, s, http.MethodPut, path, settings, http.StatusNoContent)
		reply := adminTestRequest(t, s, http.MethodGet, path, nil, http.StatusOK)
		var view routeSettings
		if err := json.Unmarshal(reply.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if !view.Enabled || view.Minutes != minutes || s.state.Targets["target-a"].routeStep() != int64(minutes)*60 {
			t.Fatalf("target's %d-minute route interval was not applied: %s", minutes, reply.Body)
		}
	}
	settings := routeSettings{Enabled: true, Minutes: 361}
	adminTestRequest(t, s, http.MethodPut, path, settings, http.StatusBadRequest)
	if s.state.Targets["target-a"].routeStep() != 2880*60 || s.state.Targets["target-b"].routeStep() != 15*60 {
		t.Fatal("one target's route interval update affected existing settings")
	}
}
