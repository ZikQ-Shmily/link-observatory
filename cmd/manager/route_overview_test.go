package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestAdminRouteOverview(t *testing.T) {
	s := newPasswordTestServer(t)
	now := time.Now()
	s.sessions["admin"] = now.Add(time.Hour)
	read := func() routeOverviewView {
		t.Helper()
		reply := adminTestRequest(t, s, http.MethodGet, "/api/admin/state", nil, http.StatusOK)
		var response struct {
			RouteOverview routeOverviewView `json:"route_overview"`
		}
		if err := json.Unmarshal(reply.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.RouteOverview
	}
	if got := read(); !reflect.DeepEqual(got, routeOverviewView{Changes: []routeOverviewChangeView{}}) {
		t.Fatalf("empty route overview = %+v", got)
	}

	const probeID = "probe-a"
	s.state.Nodes[probeID] = nodeRecord{ID: probeID, Name: "Changzhou"}
	makeTarget := func(id, name string, enabled bool) targetRecord {
		target := targetRecord{
			Target:       protocol.Target{ID: id, Name: name, IP: "203.0.113.45", Port: 443},
			Route:        routeSettings{Enabled: enabled, Revision: "current"},
			ReturnRunner: "return-" + id,
		}
		s.state.Targets[id] = target
		return target
	}
	online := makeTarget("a", "Hong Kong", true)
	offline := makeTarget("b", "Tokyo", false)
	unavailable := makeTarget("c", "Los Angeles", true)
	pending := makeTarget("d", "Seoul", false)
	s.state.RouteRunners = map[string]nodeRecord{
		online.ReturnRunner:      {Credential: "registered", LastSeen: now.Unix(), RouteReady: true},
		offline.ReturnRunner:     {Credential: "registered", LastSeen: now.Add(-offlineAfter - time.Second).Unix(), RouteReady: true},
		unavailable.ReturnRunner: {Credential: "registered", LastSeen: now.Unix()},
		pending.ReturnRunner:     {Enrollment: "awaiting registration"},
		"return-orphan":          {Credential: "registered", LastSeen: now.Unix(), RouteReady: true},
	}
	scheduledWindow := now.Add(-2 * time.Minute).Unix()
	scheduledReceipt := scheduledWindow + 15
	job := protocol.RouteJob{
		TargetID: online.ID, ProbeID: probeID, Window: scheduledWindow,
		Generation: online.routeGeneration(), Family: 4, Direction: protocol.RouteOut,
	}
	jobKey := routeKey(job)
	stale := job
	stale.Generation = online.wireID() + ".old"
	s.state.Routes = map[string]routeSeries{
		jobKey:  {Latest: protocol.RouteResult{Job: job}, UpdatedAt: scheduledReceipt},
		"stale": {Latest: protocol.RouteResult{Job: stale}, UpdatedAt: now.Unix()},
	}
	manual := job
	manual.TargetID, manual.Generation = offline.ID, offline.wireID()
	manualReceipt := now.Add(-time.Minute).Unix()
	manualKey := routeKey(manual)
	removed := manual
	removed.ProbeID = "probe-removed"
	s.state.ManualResults = map[string]manualRouteResult{
		manualKey:       {Result: protocol.RouteResult{Job: manual}, At: manualReceipt},
		"probe-removed": {Result: protocol.RouteResult{Job: removed}, At: now.Unix()},
	}
	for _, round := range []int64{40, 10, 60, 20, 30, 50, 70} {
		change := routeChange{Job: job, At: scheduledWindow + round, Hops: []hopChange{{TTL: 8}, {TTL: 9}}}
		change.Job.Window = change.At
		if round == 60 {
			change.Job.ProbeID = removed.ProbeID
		}
		if round == 70 {
			change.Job.TargetID = "deleted-target"
		}
		s.state.RouteChanges = append(s.state.RouteChanges, change)
	}
	view := read()
	if view.EnabledTargets != 2 || view.OnlineRunners != 1 || view.DeployedRunners != 3 || view.LatestTraceAt != manualReceipt {
		t.Fatalf("route overview counts and latest receipt = %+v", view)
	}
	var at []int64
	for _, change := range view.Changes {
		at = append(at, change.At)
	}
	wantAt := []int64{scheduledWindow + 60, scheduledWindow + 50, scheduledWindow + 40, scheduledWindow + 30, scheduledWindow + 20}
	if !slices.Equal(at, wantAt) {
		t.Fatalf("route changes at %v, want %v", at, wantAt)
	}
	want := routeOverviewChangeView{
		At: wantAt[0], Window: wantAt[0], TargetID: online.ID, TargetName: online.Name,
		ProbeID: removed.ProbeID, ProbeName: removed.ProbeID, Direction: protocol.RouteOut, Family: 4, Hops: []int{8, 9},
	}
	if !reflect.DeepEqual(view.Changes[0], want) || view.Changes[1].ProbeName != "Changzhou" {
		t.Fatalf("route change rows lost details needed to open the history: %+v", view.Changes)
	}
	delete(s.state.ManualResults, manualKey)
	if got := read().LatestTraceAt; got != scheduledReceipt {
		t.Fatalf("scheduled receipt %d, want %d", got, scheduledReceipt)
	}
	s.state.Routes[jobKey] = routeSeries{Latest: protocol.RouteResult{Job: job}}
	if got := read().LatestTraceAt; got != scheduledWindow {
		t.Fatalf("legacy trace time %d, want window %d", got, scheduledWindow)
	}
}
