package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestManualOrderSurvivesReloadAndLogin(t *testing.T) {
	now := time.Now()
	s := &server{
		filename: filepath.Join(t.TempDir(), "state.json"),
		sessions: map[string]time.Time{"admin": now.Add(time.Hour)},
		state: diskState{
			ProbeIntervalSeconds: 60,
			Nodes: map[string]nodeRecord{
				"a": {ID: "a", Name: "Alpha"},
				"b": {ID: "b", Name: "Beta"},
			},
			Targets: map[string]targetRecord{
				"a": {Target: protocol.Target{ID: "a"}, CreatedAt: now.Add(-time.Minute)},
				"b": {Target: protocol.Target{ID: "b"}, CreatedAt: now},
			},
		},
	}
	check := func(nodes, targets []string) {
		t.Helper()
		reply := adminTestRequest(t, s, http.MethodGet, "/api/admin/state", nil, http.StatusOK)
		var view adminView
		if err := json.Unmarshal(reply.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		var nodeIDs, targetIDs []string
		for _, node := range view.Nodes {
			nodeIDs = append(nodeIDs, node.ID)
		}
		for _, target := range view.Targets {
			targetIDs = append(targetIDs, target.ID)
		}
		if !slices.Equal(nodeIDs, nodes) || !slices.Equal(targetIDs, targets) {
			t.Fatalf("nodes = %v, targets = %v; want %v, %v", nodeIDs, targetIDs, nodes, targets)
		}
	}
	check([]string{"a", "b"}, []string{"a", "b"})
	order := map[string][]string{"ids": {"b", "a"}}
	adminTestRequest(t, s, http.MethodPut, "/api/admin/nodes/order", order, http.StatusNoContent)
	check([]string{"b", "a"}, []string{"a", "b"})
	adminTestRequest(t, s, http.MethodPut, "/api/admin/targets/order", order, http.StatusNoContent)
	adminTestRequest(t, s, http.MethodPut, "/api/admin/targets/order", map[string][]string{"ids": {"a", "a"}}, http.StatusConflict)
	adminTestRequest(t, s, http.MethodPost, "/api/admin/logout", nil, http.StatusNoContent)
	adminTestRequest(t, s, http.MethodGet, "/api/admin/state", nil, http.StatusUnauthorized)
	saved, err := loadState(s.filename, now)
	if err != nil {
		t.Fatal(err)
	}
	s = &server{state: saved, filename: s.filename, sessions: map[string]time.Time{"admin": now.Add(time.Hour)}}
	check([]string{"b", "a"}, []string{"b", "a"})
	s.state.Nodes["c"] = nodeRecord{ID: "c", Name: "AAA"}
	check([]string{"b", "a", "c"}, []string{"b", "a"})
	adminTestRequest(t, s, http.MethodDelete, "/api/admin/nodes/b", nil, http.StatusNoContent)
	check([]string{"a", "c"}, []string{"b", "a"})
}
