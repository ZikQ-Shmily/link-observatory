package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestAgentVersionAvailability(t *testing.T) {
	const latest = "v2.10.0"
	for _, test := range []struct {
		name           string
		currentVersion string
		pinnedVersion  string
		staleLatest    bool
		wantUpdate     bool
	}{
		{name: "older", currentVersion: "v2.9.9", wantUpdate: true},
		{name: "latest", currentVersion: latest},
		{name: "newer", currentVersion: "v3.0.0"},
		{name: "development", currentVersion: "dev"},
		{name: "stale latest", currentVersion: "v2.9.9", staleLatest: true},
		{name: "older than pin", currentVersion: "v2.8.0", pinnedVersion: "v2.9.0", wantUpdate: true},
		{name: "same as pin", currentVersion: "v2.9.0", pinnedVersion: "v2.9.0"},
		{name: "newer than pin", currentVersion: "v2.9.1", pinnedVersion: "v2.9.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newPasswordTestServer(t)
			now := time.Now()
			s.sessions["admin"] = now.Add(time.Hour)
			sha := strings.Repeat("a", 64)
			if test.pinnedVersion != "" {
				s.cfg.releaseURL = officialReleaseDownloadPrefix + test.pinnedVersion
				s.cfg.installHash = sha
			}
			validUntil := now.Add(time.Minute)
			wantLatest := latest
			if test.staleLatest {
				validUntil = now.Add(-time.Minute)
				wantLatest = ""
			}
			s.resolveLatestInstaller = func(context.Context) (installerRelease, error) {
				return installerRelease{URL: officialReleaseDownloadPrefix + latest, SHA256: sha, validUntil: validUntil}, nil
			}

			probe := nodeRecord{
				ID: "probe-a", Version: test.currentVersion, Credential: digest("probe-key"),
				ManagedUpdates: true, LastSeen: now.Unix(),
			}
			runner := nodeRecord{
				ID: "return-a", Version: test.currentVersion, Credential: digest("runner-key"),
				ReturnTarget: "target-a", ManagedUpdates: true, LastSeen: now.Unix(), RouteReady: true,
			}
			s.state.Nodes[probe.ID] = probe
			s.state.RouteRunners = map[string]nodeRecord{runner.ID: runner}
			s.state.Targets[runner.ReturnTarget] = targetRecord{
				Target: protocol.Target{ID: runner.ReturnTarget}, ReturnRunner: runner.ID,
			}

			reply := adminTestRequest(t, s, http.MethodGet, "/api/admin/state?probe_version=1", nil, http.StatusOK)
			var agents struct {
				Latest string `json:"latest_probe_version"`
				Nodes  []struct {
					Version         string `json:"version"`
					UpdateAvailable bool   `json:"update_available"`
				} `json:"nodes"`
			}
			if err := json.Unmarshal(reply.Body.Bytes(), &agents); err != nil {
				t.Fatal(err)
			}
			if len(agents.Nodes) != 1 || agents.Latest != wantLatest || agents.Nodes[0].Version != test.currentVersion ||
				agents.Nodes[0].UpdateAvailable != test.wantUpdate {
				t.Errorf("probe version view = %+v, want current %s, latest %q, and update %t",
					agents, test.currentVersion, wantLatest, test.wantUpdate)
			}

			// The route view must resolve version metadata even on a manager with only a return runner.
			delete(s.state.Nodes, probe.ID)
			reply = adminTestRequest(t, s, http.MethodGet, "/api/admin/targets/target-a/routes", nil, http.StatusOK)
			var returnView struct {
				Latest          string `json:"latest_probe_version"`
				Version         string `json:"runner_version"`
				UpdateAvailable bool   `json:"runner_update_available"`
			}
			if err := json.Unmarshal(reply.Body.Bytes(), &returnView); err != nil {
				t.Fatal(err)
			}
			if returnView.Latest != wantLatest || returnView.Version != test.currentVersion || returnView.UpdateAvailable != test.wantUpdate {
				t.Errorf("return runner version view = %+v, want current %s, latest %q, and update %t",
					returnView, test.currentVersion, wantLatest, test.wantUpdate)
			}
		})
	}
}
