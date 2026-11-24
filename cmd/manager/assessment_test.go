package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

const assessmentIP = "192.0.2.1"

func assessmentRound(target targetRecord, window int64) diskState {
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	timeout := protocol.Probe{Status: "timeout", Sent: 1}
	state := diskState{
		Nodes: map[string]nodeRecord{
			"east": {Group: "mainland", ISP: "East"},
			"west": {Group: "mainland", ISP: "West"},
			"sg":   {Group: "overseas", ISP: "Singapore"},
		},
		Targets: map[string]targetRecord{target.ID: target},
		Samples: make(map[string]map[string]sampleSeries),
	}
	for id, node := range state.Nodes {
		tcp := timeout
		if node.Group == "overseas" {
			tcp = ok
		}
		state.Samples[id] = map[string]sampleSeries{
			target.ID: {Results: []protocol.Result{{TargetID: target.ID, Window: window, ResolvedIP: assessmentIP, TCP: tcp, ICMP: ok}}},
		}
	}
	return state
}

func TestAssessmentComparesTargetResults(t *testing.T) {
	const window = 1800000000
	target := targetRecord{Target: protocol.Target{ID: "t", IP: "probe.example.com", Port: 443}}
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	timeout := protocol.Probe{Status: "timeout", Sent: 1}
	unavailable := protocol.Probe{Status: "unavailable"}
	for _, test := range []struct {
		name   string
		adjust func(diskState)
		want   string
	}{
		{name: "TCP timeout with ICMP replies", want: verdictSuspectedPort},
		{name: "TCP and ICMP timeout", want: verdictBothTimeout, adjust: func(state diskState) {
			state.Samples["east"]["t"].Results[0].ICMP = timeout
			state.Samples["west"]["t"].Results[0].ICMP = timeout
		}},
		{name: "both time out without overseas ICMP success", want: verdictInsufficient, adjust: func(state diskState) {
			for _, samples := range state.Samples {
				samples["t"].Results[0].ICMP = timeout
			}
		}},
		{name: "TCP timeout in both groups", want: verdictMultiRegion, adjust: func(state diskState) {
			state.Samples["sg"]["t"].Results[0].TCP = timeout
		}},
		{name: "connection refused", want: verdictRefused, adjust: func(state diskState) {
			state.Samples["sg"]["t"].Results[0].TCP = protocol.Probe{Status: "refused", Sent: 1}
		}},
		{name: "TCP succeeds across both groups", want: verdictOK, adjust: func(state diskState) {
			state.Samples["east"]["t"].Results[0].TCP = ok
		}},
		{name: "TCP reachable with no ICMP reply", want: verdictICMPNoReply, adjust: func(state diskState) {
			state.Samples["east"]["t"].Results[0].TCP = ok
			state.Samples["east"]["t"].Results[0].ICMP = timeout
		}},
		{name: "missing ICMP measurements", want: verdictInsufficient, adjust: func(state diskState) {
			for _, samples := range state.Samples {
				samples["t"].Results[0].ICMP = unavailable
			}
		}},
		{name: "no overseas evidence from this round", want: verdictInsufficient, adjust: func(state diskState) {
			state.Samples["sg"]["t"].Results[0].Window -= protocol.DefaultIntervalSeconds
		}},
		{name: "different DNS addresses", want: verdictInsufficient, adjust: func(state diskState) {
			state.Samples["sg"]["t"].Results[0].ResolvedIP = "192.0.2.2"
		}},
		{name: "missing DNS address", want: verdictInsufficient, adjust: func(state diskState) {
			state.Samples["sg"]["t"].Results[0].ResolvedIP = ""
		}},
		{name: "same ISP", want: verdictInsufficient, adjust: func(state diskState) {
			state.Nodes["west"] = nodeRecord{Group: "mainland", ISP: "EAST"}
		}},
		{name: "same ISP TCP success", want: verdictOK, adjust: func(state diskState) {
			state.Nodes["east-healthy"] = nodeRecord{Group: "mainland", ISP: "EAST"}
			state.Samples["east-healthy"] = map[string]sampleSeries{"t": {Results: []protocol.Result{{
				TargetID: "t", Window: window, ResolvedIP: assessmentIP, TCP: ok, ICMP: ok,
			}}}}
		}},
		{name: "one protocol only from a different node of the same ISP", want: verdictInsufficient, adjust: func(state diskState) {
			state.Samples["east"]["t"].Results[0].ICMP = unavailable
			state.Nodes["east-icmp"] = nodeRecord{Group: "mainland", ISP: "EAST"}
			state.Samples["east-icmp"] = map[string]sampleSeries{"t": {Results: []protocol.Result{{
				TargetID: "t", Window: window, ResolvedIP: assessmentIP, TCP: unavailable, ICMP: ok,
			}}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := assessmentRound(target, window)
			if test.adjust != nil {
				test.adjust(state)
			}
			if evidence := assess(state, target.ID, window); evidence.status != test.want {
				t.Fatalf("verdict = %q, want %q", evidence.status, test.want)
			}
		})
	}
}

func TestTargetIncidentRequiresConsecutiveEvidenceAndRecovery(t *testing.T) {
	const start, step = 1800000000, protocol.DefaultIntervalSeconds
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	timeout := protocol.Probe{Status: "timeout", Sent: 1}
	unavailable := protocol.Probe{Status: "unavailable"}
	for _, verdict := range []string{verdictSuspectedPort, verdictBothTimeout} {
		t.Run(verdict, func(t *testing.T) {
			target := targetRecord{Target: protocol.Target{ID: "t", IP: "probe.example.com", Port: 443}}
			state := assessmentRound(target, start)
			for i := int64(0); i < 4; i++ {
				window := start + i*step
				round := assessmentRound(target, window)
				if (i == 0) != (verdict == verdictBothTimeout) {
					round.Samples["east"]["t"].Results[0].ICMP = timeout
					round.Samples["west"]["t"].Results[0].ICMP = timeout
				}
				status := recordWindow(&state, &target, assess(round, target.ID, window), window, step)
				if i < 3 && (status != verdictInsufficient || len(state.Events) != 0) {
					t.Fatalf("mixed verdicts opened an early incident in window %d: %s", i, status)
				}
			}
			if len(state.Events) != 1 || state.Events[0].Verdict != verdict ||
				state.Events[0].StartedAt.Unix() != start+step || state.Events[0].ResolvedIP != assessmentIP ||
				!slices.Equal(state.Events[0].AffectedISPs, []string{"east", "west"}) ||
				!slices.Equal(state.Events[0].AffectedISPNames, []string{"East", "West"}) {
				t.Fatalf("unexpected incident: %+v", state.Events)
			}

			for i := int64(4); i <= 7; i++ {
				window := start + i*step
				round := assessmentRound(target, window)
				for id, samples := range round.Samples {
					result := &samples[target.ID].Results[0]
					result.TCP = ok
					if verdict == verdictSuspectedPort || (i == 4 && id == "west") {
						result.ICMP = unavailable
					}
					if i == 4 && id == "west" && verdict == verdictSuspectedPort {
						result.TCP = timeout
					}
				}
				if i == 5 {
					delete(round.Samples, "sg")
				}
				recordWindow(&state, &target, assess(round, target.ID, window), window, step)
				if i < 7 && state.Events[0].State != "active" {
					t.Fatalf("incident resolved early in window %d", i)
				}
			}
			event := state.Events[0]
			if event.State != "resolved" || event.EndedAt == nil || event.EndedAt.Unix() != start+7*step {
				t.Fatalf("target recovery did not resolve incident: %+v", event)
			}
		})
	}
}

func TestEventISPNamesPreserveSpellingAndFillLegacyLabels(t *testing.T) {
	state := diskState{
		Nodes: map[string]nodeRecord{
			"east": {Group: "mainland", ISP: "China Telecom"},
			"west": {Group: "mainland", ISP: "China Unicom"},
			"sg":   {Group: "overseas", ISP: "Oracle"},
		},
		Events: []eventRecord{
			{AffectedISPs: []string{"china telecom", "china unicom"}},
			{AffectedISPs: []string{"china telecom", "removed isp"}, AffectedISPNames: []string{"CHINA TELECOM", "Removed ISP"}},
		},
	}
	view := describeEvents(state)
	if !slices.Equal(view[0].AffectedISPNames, []string{"China Telecom", "China Unicom"}) ||
		!slices.Equal(view[1].AffectedISPNames, []string{"CHINA TELECOM", "Removed ISP"}) {
		t.Fatalf("unexpected event ISP labels: %+v", view)
	}
	if !slices.Equal(view[0].AffectedISPs, []string{"china telecom", "china unicom"}) || state.Events[0].AffectedISPNames != nil {
		t.Fatal("building the display labels changed matching keys or stored event history")
	}
}

func TestLegacyControlSnapshotLoadsTargetHistory(t *testing.T) {
	name := filepath.Join(t.TempDir(), "state.json")
	stateJSON := `{
		"control_key":"192.0.2.2:443",
		"targets":{"t":{"id":"t","history":[{"at":"2027-01-15T08:00:00Z","status":"suspected_regional_block"}],
			"bad_windows":2,"dual_windows":2,"good_windows":1}},
		"events":[{"target_id":"t","state":"active","verdict":"suspected_regional_block"}],
		"samples":{"east":{"control":{"results":[{"target_id":"control"}]},"t":{"results":[{"target_id":"t"}]}}}
	}`
	if err := os.WriteFile(name, []byte(stateJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := loadState(name, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	target := state.Targets["t"]
	if target.History[0].Status != verdictBothTimeout || state.Events[0].Verdict != verdictBothTimeout ||
		state.Events[0].State != "active" || target.CandidateWindows != 0 || target.RecoveryWindows != 0 {
		t.Fatalf("history, event or streak changed incorrectly: %+v, %+v", target, state.Events)
	}
	if _, exists := state.Samples["east"]["control"]; exists || len(state.Samples["east"]["t"].Results) != 1 {
		t.Fatal("legacy control samples were retained or target samples lost")
	}
}

func TestDuplicateWindowDoesNotOverrideOriginalReport(t *testing.T) {
	const window = 1800000000
	initial := protocol.Result{Window: window, TargetID: "t", TCP: protocol.Probe{Status: "timeout", Sent: 3}}
	later := protocol.Result{Window: window, TargetID: "t", TCP: protocol.Probe{Status: "ok", Sent: 3, Received: 3}}
	series := updateSeries(sampleSeries{}, initial, window, protocol.DefaultIntervalSeconds)
	series = updateSeries(series, later, window, protocol.DefaultIntervalSeconds)
	if len(series.Results) != 1 || series.Results[0] != initial {
		t.Fatalf("duplicate replaced result: %+v", series)
	}
}
