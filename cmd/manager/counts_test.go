package main

import (
	"path/filepath"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestClosedRoundsPersistReachabilityIndependentOfVerdict(t *testing.T) {
	const interval = protocol.DefaultIntervalSeconds
	const window = int64(1800000000)
	at := time.Unix(window, 0).UTC()
	target := targetRecord{Target: protocol.Target{ID: "t", IP: "192.0.2.1", Port: 443}, CreatedAt: at}
	probe := func(status string) protocol.Probe {
		p := protocol.Probe{Status: status, Sent: 1}
		if status == "ok" {
			p.Received = 1
		}
		return p
	}
	sample := func(window int64, tcp, icmp string) protocol.Result {
		return protocol.Result{TargetID: "t", Window: window, TCP: probe(tcp), ICMP: probe(icmp)}
	}
	s := &server{
		filename: filepath.Join(t.TempDir(), "state.json"),
		state: diskState{
			ProbeIntervalSeconds: interval, LastEvaluated: window - interval,
			Targets: map[string]targetRecord{"t": target},
			Nodes: map[string]nodeRecord{
				"a": {Group: "mainland"}, "b": {Group: "mainland"}, "c": {Group: "overseas"},
			},
			Samples: map[string]map[string]sampleSeries{
				"a": {"t": {Results: []protocol.Result{sample(window, "ok", "timeout")}}},
				"b": {"t": {Results: []protocol.Result{sample(window, "reset", "unreachable")}}},
				"c": {"t": {Results: []protocol.Result{
					sample(window+interval, "error", "unavailable"),
					sample(window, "refused", "unavailable"),
				}}},
			},
		},
	}
	s.evaluateClosedWindows(at.Add(3 * time.Minute))
	loaded, err := loadState(s.filename, at.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	history := loaded.Targets["t"].History
	if len(history) != 3 || history[0].Status != verdictInsufficient {
		t.Fatalf("unexpected finalized history: %+v", history)
	}
	want := roundCounts{
		Mainland: cohortCounts{TCP: reachabilityCount{Reachable: 1, Valid: 2}, ICMP: reachabilityCount{Valid: 2}},
		Overseas: cohortCounts{TCP: reachabilityCount{Valid: 1}},
	}
	if history[0].Counts == nil || *history[0].Counts != want {
		t.Fatalf("wrong persisted counts: %+v, want %+v", history[0].Counts, want)
	}
	for i, round := range history {
		if round.Sampled == nil || *round.Sampled != (i < 2) {
			t.Fatalf("round %d: expected sample presence %t, got %+v", i, i < 2, round)
		}
		if i > 0 && (round.Counts == nil || *round.Counts != (roundCounts{})) {
			t.Fatalf("round %d: an error-only or empty round has nonzero valid counts: %+v", i, round.Counts)
		}
	}
}

func TestLegacyRoundCountsOnlyUseRetainedExactSamples(t *testing.T) {
	const interval = protocol.DefaultIntervalSeconds
	at := time.Unix(1800000000, 0).UTC()
	unknown, legacy, final := at.Add(-2*time.Minute), at.Add(-time.Minute), at
	sampled := false
	target := targetRecord{
		Target: protocol.Target{ID: "t"},
		History: []roundStatus{
			{At: unknown, Status: verdictOK},
			{At: legacy, Status: verdictInsufficient},
			{At: final, Status: verdictInsufficient, Counts: &roundCounts{}, Sampled: &sampled},
		},
	}
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	state := diskState{
		ProbeIntervalSeconds: interval,
		Nodes:                map[string]nodeRecord{"overseas": {Group: "overseas", LastSeen: at.Add(-time.Hour).Unix()}},
		Samples: map[string]map[string]sampleSeries{
			"overseas": {"t": {Results: []protocol.Result{
				{TargetID: "t", Window: final.Unix(), TCP: ok, ICMP: ok},
				{TargetID: "t", Window: legacy.Unix(), TCP: ok, ICMP: ok},
			}}},
		},
	}

	history := describeTarget(state, target, at.Add(time.Hour)).History
	if history[0].Counts != nil || history[0].Sampled != nil || history[0].Status != verdictOK {
		t.Fatalf("missing legacy data was inferred: %+v", history[0])
	}
	if history[1].Counts == nil || history[1].Counts.Overseas.TCP != (reachabilityCount{Reachable: 1, Valid: 1}) ||
		history[1].Counts.Overseas.ICMP != (reachabilityCount{Reachable: 1, Valid: 1}) ||
		history[1].Sampled == nil || !*history[1].Sampled || history[1].Status != verdictInsufficient {
		t.Fatalf("exact retained observation was not surfaced: %+v", history[1])
	}
	if target.History[1].Counts != nil || history[2].Counts == nil || *history[2].Counts != (roundCounts{}) || *history[2].Sampled {
		t.Fatal("reading history changed an old record or replaced a finalized summary")
	}

	state.LastEvaluated = final.Unix()
	state.Targets = map[string]targetRecord{target.ID: target}
	s := &server{state: state, filename: filepath.Join(t.TempDir(), "state.json")}
	now := final.Add(2 * time.Minute)
	s.evaluateClosedWindows(now)
	reloaded, err := loadState(s.filename, now)
	if err != nil {
		t.Fatal(err)
	}
	storedRound := reloaded.Targets[target.ID].History[1]
	if storedRound.Counts == nil || *storedRound.Counts != *history[1].Counts {
		t.Fatalf("recovered counts would be lost when raw samples expire: %+v", storedRound)
	}
}
