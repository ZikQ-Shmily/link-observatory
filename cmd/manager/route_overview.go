package main

import (
	"cmp"
	"slices"
	"time"
)

const recentRouteChanges = 5

type routeOverviewView struct {
	EnabledTargets  int                       `json:"enabled_targets"`
	OnlineRunners   int                       `json:"online_runners"`
	DeployedRunners int                       `json:"deployed_runners"`
	LatestTraceAt   int64                     `json:"latest_trace_at"`
	Changes         []routeOverviewChangeView `json:"changes"`
}

type routeOverviewChangeView struct {
	At         int64  `json:"at"`
	Window     int64  `json:"window"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	ProbeID    string `json:"probe_id"`
	ProbeName  string `json:"probe_name"`
	Direction  string `json:"direction"`
	Family     int    `json:"family"`
	Hops       []int  `json:"hops"`
}

func describeRouteOverview(state diskState, now time.Time) routeOverviewView {
	view := routeOverviewView{
		LatestTraceAt: newestTraceAt(state),
		Changes:       make([]routeOverviewChangeView, 0, recentRouteChanges),
	}
	for _, target := range state.Targets {
		if target.Route.Enabled {
			view.EnabledTargets++
		}
		status := state.RouteRunners[target.ReturnRunner].returnRunnerStatus(now)
		if status != "pending" {
			view.DeployedRunners++
		}
		if status == "online" {
			view.OnlineRunners++
		}
	}

	// Reports can arrive out of order. Prefer the latest observation time,
	// then the newest recorded change among reports for the same window.
	changes := slices.Clone(state.RouteChanges)
	slices.Reverse(changes)
	slices.SortStableFunc(changes, func(a, b routeChange) int { return cmp.Compare(b.At, a.At) })
	for _, change := range changes {
		job := change.Job
		target, exists := state.Targets[job.TargetID]
		if !exists {
			continue
		}
		probeName := state.Nodes[job.ProbeID].Name
		if probeName == "" {
			probeName = job.ProbeID
		}
		hops := make([]int, len(change.Hops))
		for i, hop := range change.Hops {
			hops[i] = hop.TTL
		}
		view.Changes = append(view.Changes, routeOverviewChangeView{
			At: change.At, Window: job.Window, TargetID: job.TargetID, TargetName: target.Name,
			ProbeID: job.ProbeID, ProbeName: probeName, Direction: job.Direction, Family: job.Family, Hops: hops,
		})
		if len(view.Changes) == recentRouteChanges {
			break
		}
	}
	return view
}

func newestTraceAt(state diskState) int64 {
	var latest int64
	for _, series := range state.Routes {
		job := series.Latest.Job
		target, exists := state.Targets[job.TargetID]
		if _, hasProbe := state.Nodes[job.ProbeID]; exists && hasProbe && job.Generation == target.routeGeneration() {
			latest = max(latest, cmp.Or(series.UpdatedAt, job.Window))
		}
	}
	for _, manual := range state.ManualResults {
		job := manual.Result.Job
		target, exists := state.Targets[job.TargetID]
		if _, hasProbe := state.Nodes[job.ProbeID]; exists && hasProbe && job.Generation == target.wireID() {
			latest = max(latest, cmp.Or(manual.At, job.Window))
		}
	}
	return latest
}
