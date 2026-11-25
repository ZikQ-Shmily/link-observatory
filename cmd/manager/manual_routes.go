package main

import (
	"maps"
	"net/http"
	"time"

	"link-observatory/internal/protocol"
)

const manualTraceTTL = int64(20 * time.Minute / time.Second)

type manualRouteAssignment struct {
	AgentID string            `json:"agent_id"`
	Job     protocol.RouteJob `json:"job"`
	Done    bool              `json:"done,omitempty"`
}

type manualRouteRound struct {
	ID          string                           `json:"id"`
	RequestedAt int64                            `json:"requested_at"`
	Jobs        map[string]manualRouteAssignment `json:"jobs"`
	Done        int                              `json:"done"`
}

type manualRouteView struct {
	State       string `json:"state"`
	RequestedAt int64  `json:"requested_at"`
	Done        int    `json:"done"`
	Total       int    `json:"total"`
}

func (round manualRouteRound) active(now int64) bool {
	return round.ID != "" && round.Done < len(round.Jobs) && now-round.RequestedAt < manualTraceTTL
}

func (round manualRouteRound) view(now int64) *manualRouteView {
	if round.ID == "" {
		return nil
	}
	state := "completed"
	if round.Done < len(round.Jobs) {
		state = "expired"
		if round.active(now) {
			state = "running"
		}
	}
	return &manualRouteView{State: state, RequestedAt: round.RequestedAt, Done: round.Done, Total: len(round.Jobs)}
}

func (round manualRouteRound) appendPending(jobs []protocol.RouteJob, state diskState, target targetRecord, agent nodeRecord, now int64) []protocol.RouteJob {
	if !round.active(now) {
		return jobs
	}
	for _, assignment := range round.Jobs {
		if assignment.AgentID != agent.ID || assignment.Done {
			continue
		}
		job := assignment.Job
		job.SourceIP = agent.egress(job.Family, now)
		if job.Generation == target.wireID() && state.permitsRouteAddress(target, agent, job, now) {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func (s *server) traceTargetNow(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, exists := s.state.Targets[r.PathValue("id")]
	if !exists {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	now := time.Now()
	if target.ManualTrace.active(now.Unix()) {
		writeJSON(w, http.StatusAccepted, target.ManualTrace.view(now.Unix()))
		return
	}
	round := manualRouteRound{
		ID: randomHex(8), RequestedAt: now.Unix(), Jobs: make(map[string]manualRouteAssignment),
	}
	add := func(agent nodeRecord) {
		if !agent.RouteReady || !agent.ManualRoutes || agent.Credential == "" || agent.LastSeen == 0 || probeOffline(agent, now) {
			return
		}
		for _, job := range s.state.routeJobs(target, agent, now.Unix(), now.Unix()) {
			job.ManualID = round.ID
			job.Generation = target.wireID()
			round.Jobs[routeKey(job)] = manualRouteAssignment{AgentID: agent.ID, Job: job}
		}
	}
	for _, probe := range s.state.Nodes {
		add(probe)
	}
	add(s.state.RouteRunners[target.ReturnRunner])
	if len(round.Jobs) == 0 {
		writeError(w, http.StatusConflict, "没有可执行追踪的在线节点。请检查探针版本与 NextTrace 状态。")
		return
	}
	target.ManualTrace = round
	next := s.state
	next.Targets = maps.Clone(next.Targets)
	next.Targets[target.ID] = target
	if s.commit(w, next) {
		writeJSON(w, http.StatusAccepted, round.view(now.Unix()))
	}
}

func (s *server) acceptManualTrace(w http.ResponseWriter, agent nodeRecord, result protocol.RouteResult, now int64) {
	job := result.Job
	key := routeKey(job)
	target, exists := s.state.Targets[job.TargetID]
	round := target.ManualTrace
	assignment := round.Jobs[key]
	expected := assignment.Job
	expected.SourceIP = agent.egress(job.Family, now)
	if !exists || !agent.ManualRoutes || round.ID != job.ManualID || assignment.AgentID != agent.ID ||
		job.Generation != target.wireID() || expected != job || !s.state.permitsRouteAddress(target, agent, job, now) {
		writeError(w, http.StatusConflict, "route assignment changed")
		return
	}
	if assignment.Done {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !round.active(now) {
		writeError(w, http.StatusConflict, "route assignment changed")
		return
	}
	if !validRoute(result) {
		writeError(w, http.StatusUnprocessableEntity, "invalid route result")
		return
	}
	assignment.Done = true
	round.Jobs = maps.Clone(round.Jobs)
	round.Jobs[key] = assignment
	round.Done++
	target.ManualTrace = round

	next := s.state
	next.Targets = maps.Clone(next.Targets)
	next.Targets[target.ID] = target
	next.saveManualResult(key, result, now)
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

type manualRouteResult struct {
	Result protocol.RouteResult `json:"result"`
	At     int64                `json:"at"`
}

func (state *diskState) saveManualResult(key string, result protocol.RouteResult, now int64) {
	state.ManualResults = maps.Clone(state.ManualResults)
	if state.ManualResults == nil {
		state.ManualResults = make(map[string]manualRouteResult)
	}
	if _, exists := state.ManualResults[key]; !exists && len(state.ManualResults) >= maxRouteSeries {
		oldest := ""
		for candidate, stored := range state.ManualResults {
			if oldest == "" || stored.At < state.ManualResults[oldest].At {
				oldest = candidate
			}
		}
		delete(state.ManualResults, oldest)
	}
	state.ManualResults[key] = manualRouteResult{Result: result, At: now}
}

func (state diskState) displayRoutes(target targetRecord) []protocol.RouteResult {
	results := make(map[string]protocol.RouteResult)
	for key, series := range state.Routes {
		job := series.Latest.Job
		if _, ok := state.Nodes[job.ProbeID]; ok && job.TargetID == target.ID && job.Generation == target.routeGeneration() {
			results[key] = series.Latest
		}
	}
	for key, manual := range state.ManualResults {
		job := manual.Result.Job
		if _, ok := state.Nodes[job.ProbeID]; !ok || job.TargetID != target.ID || job.Generation != target.wireID() {
			continue
		}
		if _, exists := results[key]; !exists || manual.At >= state.Routes[key].UpdatedAt {
			results[key] = manual.Result
		}
	}
	view := make([]protocol.RouteResult, 0, len(results))
	for _, result := range results {
		view = append(view, result)
	}
	return view
}
