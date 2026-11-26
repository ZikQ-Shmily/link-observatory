package main

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"link-observatory/internal/protocol"
)

const (
	defaultRouteMinutes = 15
	maxRouteSeries      = 192
	maxRouteChanges     = 100
)

type routeSettings struct {
	Enabled  bool   `json:"enabled"`
	Minutes  int    `json:"minutes"`
	Revision string `json:"revision,omitempty"`
}

type egressAddress struct {
	IP string `json:"ip"`
	At int64  `json:"at"`
}

type egressChange struct {
	ProbeID string `json:"probe_id"`
	Family  int    `json:"family"`
	Before  string `json:"before"`
	After   string `json:"after"`
	At      int64  `json:"at"`
}

type routeSeries struct {
	Latest      protocol.RouteResult `json:"latest"`
	Baseline    protocol.RouteResult `json:"baseline,omitzero"`
	Candidate   string               `json:"candidate,omitempty"`
	CandidateAt int64                `json:"candidate_at,omitempty"`
	UpdatedAt   int64                `json:"updated_at"`
}

type hopChange struct {
	TTL    int                 `json:"ttl"`
	Before []protocol.RouteHop `json:"before"`
	After  []protocol.RouteHop `json:"after"`
}

type routeChange struct {
	Job      protocol.RouteJob `json:"job"`
	IP       string            `json:"destination_ip"`
	BeforeAt int64             `json:"before_at"`
	FirstAt  int64             `json:"first_at"`
	At       int64             `json:"at"`
	Hops     []hopChange       `json:"hops"`
}

func (node nodeRecord) returnRunnerStatus(now time.Time) string {
	switch {
	case node.Credential == "":
		return "pending"
	case node.LastSeen == 0 || probeOffline(node, now):
		return "offline"
	case !node.RouteReady:
		return "unavailable"
	default:
		return "online"
	}
}

func (state diskState) lookupAgent(id string) (nodeRecord, bool) {
	if node, ok := state.Nodes[id]; ok {
		return node, true
	}
	node, ok := state.RouteRunners[id]
	return node, ok
}

func (state *diskState) setAgent(node nodeRecord) {
	if node.ReturnTarget == "" {
		state.Nodes = maps.Clone(state.Nodes)
		state.Nodes[node.ID] = node
		return
	}
	if state.RouteRunners == nil {
		state.RouteRunners = make(map[string]nodeRecord)
	} else {
		state.RouteRunners = maps.Clone(state.RouteRunners)
	}
	state.RouteRunners[node.ID] = node
}

func (node nodeRecord) egress(family int, now int64) string {
	value := node.Egress4
	if family == 6 {
		value = node.Egress6
	}
	if now-value.At > int64(offlineAfter/time.Second) {
		return ""
	}
	return value.IP
}

func (state *diskState) setEgress(node *nodeRecord, value string, family int, now int64) {
	ip, ok := protocol.PublicIP(value, family)
	if !ok {
		return
	}
	dest := &node.Egress4
	if family == 6 {
		dest = &node.Egress6
	}
	if node.ReturnTarget == "" && dest.IP != "" && dest.IP != ip.String() {
		change := egressChange{ProbeID: node.ID, Family: family, Before: dest.IP, After: ip.String(), At: now}
		state.EgressChanges = append(slices.Clone(state.EgressChanges[max(0, len(state.EgressChanges)-maxRouteChanges+1):]), change)
	}
	*dest = egressAddress{IP: ip.String(), At: now}
}

func routeKey(job protocol.RouteJob) string {
	return job.TargetID + "/" + job.ProbeID + "/" + job.Direction + "/" + strconv.Itoa(job.Family)
}

func (target targetRecord) routeGeneration() string {
	return target.wireID() + "." + target.Route.Revision
}

func (target targetRecord) routeStep() int64 {
	if target.Route.Minutes == 0 {
		return defaultRouteMinutes * 60
	}
	return int64(target.Route.Minutes) * 60
}

func (state diskState) routeJobs(target targetRecord, agent nodeRecord, now, window int64) []protocol.RouteJob {
	var jobs []protocol.RouteJob
	add := func(probe, direction, address string, family int) {
		if address == "" {
			return
		}
		jobs = append(jobs, protocol.RouteJob{TargetID: target.ID, Generation: target.routeGeneration(), ProbeID: probe,
			Direction: direction, Address: address, SourceIP: agent.egress(family, now), Family: family, Window: window})
	}
	if agent.ReturnTarget == "" {
		targetIP, literal := protocol.ParseTargetIP(target.IP)
		for _, family := range []int{4, 6} {
			if !literal || targetIP.Is4() == (family == 4) {
				add(agent.ID, protocol.RouteOut, target.IP, family)
			}
		}
	} else if target.ID == agent.ReturnTarget && target.ReturnRunner == agent.ID {
		for _, probe := range state.Nodes {
			for _, family := range []int{4, 6} {
				add(probe.ID, protocol.RouteBack, probe.egress(family, now), family)
			}
		}
	}
	return jobs
}

func (state diskState) pendingRoutes(agent nodeRecord, now int64) []protocol.RouteJob {
	jobs := []protocol.RouteJob{}
	if !agent.RouteReady {
		return jobs
	}
	for _, target := range state.Targets {
		if agent.ManualRoutes {
			jobs = target.ManualTrace.appendPending(jobs, state, target, agent, now)
		}
		if !target.Route.Enabled {
			continue
		}
		window := protocol.WindowStart(now, int(target.routeStep()))
		for _, job := range state.routeJobs(target, agent, now, window) {
			latest := state.Routes[routeKey(job)].Latest.Job
			if latest.Window != job.Window || latest.Address != job.Address || latest.SourceIP != job.SourceIP || latest.Generation != job.Generation {
				jobs = append(jobs, job)
			}
		}
	}
	slices.SortFunc(jobs, func(a, b protocol.RouteJob) int {
		if a.ManualID != "" || b.ManualID != "" {
			if a.ManualID == "" {
				return 1
			}
			if b.ManualID == "" {
				return -1
			}
			if a.Window != b.Window {
				return cmp.Compare(a.Window, b.Window)
			}
		}
		left, right := state.Routes[routeKey(a)].UpdatedAt, state.Routes[routeKey(b)].UpdatedAt
		if left != right {
			return cmp.Compare(left, right)
		}
		return strings.Compare(routeKey(a), routeKey(b))
	})
	return jobs[:min(4, len(jobs))]
}

func (s *server) routePoll(w http.ResponseWriter, r *http.Request) {
	var input protocol.RoutePoll
	if !decodeJSON(w, r, &input, 2048) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agent(w, r)
	if !ok {
		return
	}
	now := time.Now().Unix()
	if input.Sampled || agent.RouteReady != input.Ready || agent.ManualRoutes != input.Manual {
		next := s.state
		agent.RouteReady, agent.ManualRoutes = input.Ready, input.Manual
		if input.Sampled {
			next.setEgress(&agent, input.IPv4, 4, now)
			next.setEgress(&agent, input.IPv6, 6, now)
		}
		next.setAgent(agent)
		if !s.commit(w, next) {
			return
		}
	}
	if input.Busy {
		writeJSON(w, http.StatusOK, []protocol.RouteJob{})
		return
	}
	writeJSON(w, http.StatusOK, s.state.pendingRoutes(agent, now))
}

func (state diskState) permitsRoute(agent nodeRecord, job protocol.RouteJob, now int64) bool {
	target, ok := state.Targets[job.TargetID]
	if !ok || !target.Route.Enabled || target.routeGeneration() != job.Generation || (job.Family != 4 && job.Family != 6) {
		return false
	}
	current := protocol.WindowStart(now, int(target.routeStep()))
	if (job.Window != current && job.Window != current-target.routeStep()) || job.SourceIP != agent.egress(job.Family, now) {
		return false
	}
	return state.permitsRouteAddress(target, agent, job, now)
}

func (state diskState) permitsRouteAddress(target targetRecord, agent nodeRecord, job protocol.RouteJob, now int64) bool {
	switch job.Direction {
	case protocol.RouteOut:
		return agent.ReturnTarget == "" && agent.ID == job.ProbeID && target.IP == job.Address
	case protocol.RouteBack:
		probe, exists := state.Nodes[job.ProbeID]
		return exists && target.ReturnRunner == agent.ID && agent.ReturnTarget == target.ID &&
			job.Address != "" && probe.egress(job.Family, now) == job.Address
	default:
		return false
	}
}

func validRoute(result protocol.RouteResult) bool {
	if len(result.Hops) > protocol.MaxRouteHops*3 || len(result.Error) > 240 {
		return false
	}
	if result.Error != "" {
		return len(result.Hops) == 0
	}
	ip, ok := protocol.ParseTargetIP(result.IP)
	if !ok || ip.String() != result.IP || ip.Is4() != (result.Job.Family == 4) {
		return false
	}
	if requested, literal := protocol.ParseTargetIP(result.Job.Address); literal && ip != requested {
		return false
	}
	var count [protocol.MaxRouteHops + 1]int
	for _, hop := range result.Hops {
		ip, ok := protocol.ParseTargetIP(hop.IP)
		if !ok || ip.String() != hop.IP || ip.Is4() != (result.Job.Family == 4) ||
			hop.TTL < 1 || hop.TTL > protocol.MaxRouteHops || hop.RTT < 0 || hop.RTT > 90000 ||
			len(hop.Location) > 156 || len(hop.ASN) > 16 || len(hop.Network) > 96 || len(hop.Hostname) > 160 {
			return false
		}
		count[hop.TTL]++
		if count[hop.TTL] > 3 {
			return false
		}
	}
	return true
}

func (s *server) routeResult(w http.ResponseWriter, r *http.Request) {
	var result protocol.RouteResult
	if !decodeJSON(w, r, &result, 96<<10) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agent(w, r)
	if !ok {
		return
	}
	now := time.Now().Unix()
	job := result.Job
	if job.ManualID != "" {
		s.acceptManualTrace(w, agent, result, now)
		return
	}
	if !s.state.permitsRoute(agent, job, now) {
		writeError(w, http.StatusConflict, "route assignment changed")
		return
	}
	if !validRoute(result) {
		writeError(w, http.StatusUnprocessableEntity, "invalid route result")
		return
	}
	next := s.state
	if !next.addRoute(result, now) || s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func changedRouteHops(before, after []protocol.RouteHop) []hopChange {
	var oldByTTL, newByTTL [protocol.MaxRouteHops + 1][]protocol.RouteHop
	for _, hop := range before {
		oldByTTL[hop.TTL] = append(oldByTTL[hop.TTL], hop)
	}
	for _, hop := range after {
		newByTTL[hop.TTL] = append(newByTTL[hop.TTL], hop)
	}
	var changes []hopChange
	for ttl, old := range oldByTTL {
		newHops := newByTTL[ttl]
		if len(old) == 0 || len(newHops) == 0 {
			continue // Silence cannot distinguish a path change from rate limiting.
		}
		if !slices.ContainsFunc(old, func(previous protocol.RouteHop) bool {
			return slices.ContainsFunc(newHops, func(hop protocol.RouteHop) bool { return hop.IP == previous.IP })
		}) {
			changes = append(changes, hopChange{TTL: ttl, Before: old, After: newHops})
		}
	}
	return changes
}

func routeSignature(changes []hopChange) string {
	var parts []string
	for _, change := range changes {
		ips := make([]string, 0, len(change.After))
		for _, hop := range change.After {
			ips = append(ips, hop.IP)
		}
		slices.Sort(ips)
		parts = append(parts, fmt.Sprintf("%d=%s", change.TTL, strings.Join(slices.Compact(ips), ",")))
	}
	return digest(strings.Join(parts, ";"))
}

func (state *diskState) addRoute(result protocol.RouteResult, now int64) bool {
	job := result.Job
	key := routeKey(job)
	series := state.Routes[key]
	latest := series.Latest
	if latest.Job.Generation == job.Generation && latest.Job.Address == job.Address && latest.Job.SourceIP == job.SourceIP && latest.Job.Window >= job.Window {
		return false
	}
	series.Latest, series.UpdatedAt = result, now
	baseline := series.Baseline
	if result.Error != "" || len(result.Hops) == 0 {
		series.Candidate, series.CandidateAt = "", 0
	} else if baseline.IP != result.IP || baseline.Job.SourceIP != job.SourceIP || baseline.Job.Generation != job.Generation {
		series.Baseline, series.Candidate, series.CandidateAt = result, "", 0
	} else if changed := changedRouteHops(baseline.Hops, result.Hops); len(changed) > 0 {
		signature := routeSignature(changed)
		if series.Candidate == signature && job.Window-series.CandidateAt == state.Targets[job.TargetID].routeStep() {
			change := routeChange{Job: job, IP: result.IP, BeforeAt: baseline.Job.Window,
				FirstAt: series.CandidateAt, At: job.Window, Hops: changed}
			state.RouteChanges = append(slices.Clone(state.RouteChanges[max(0, len(state.RouteChanges)-maxRouteChanges+1):]), change)
			state.routeChangeMail(change)
			series.Baseline, series.Candidate, series.CandidateAt = result, "", 0
		} else {
			series.Candidate, series.CandidateAt = signature, job.Window
		}
	} else {
		series.Candidate, series.CandidateAt = "", 0
	}
	if state.Routes == nil {
		state.Routes = make(map[string]routeSeries)
	} else {
		state.Routes = maps.Clone(state.Routes)
	}
	if _, exists := state.Routes[key]; !exists && len(state.Routes) >= maxRouteSeries {
		oldest := ""
		for candidate, stored := range state.Routes {
			if oldest == "" || stored.UpdatedAt < state.Routes[oldest].UpdatedAt {
				oldest = candidate
			}
		}
		delete(state.Routes, oldest)
	}
	state.Routes[key] = series
	return true
}

func (s *server) targetRoutes(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	target, exists := state.Targets[r.PathValue("id")]
	if !exists {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	results := state.displayRoutes(target)
	changes := []routeChange{}
	for i := len(state.RouteChanges) - 1; i >= 0; i-- {
		if event := state.RouteChanges[i]; event.Job.TargetID == target.ID {
			changes = append(changes, event)
		}
	}
	runner := state.RouteRunners[target.ReturnRunner]
	now := time.Now()
	var latest, available string
	if runner.Version != "" {
		latest, available = s.probeVersions(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": target.Route.Enabled, "minutes": target.routeStep() / 60,
		"runner": runner.returnRunnerStatus(now), "runner_id": runner.ID, "runner_version": runner.Version, "latest_probe_version": latest,
		"runner_update_available": protocol.NewerVersion(available, runner.Version),
		"runner_managed_updates":  runner.ManagedUpdates, "runner_update": runner.Update.view(now), "routes": results, "changes": changes, "egress_changes": state.EgressChanges,
		"runner_ipv4": runner.egress(4, now.Unix()), "runner_ipv6": runner.egress(6, now.Unix()), "manual": target.ManualTrace.view(now.Unix())})
}

func (s *server) updateTargetRoutes(w http.ResponseWriter, r *http.Request) {
	var input routeSettings
	if !decodeJSON(w, r, &input, 2048) {
		return
	}
	if !slices.Contains([]int{5, 15, 30, 60, 360, 720, 1440, 2880}, input.Minutes) {
		writeError(w, http.StatusBadRequest, "invalid route interval")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, exists := s.state.Targets[r.PathValue("id")]
	if !exists {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	if target.Route.Enabled != input.Enabled || target.routeStep()/60 != int64(input.Minutes) {
		input.Revision = randomHex(8)
		target.Route = input
		next := s.state
		next.Targets = maps.Clone(next.Targets)
		next.Targets[target.ID] = target
		if !s.commit(w, next) {
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) returnInstallCommand(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Proxy string `json:"gh_proxy"`
	}
	if !decodeJSON(w, r, &input, 4096) {
		return
	}
	if !s.cfg.cookieSecure {
		writeError(w, http.StatusServiceUnavailable, "请将管理端的 PUBLIC_URL 配置为 HTTPS 地址。")
		return
	}
	var proxy string
	if input.Proxy != "" {
		var valid bool
		proxy, valid = normalizeGHProxy(input.Proxy)
		if !valid {
			writeError(w, http.StatusBadRequest, "请输入有效的 gh-proxy HTTPS 地址。可包含端口或路径前缀。")
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, exists := s.state.Targets[r.PathValue("id")]
	if !exists {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	next := s.state
	runner := next.RouteRunners[target.ReturnRunner]
	var token string
	if runner.ID == "" {
		runner = nodeRecord{ID: "return-" + randomHex(8), Name: target.Name, ReturnTarget: target.ID}
	}
	if runner.Credential == "" {
		token = randomHex(32)
		runner.Enrollment, runner.TokenExpiry = digest(token), time.Now().Add(enrollTTL).Unix()
		next.setAgent(runner)
		next.Targets = maps.Clone(next.Targets)
		target.ReturnRunner = runner.ID
		next.Targets[target.ID] = target
		if !s.commit(w, next) {
			return
		}
	}
	command := buildInstallCommandFrom(mainReturnInstallerURL, "", s.cfg.publicURL, runner.ID, token, proxy)
	writeJSON(w, http.StatusOK, map[string]any{"command": command, "expires_at": runner.TokenExpiry})
}

func (state *diskState) removeRoutes(matches func(protocol.RouteJob) bool) {
	state.Routes = maps.Clone(state.Routes)
	maps.DeleteFunc(state.Routes, func(_ string, route routeSeries) bool { return matches(route.Latest.Job) })
	state.ManualResults = maps.Clone(state.ManualResults)
	maps.DeleteFunc(state.ManualResults, func(_ string, route manualRouteResult) bool { return matches(route.Result.Job) })
}

func (state *diskState) clearReturnRunner(target *targetRecord) {
	state.RouteRunners = maps.Clone(state.RouteRunners)
	delete(state.RouteRunners, target.ReturnRunner)
	target.ReturnRunner = ""
	target.ManualTrace = manualRouteRound{}
	state.removeRoutes(func(job protocol.RouteJob) bool {
		return job.TargetID == target.ID && job.Direction == protocol.RouteBack
	})
}

func (s *server) removeReturnRunner(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, exists := s.state.Targets[r.PathValue("id")]
	if !exists {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	next := s.state
	next.clearReturnRunner(&target)
	target.Route.Revision = randomHex(8)
	next.Targets = maps.Clone(next.Targets)
	next.Targets[target.ID] = target
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}
