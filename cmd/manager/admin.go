package main

import (
	"cmp"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"link-observatory/internal/protocol"
)

type nodeView struct {
	UpdateAvailable  bool        `json:"update_available"`
	ManagedUpdates   bool        `json:"managed_updates"`
	Update           *updateView `json:"update,omitempty"`
	EgressIPv4       string      `json:"egress_ipv4,omitempty"`
	EgressIPv6       string      `json:"egress_ipv6,omitempty"`
	RouteReady       bool        `json:"route_ready"`
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Location         string      `json:"location"`
	ISP              string      `json:"isp"`
	Group            string      `json:"group"`
	State            string      `json:"state"`
	Version          string      `json:"version,omitempty"`
	LastSeen         *time.Time  `json:"last_seen,omitempty"`
	ICMPv4           bool        `json:"icmp_v4"`
	ICMPv6           bool        `json:"icmp_v6"`
	ManageCommand    string      `json:"manage_command"`
	UninstallCommand string      `json:"uninstall_command"`
}

type nodeEnrollment struct {
	Node      nodeView  `json:"node"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type observation struct {
	NodeID     string         `json:"node_id"`
	ObservedAt time.Time      `json:"observed_at"`
	ResolvedIP string         `json:"resolved_ip,omitempty"`
	TCP        protocol.Probe `json:"tcp"`
	ICMP       protocol.Probe `json:"icmp"`
}

type targetView struct {
	protocol.Target
	Verdict   string        `json:"verdict"`
	Latest    []observation `json:"latest"`
	History   []roundStatus `json:"history"`
	CreatedAt time.Time     `json:"created_at"`
}

type adminView struct {
	Nodes                []nodeView        `json:"nodes"`
	Targets              []targetView      `json:"targets"`
	Events               []eventRecord     `json:"events"`
	RouteOverview        routeOverviewView `json:"route_overview"`
	ProbeIntervalSeconds int               `json:"probe_interval_seconds"`
	ProbeScheduleStart   int64             `json:"probe_schedule_start"`
	ReleaseConfigured    bool              `json:"release_configured"`
	LatestProbeVersion   string            `json:"latest_probe_version,omitempty"`
}

func describeNode(node nodeRecord, now time.Time) nodeView {
	manage := `bash "$HOME/.local/share/link-monitor/nodes/` + node.ID + `/install.sh"`
	view := nodeView{
		ID: node.ID, Name: node.Name, Location: node.Location, ISP: node.ISP, Group: node.Group,
		State: "pending", Version: node.Version, ICMPv4: node.ICMPv4, ICMPv6: node.ICMPv6,
		ManagedUpdates: node.ManagedUpdates, Update: node.updateView(now),
		ManageCommand: manage, UninstallCommand: manage + " uninstall",
		EgressIPv4: node.egress(4, now.Unix()), EgressIPv6: node.egress(6, now.Unix()), RouteReady: node.RouteReady,
	}
	if node.LastSeen > 0 {
		seen := time.Unix(node.LastSeen, 0).UTC()
		view.LastSeen = &seen
		view.State = "offline"
		if !probeOffline(node, now) {
			view.State = "online"
		}
	}
	return view
}

func describeTarget(state diskState, target targetRecord, now time.Time) targetView {
	history := historyWithCounts(state, target)
	view := targetView{
		Target: target.Target, CreatedAt: target.CreatedAt, History: history,
		Latest: []observation{}, Verdict: verdictPending,
	}
	interval := state.ProbeIntervalSeconds
	present := protocol.WindowStart(now.Unix(), interval)
	for nodeID, series := range state.Samples {
		for _, result := range series[target.ID].Results {
			if result.Window > present {
				continue
			}
			view.Latest = append(view.Latest, observation{
				NodeID: nodeID, ObservedAt: time.Unix(result.Window, 0).UTC(),
				ResolvedIP: result.ResolvedIP, TCP: result.TCP, ICMP: result.ICMP,
			})
			break
		}
	}
	slices.SortFunc(view.Latest, func(a, b observation) int { return cmp.Compare(a.NodeID, b.NodeID) })
	if len(history) > 0 {
		last := history[len(history)-1]
		view.Verdict = last.Status
		if last.At.Unix() < state.ScheduleStart || now.Sub(last.At) > time.Duration(3*interval)*time.Second {
			view.Verdict = verdictInsufficient
		}
	}
	return view
}

func describeEvents(state diskState) []eventRecord {
	currentNames := make(map[string]string)
	for _, node := range state.Nodes {
		if node.Group != "mainland" {
			continue
		}
		key := strings.ToLower(node.ISP)
		if currentNames[key] == "" || node.ISP < currentNames[key] {
			currentNames[key] = node.ISP
		}
	}
	events := slices.Clone(state.Events)
	for i := range events {
		event := &events[i]
		names := slices.Clone(event.AffectedISPs)
		for j, key := range names {
			if j < len(event.AffectedISPNames) && event.AffectedISPNames[j] != "" {
				names[j] = event.AffectedISPNames[j]
			} else if name := currentNames[key]; name != "" {
				names[j] = name
			}
		}
		event.AffectedISPNames = names
	}
	return events
}

func (s *server) adminState(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	view := adminView{
		Nodes: []nodeView{}, Targets: []targetView{}, Events: describeEvents(state),
		ProbeIntervalSeconds: state.ProbeIntervalSeconds, ProbeScheduleStart: state.ScheduleStart,
		ReleaseConfigured: s.cfg.cookieSecure, RouteOverview: describeRouteOverview(state, now),
	}
	for _, node := range state.Nodes {
		view.Nodes = append(view.Nodes, describeNode(node, now))
	}
	if r.URL.Query().Get("probe_version") == "1" &&
		slices.ContainsFunc(view.Nodes, func(node nodeView) bool { return node.Version != "" }) {
		latest, available := s.probeVersions(r.Context())
		view.LatestProbeVersion = latest
		for i := range view.Nodes {
			view.Nodes[i].UpdateAvailable = protocol.NewerVersion(available, view.Nodes[i].Version)
		}
	}
	for _, target := range state.Targets {
		view.Targets = append(view.Targets, describeTarget(state, target, now))
	}
	rank := orderPositions(state.NodeOrder)
	slices.SortFunc(view.Nodes, func(a, b nodeView) int {
		return cmp.Or(cmp.Compare(rank[a.ID], rank[b.ID]), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	rank = orderPositions(state.TargetOrder)
	slices.SortFunc(view.Targets, func(a, b targetView) int {
		return cmp.Or(cmp.Compare(rank[a.ID], rank[b.ID]), a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	slices.SortFunc(view.Events, func(a, b eventRecord) int { return b.StartedAt.Compare(a.StartedAt) })
	writeJSON(w, http.StatusOK, view)
}

func (s *server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProbeIntervalSeconds int `json:"probe_interval_seconds"`
	}
	if !decodeJSON(w, r, &input, 8192) {
		return
	}
	interval := input.ProbeIntervalSeconds
	if !protocol.ValidIntervalSeconds(interval) {
		writeError(w, http.StatusBadRequest, "probe interval must be a whole number of minutes from 1 to 10")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if interval == s.state.ProbeIntervalSeconds {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	next := s.state
	next.ProbeIntervalSeconds = interval
	next.LastEvaluated = protocol.WindowStart(time.Now().Unix(), interval)
	next.ScheduleStart = next.LastEvaluated + int64(interval)
	next.Targets = maps.Clone(next.Targets)
	for id, target := range next.Targets {
		target.resetEvidenceStreaks()
		next.Targets[id] = target
	}
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func readNodeSettings(w http.ResponseWriter, r *http.Request) (nodeRecord, bool) {
	var input struct {
		Name     string `json:"name"`
		Location string `json:"location"`
		ISP      string `json:"isp"`
		Group    string `json:"group"`
	}
	if !decodeJSON(w, r, &input, 8192) {
		return nodeRecord{}, false
	}
	node := nodeRecord{
		Name:     cleanLabel(input.Name),
		Location: cleanLabel(input.Location), ISP: cleanLabel(input.ISP), Group: input.Group,
	}
	if !validLabel(node.Name, 32) || !validLabel(node.Location, 24) ||
		!validLabel(node.ISP, 24) || (node.Group != "mainland" && node.Group != "overseas") {
		writeError(w, http.StatusBadRequest, "invalid node name, group, location or ISP")
		return nodeRecord{}, false
	}
	return node, true
}

func (s *server) addNode(w http.ResponseWriter, r *http.Request) {
	node, ok := readNodeSettings(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Nodes) >= maxNodes {
		writeError(w, http.StatusConflict, "node limit reached")
		return
	}
	node.ID = "probe-" + randomHex(8)
	s.issueEnrollment(w, node, http.StatusCreated)
}

func (s *server) editNode(w http.ResponseWriter, r *http.Request) {
	updated, ok := readNodeSettings(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.state.Nodes[id]
	if !exists {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	now := time.Now().UTC()
	next := s.state
	if node.ISP != updated.ISP || node.Group != updated.Group {
		// Old observations carry the previous grouping or ISP attribution.
		node.EvidenceStart = now.Unix() + 1
		next.Samples = maps.Clone(next.Samples)
		delete(next.Samples, id)
		next.removeRoutes(func(job protocol.RouteJob) bool { return job.ProbeID == id })
		next.Targets = maps.Clone(next.Targets)
		for targetID, target := range next.Targets {
			target.resetEvidenceStreaks()
			next.Targets[targetID] = target
		}
	}
	node.Name, node.Location, node.ISP, node.Group = updated.Name, updated.Location, updated.ISP, updated.Group
	next.Nodes = maps.Clone(next.Nodes)
	next.Nodes[id] = node
	if s.commit(w, next) {
		writeJSON(w, http.StatusOK, describeNode(node, now))
	}
}

func (s *server) rotateToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.state.Nodes[r.PathValue("id")]
	if !exists {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if node.Credential != "" {
		writeError(w, http.StatusConflict, "node already registered")
		return
	}
	s.issueEnrollment(w, node, http.StatusOK)
}

func (s *server) issueEnrollment(w http.ResponseWriter, node nodeRecord, status int) {
	now := time.Now().UTC()
	token := randomHex(32)
	expires := now.Add(enrollTTL)
	node.Enrollment, node.TokenExpiry = digest(token), expires.Unix()
	next := s.state
	next.Nodes = maps.Clone(next.Nodes)
	next.Nodes[node.ID] = node
	if s.commit(w, next) {
		writeJSON(w, status, nodeEnrollment{
			Node: describeNode(node, now), Token: token, ExpiresAt: expires,
		})
	}
}

func (s *server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Nodes[id]; !exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	next := s.state
	next.Nodes = maps.Clone(next.Nodes)
	delete(next.Nodes, id)
	next.NodeOrder = removeOrderEntry(next.NodeOrder, id)
	next.Samples = maps.Clone(next.Samples)
	delete(next.Samples, id)
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func readTargetSettings(w http.ResponseWriter, r *http.Request) (protocol.Target, bool) {
	var input struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}
	if !decodeJSON(w, r, &input, 8192) {
		return protocol.Target{}, false
	}
	address, valid := protocol.NormalizeTargetAddress(input.IP)
	name := cleanLabel(input.Name)
	if !valid || input.Port < 1 || input.Port > 65535 || !validLabel(name, 32) {
		writeError(w, http.StatusBadRequest, "invalid target name, IP address, hostname or TCP port")
		return protocol.Target{}, false
	}
	return protocol.Target{Name: name, IP: address, Port: input.Port}, true
}

func targetEndpointTaken(targets map[string]targetRecord, address protocol.Target) bool {
	for id, existing := range targets {
		if id != address.ID && existing.IP == address.IP && existing.Port == address.Port {
			return true
		}
	}
	return false
}

func (s *server) addTarget(w http.ResponseWriter, r *http.Request) {
	address, ok := readTargetSettings(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Targets) >= maxTargets {
		writeError(w, http.StatusConflict, "target limit reached")
		return
	}
	if targetEndpointTaken(s.state.Targets, address) {
		writeError(w, http.StatusConflict, "address and TCP port already monitored")
		return
	}
	address.ID = "target-" + randomHex(8)
	target := targetRecord{Target: address, CreatedAt: now, History: []roundStatus{}}
	next := s.state
	next.Targets = maps.Clone(next.Targets)
	next.Targets[target.ID] = target
	if s.commit(w, next) {
		writeJSON(w, http.StatusCreated, describeTarget(next, target, now))
	}
}

func (s *server) editTarget(w http.ResponseWriter, r *http.Request) {
	address, ok := readTargetSettings(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	target, exists := s.state.Targets[id]
	if !exists {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	address.ID = id
	if targetEndpointTaken(s.state.Targets, address) {
		writeError(w, http.StatusConflict, "address and TCP port already monitored")
		return
	}
	now := time.Now().UTC()
	next := s.state
	if target.IP != address.IP || target.Port != address.Port {
		oldEndpoint := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
		updated := targetRecord{
			Target: target.Target, CreatedAt: target.CreatedAt, Route: target.Route, ReturnRunner: target.ReturnRunner,
			EndpointChangedAt: now, ProbeID: "target-" + randomHex(8),
		}
		if target.IP == address.IP {
			updated.AlertsInitialized = target.AlertsInitialized
			updated.ICMPAlert = target.ICMPAlert
			updated.ICMPAlert.resetStreaks()
		} else {
			next.clearReturnRunner(&updated)
			next.removeRoutes(func(job protocol.RouteJob) bool { return job.TargetID == id })
			updated.Route.Revision = randomHex(8)
		}
		target = updated
		next.Samples = maps.Clone(next.Samples)
		removeTargetSamples(next.Samples, id)
		next.Events = slices.Clone(next.Events)
		for i := range next.Events {
			event := &next.Events[i]
			if event.TargetID != id {
				continue
			}
			if event.TargetAddress == "" {
				event.TargetAddress = oldEndpoint
			}
			if event.State == "active" {
				event.State, event.EndedAt = "superseded", &now
			}
		}
	}
	target.Target = address
	next.Targets = maps.Clone(next.Targets)
	next.Targets[id] = target
	if s.commit(w, next) {
		writeJSON(w, http.StatusOK, describeTarget(next, target, now))
	}
}

func removeTargetSamples(samples map[string]map[string]sampleSeries, id string) {
	for node, targets := range samples {
		if _, exists := targets[id]; exists {
			items := maps.Clone(targets)
			delete(items, id)
			samples[node] = items
		}
	}
}

func (s *server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	target, exists := s.state.Targets[id]
	if !exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	now := time.Now().UTC()
	next := s.state
	next.Targets = maps.Clone(next.Targets)
	delete(next.Targets, id)
	next.clearReturnRunner(&target)
	next.removeRoutes(func(job protocol.RouteJob) bool { return job.TargetID == id })
	next.TargetOrder = removeOrderEntry(next.TargetOrder, id)
	next.Samples = maps.Clone(next.Samples)
	removeTargetSamples(next.Samples, id)
	next.Events = slices.Clone(next.Events)
	for i := range next.Events {
		if next.Events[i].TargetID == id && next.Events[i].State == "active" {
			next.Events[i].State = "resolved"
			next.Events[i].EndedAt = &now
		}
	}
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}
