package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"link-observatory/internal/protocol"
)

const (
	offlineAfter   = 3 * time.Minute
	maxNodes       = 32
	maxTargets     = 100
	rawWindows     = 8
	historyWindows = 144
	maxEvents      = 400
)

type nodeRecord struct {
	ManagedUpdates   bool          `json:"managed_updates,omitempty"`
	Update           updateTask    `json:"update,omitzero"`
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	Location         string        `json:"location"`
	ISP              string        `json:"isp"`
	Group            string        `json:"group"`
	Version          string        `json:"version,omitempty"`
	ICMPv4           bool          `json:"icmp_v4"`
	ICMPv6           bool          `json:"icmp_v6"`
	MailOfflineSince int64         `json:"mail_offline_since,omitempty"`
	LastSeen         int64         `json:"last_seen,omitempty"`
	EvidenceStart    int64         `json:"evidence_start,omitempty"`
	Enrollment       string        `json:"enrollment,omitempty"`
	TokenExpiry      int64         `json:"token_expiry,omitempty"`
	Credential       string        `json:"credential,omitempty"`
	ReturnTarget     string        `json:"return_target,omitempty"`
	ManualRoutes     bool          `json:"manual_routes,omitempty"`
	RouteReady       bool          `json:"route_ready,omitempty"`
	Egress4          egressAddress `json:"egress_v4,omitzero"`
	Egress6          egressAddress `json:"egress_v6,omitzero"`

	Metrics *protocol.HostMetrics `json:"metrics,omitempty"`
}

type roundStatus struct {
	At      time.Time    `json:"at"`
	Status  string       `json:"status"`
	Counts  *roundCounts `json:"counts,omitempty"`
	Sampled *bool        `json:"sampled,omitempty"`
}

type targetRecord struct {
	protocol.Target
	ProbeID           string             `json:"probe_id,omitempty"`
	EndpointChangedAt time.Time          `json:"endpoint_changed_at,omitzero"`
	CreatedAt         time.Time          `json:"created_at"`
	History           []roundStatus      `json:"history"`
	CandidateWindows  int                `json:"candidate_windows,omitempty"`
	RecoveryWindows   int                `json:"recovery_windows,omitempty"`
	CandidateIP       string             `json:"candidate_ip,omitempty"`
	AlertsInitialized bool               `json:"alerts_initialized,omitempty"`
	TCPAlert          protocolAlertState `json:"tcp_alert,omitzero"`
	ICMPAlert         protocolAlertState `json:"icmp_alert,omitzero"`
	CandidateStatus   string             `json:"candidate_status,omitempty"`
	Route             routeSettings      `json:"route,omitzero"`
	ManualTrace       manualRouteRound   `json:"manual_trace,omitzero"`
	ReturnRunner      string             `json:"return_runner,omitempty"`
}

func (target *targetRecord) resetEvidenceStreaks() {
	target.CandidateWindows, target.RecoveryWindows = 0, 0
	target.CandidateIP, target.CandidateStatus = "", ""
	target.TCPAlert.resetStreaks()
	target.ICMPAlert.resetStreaks()
}

func (target targetRecord) wireID() string {
	if target.ProbeID != "" {
		return target.ProbeID
	}
	return target.ID
}

func (target targetRecord) monitoringSince() time.Time {
	if !target.EndpointChangedAt.IsZero() {
		return target.EndpointChangedAt
	}
	return target.CreatedAt
}

type eventRecord struct {
	AffectedISPs     []string   `json:"affected_isps,omitempty"`
	AffectedISPNames []string   `json:"affected_isp_names,omitempty"`
	ID               string     `json:"id"`
	TargetID         string     `json:"target_id"`
	TargetName       string     `json:"target_name"`
	TargetAddress    string     `json:"target_address,omitempty"`
	State            string     `json:"state"`
	Verdict          string     `json:"verdict"`
	ResolvedIP       string     `json:"resolved_ip,omitempty"`
	StartedAt        time.Time  `json:"started_at"`
	EndedAt          *time.Time `json:"ended_at,omitempty"`
}

type sampleSeries struct {
	Results []protocol.Result `json:"results,omitempty"`
}

type diskState struct {
	Mail                 mailSettings                       `json:"mail,omitzero"`
	MailQueue            []mailJob                          `json:"mail_queue,omitempty"`
	NodeOrder            []string                           `json:"node_order,omitempty"`
	TargetOrder          []string                           `json:"target_order,omitempty"`
	AdminPassword        *adminPasswordRecord               `json:"admin_password,omitempty"`
	Nodes                map[string]nodeRecord              `json:"nodes"`
	Targets              map[string]targetRecord            `json:"targets"`
	Samples              map[string]map[string]sampleSeries `json:"samples"`
	Events               []eventRecord                      `json:"events"`
	LastEvaluated        int64                              `json:"last_evaluated"`
	ProbeIntervalSeconds int                                `json:"probe_interval_seconds"`
	ScheduleStart        int64                              `json:"schedule_start,omitempty"`
	RouteRunners         map[string]nodeRecord              `json:"route_runners,omitempty"`
	Routes               map[string]routeSeries             `json:"routes,omitempty"`
	ManualResults        map[string]manualRouteResult       `json:"manual_results,omitempty"`
	RouteChanges         []routeChange                      `json:"route_changes,omitempty"`
	EgressChanges        []egressChange                     `json:"egress_changes,omitempty"`
}

func openStore(dir string, now time.Time) (string, *os.File, diskState, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", nil, diskState{}, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".manager.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", nil, diskState{}, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return "", nil, diskState{}, fmt.Errorf("lock data directory: %w", err)
	}

	name := filepath.Join(dir, "state.json")
	state, err := loadState(name, now)
	if err != nil {
		lock.Close()
		return "", nil, diskState{}, err
	}
	return name, lock, state, nil
}

func loadState(name string, now time.Time) (diskState, error) {
	var state diskState
	file, err := os.Open(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return state, err
	}
	if file != nil {
		defer file.Close()
		decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
		if err := decoder.Decode(&state); err != nil {
			return state, fmt.Errorf("read state: %w", err)
		}
		if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
			return state, errors.New("trailing data in state file")
		}
	}
	state.Mail.Events = groupedMailEvents(state.Mail.Events)
	if p := state.AdminPassword; p != nil && (len(p.Salt) != adminPasswordSaltSize || len(p.Hash) != adminPasswordHashSize) {
		return state, errors.New("invalid stored admin password hash")
	}
	if state.Nodes == nil {
		state.Nodes = make(map[string]nodeRecord)
	}
	if state.Targets == nil {
		state.Targets = make(map[string]targetRecord)
	}
	if state.Samples == nil {
		state.Samples = make(map[string]map[string]sampleSeries)
	}
	if state.Events == nil {
		state.Events = []eventRecord{}
	}
	// Translate the previous dual-protocol verdict and discard legacy control samples.
	for i := range state.Events {
		if state.Events[i].Verdict == legacyDualVerdict {
			state.Events[i].Verdict = verdictBothTimeout
		}
	}
	for _, target := range state.Targets {
		for i := range target.History {
			if target.History[i].Status == legacyDualVerdict {
				target.History[i].Status = verdictBothTimeout
			}
		}
	}
	for _, series := range state.Samples {
		delete(series, "control")
	}
	if state.ProbeIntervalSeconds == 0 {
		state.ProbeIntervalSeconds = protocol.DefaultIntervalSeconds
	}
	if !protocol.ValidIntervalSeconds(state.ProbeIntervalSeconds) {
		return state, errors.New("invalid probe interval in state file")
	}
	if state.LastEvaluated == 0 {
		interval := state.ProbeIntervalSeconds
		state.LastEvaluated = max(protocol.WindowStart(now.Unix(), interval), state.ScheduleStart) - int64(interval)
	}
	return state, nil
}

func writeState(name string, state diskState) error {
	dir := filepath.Dir(name)
	temp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := json.NewEncoder(temp).Encode(state); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), name)
}
