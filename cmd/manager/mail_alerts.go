package main

import (
	"log"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"link-observatory/internal/protocol"
)

const (
	alertFailureRounds  = 3
	alertRecoveryRounds = 2
	maxMailQueue        = 512
	maxAlertAddresses   = 16
)

type mailNotice struct {
	ProbeName string            `json:"probe_name,omitempty"`
	Route     *routeChange      `json:"route,omitempty"`
	Kind      mailKind          `json:"kind"`
	Name      string            `json:"name,omitempty"`
	ID        string            `json:"id,omitempty"`
	Address   string            `json:"address,omitempty"`
	IP        string            `json:"ip,omitempty"`
	ISP       string            `json:"isp,omitempty"`
	Location  string            `json:"location,omitempty"`
	Group     string            `json:"group,omitempty"`
	Version   string            `json:"version,omitempty"`
	ISPs      []string          `json:"isps,omitempty"`
	Mainland  reachabilityCount `json:"mainland,omitzero"`
	Overseas  reachabilityCount `json:"overseas,omitzero"`
	Previous  reachabilityCount `json:"previous,omitzero"`
	At        time.Time         `json:"at"`
	StartedAt time.Time         `json:"started_at,omitzero"`
	LastSeen  time.Time         `json:"last_seen,omitzero"`
}

func (state *diskState) routeChangeMail(change routeChange) {
	target := state.Targets[change.Job.TargetID]
	node := state.Nodes[change.Job.ProbeID]
	state.enqueueMail(mailNotice{
		Kind: mailRouteChange, Name: target.Name, ID: target.ID, Address: target.IP, IP: change.IP,
		ProbeName: node.Name, ISP: node.ISP, Route: &change,
		At: time.Unix(change.At, 0).UTC(), StartedAt: time.Unix(change.FirstAt, 0).UTC(),
	})
}

type mailJob struct {
	ID       string     `json:"id"`
	Notice   mailNotice `json:"notice"`
	Attempts int        `json:"attempts,omitempty"`
	NextTry  time.Time  `json:"next_try,omitzero"`
}

func (state *diskState) enqueueMail(notice mailNotice) {
	if !state.Mail.wants(notice.Kind) {
		return
	}
	if len(state.MailQueue) >= maxMailQueue {
		log.Printf("mail queue full, skipped %s for %s", notice.Kind, notice.ID)
		return
	}
	state.MailQueue = append(slices.Clone(state.MailQueue), mailJob{ID: randomHex(16), Notice: notice})
}

func (s *server) evaluateProbeAvailability(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state
	changed := false
	for id, node := range s.state.Nodes {
		if node.MailOfflineSince != 0 || !probeOffline(node, now) {
			continue
		}
		if !changed {
			next.Nodes = maps.Clone(next.Nodes)
			changed = true
		}
		node.MailOfflineSince = node.LastSeen + int64(offlineAfter/time.Second)
		next.Nodes[id] = node
		next.enqueueMail(probeNotice(node, mailProbeOffline, now))
	}
	if changed {
		if err := writeState(s.filename, next); err != nil {
			log.Printf("save probe availability: %v", err)
			return
		}
		s.state = next
	}
}

func probeOffline(node nodeRecord, now time.Time) bool {
	return node.LastSeen > 0 && now.Sub(time.Unix(node.LastSeen, 0)) > offlineAfter
}

func probeNotice(node nodeRecord, kind mailKind, now time.Time) mailNotice {
	return mailNotice{
		Kind: kind, Name: node.Name, ID: node.ID, ISP: node.ISP, Location: node.Location,
		Group: node.Group, Version: node.Version, At: now.UTC(),
		StartedAt: time.Unix(node.MailOfflineSince, 0).UTC(), LastSeen: time.Unix(node.LastSeen, 0).UTC(),
	}
}

type protocolAlertState struct {
	Active         []protocolIncident `json:"active,omitempty"`
	RecoveryIP     string             `json:"recovery_ip,omitempty"`
	CandidateIP    string             `json:"candidate_ip,omitempty"`
	CandidateISPs  []string           `json:"candidate_isps,omitempty"`
	FailureRounds  int                `json:"failure_rounds,omitempty"`
	RecoveryRounds int                `json:"recovery_rounds,omitempty"`
}

func (alert *protocolAlertState) resetStreaks() {
	*alert = protocolAlertState{Active: alert.Active}
}

type protocolIncident struct {
	IP        string            `json:"ip"`
	ISPs      []string          `json:"isps"`
	StartedAt time.Time         `json:"started_at"`
	Mainland  reachabilityCount `json:"mainland,omitzero"`
}

type alertISP struct {
	name    string
	ok      bool
	timeout bool
}

type protocolWindow struct {
	ip             string
	mixedIP        bool
	mainland       map[string]alertISP
	mainlandCounts reachabilityCount
	overseasCounts reachabilityCount
}

func (window *protocolWindow) observe(ip string, node nodeRecord, probe protocol.Probe) {
	ok, timeout := probeOK(probe), probeTimeout(probe)
	if ip == "" || (!ok && !timeout) {
		return
	}
	if window.ip == "" {
		window.ip = ip
	}
	window.mixedIP = window.mixedIP || window.ip != ip
	if node.Group == "overseas" {
		window.overseasCounts.add(probe.Status)
		return
	}
	window.mainlandCounts.add(probe.Status)
	if window.mainland == nil {
		window.mainland = make(map[string]alertISP)
	}
	key := strings.ToLower(node.ISP)
	isp := window.mainland[key]
	isp.ok, isp.timeout = isp.ok || ok, isp.timeout || timeout
	if isp.name == "" || node.ISP < isp.name {
		isp.name = node.ISP
	}
	window.mainland[key] = isp
}

func (window protocolWindow) affected() []string {
	if window.mixedIP || window.overseasCounts.Reachable == 0 {
		return nil
	}
	var affected []string
	for key, isp := range window.mainland {
		if isp.timeout && !isp.ok {
			affected = append(affected, key)
		}
	}
	slices.Sort(affected)
	return affected
}

func (window protocolWindow) recovered(incident protocolIncident) bool {
	if window.mixedIP || window.ip != incident.IP || window.overseasCounts.Reachable == 0 {
		return false
	}
	for _, key := range incident.ISPs {
		if !window.mainland[key].ok {
			return false
		}
	}
	return true
}

func (state *diskState) recordTargetNotifications(target *targetRecord, evidence windowEvidence, window, step int64) {
	if !target.AlertsInitialized {
		target.AlertsInitialized = true
		// Older managers already recorded active TCP or dual-protocol incidents.
		// Keep them as the baseline so the next recovery can be announced.
		for _, event := range state.Events {
			if event.State != "active" || event.TargetID != target.ID || len(event.AffectedISPs) < 2 {
				continue
			}
			ip := event.ResolvedIP
			if literal, ok := protocol.ParseTargetIP(target.IP); ok {
				ip = literal.String()
			}
			if ip == "" {
				continue
			}
			incident := protocolIncident{IP: ip, ISPs: event.AffectedISPs, StartedAt: event.StartedAt}
			target.TCPAlert.Active = []protocolIncident{incident}
			if event.Verdict == verdictBothTimeout {
				target.ICMPAlert.Active = []protocolIncident{incident}
			}
			break
		}
	}
	state.recordProtocolAlert(target.Target, &target.TCPAlert, evidence.tcpAlert, mailTCPFailure, mailTCPRecovery, window, step)
	state.recordProtocolAlert(target.Target, &target.ICMPAlert, evidence.icmpAlert, mailICMPFailure, mailICMPRecovery, window, step)
}

func (state *diskState) recordProtocolAlert(target protocol.Target, alert *protocolAlertState, evidence protocolWindow, failure, recovery mailKind, window, step int64) {
	var kind mailKind
	var incident protocolIncident
	index := slices.IndexFunc(alert.Active, func(item protocolIncident) bool { return item.IP == evidence.ip })
	if index >= 0 {
		incident = alert.Active[index]
		alert.CandidateIP, alert.CandidateISPs, alert.FailureRounds = "", nil, 0
		recovered := evidence.recovered(incident)
		if alert.RecoveryIP != evidence.ip || !recovered {
			alert.RecoveryRounds, alert.RecoveryIP = 0, ""
		}
		if !recovered {
			return
		}
		alert.RecoveryIP = evidence.ip
		alert.RecoveryRounds++
		if alert.RecoveryRounds < alertRecoveryRounds {
			return
		}
		alert.Active = slices.Delete(slices.Clone(alert.Active), index, index+1)
		alert.resetStreaks()
		kind = recovery
	} else {
		alert.RecoveryRounds, alert.RecoveryIP = 0, ""
		affected := evidence.affected()
		if len(affected) < 2 {
			alert.resetStreaks()
			return
		}
		if alert.CandidateIP != evidence.ip || !slices.Equal(alert.CandidateISPs, affected) {
			alert.CandidateIP, alert.CandidateISPs, alert.FailureRounds = evidence.ip, affected, 0
		}
		alert.FailureRounds++
		if alert.FailureRounds < alertFailureRounds {
			return
		}
		incident = protocolIncident{
			IP: evidence.ip, ISPs: affected, Mainland: evidence.mainlandCounts,
			StartedAt: time.Unix(window-(alertFailureRounds-1)*step, 0).UTC(),
		}
		// A hostname can rotate through several IPs. Keep recent incidents
		// independently, and bound old entries that may never be probed again.
		active := alert.Active[max(0, len(alert.Active)+1-maxAlertAddresses):]
		alert.Active = append(slices.Clone(active), incident)
		alert.resetStreaks()
		kind = failure
	}

	address := target.IP
	if failure == mailTCPFailure {
		address = net.JoinHostPort(address, strconv.Itoa(target.Port))
	}
	notice := mailNotice{
		Kind: kind, ID: target.ID, Name: target.Name, Address: address, IP: evidence.ip,
		Mainland: evidence.mainlandCounts, Overseas: evidence.overseasCounts, Previous: incident.Mainland,
		At: time.Unix(window, 0).UTC(), StartedAt: incident.StartedAt,
	}
	for _, key := range incident.ISPs {
		notice.ISPs = append(notice.ISPs, evidence.mainland[key].name)
	}
	state.enqueueMail(notice)
}
