package main

import (
	"context"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"link-observatory/internal/protocol"
)

const (
	verdictPending       = "pending"
	verdictOK            = "ok"
	verdictICMPNoReply   = "icmp_no_reply"
	verdictRefused       = "refused"
	verdictInsufficient  = "insufficient"
	verdictMultiRegion   = "multi_region_unreachable"
	verdictSuspectedPort = "suspected_port_block"
	verdictBothTimeout   = "tcp_icmp_timeout"
	legacyDualVerdict    = "suspected_regional_block"
)

func updateSeries(series sampleSeries, result protocol.Result, present int64, interval int) sampleSeries {
	maxAge := int64((rawWindows - 1) * interval)
	if result.Window < present-maxAge {
		return series
	}
	for _, existing := range series.Results {
		if existing.Window == result.Window {
			return series
		}
	}
	results := slices.Clone(series.Results)
	results = slices.DeleteFunc(results, func(item protocol.Result) bool {
		return item.Window < present-maxAge
	})
	results = append(results, result)
	slices.SortFunc(results, func(a, b protocol.Result) int {
		if a.Window < b.Window {
			return 1
		}
		if a.Window > b.Window {
			return -1
		}
		return 0
	})
	// Histories from a previous, shorter cadence can coexist during a switch.
	series.Results = results[:min(len(results), rawWindows+1)]
	return series
}

func probeOK(probe protocol.Probe) bool {
	return probe.Status == "ok" && probe.Received > 0
}

func probeTimeout(probe protocol.Probe) bool {
	return probe.Status == "timeout" && probe.Sent > 0 && probe.Received == 0
}

func atWindow(series sampleSeries, window int64) (protocol.Result, bool) {
	for _, result := range series.Results {
		if result.Window == window {
			return result, true
		}
	}
	return protocol.Result{}, false
}

type ispObservation struct {
	name        string
	tcpObserved bool
	tcpOK       bool
	icmpOK      bool
	bothOK      bool
	tcpTimeout  bool
	tcpOnly     bool
	bothTimeout bool
}

type windowEvidence struct {
	status         string
	resolvedIP     string
	comparable     bool
	counts         roundCounts
	sampled        bool
	affectedISPs   []string
	mainland       map[string]ispObservation
	overseasTCP    bool
	overseasBothOK bool
	tcpAlert       protocolWindow
	icmpAlert      protocolWindow
}

func assess(state diskState, targetID string, window int64) windowEvidence {
	evidence := windowEvidence{
		status: verdictInsufficient, comparable: true,
		mainland: make(map[string]ispObservation),
	}
	address := state.Targets[targetID].IP
	_, literal := protocol.ParseTargetIP(address)
	hostname := address != "" && !literal
	var overseasObserved, overseasTimeout, refused, icmpNoReply bool
	for id, node := range state.Nodes {
		result, found := atWindow(state.Samples[id][targetID], window)
		if !found || !evidence.counts.add(node.Group, result) {
			continue
		}
		evidence.sampled = true
		if hostname {
			if result.ResolvedIP == "" {
				continue
			}
			if evidence.resolvedIP == "" {
				evidence.resolvedIP = result.ResolvedIP
			} else if evidence.resolvedIP != result.ResolvedIP {
				evidence.comparable = false
			}
		}

		resolved := address
		if hostname {
			resolved = result.ResolvedIP
		}
		evidence.tcpAlert.observe(resolved, node, result.TCP)
		evidence.icmpAlert.observe(resolved, node, result.ICMP)

		tcpOK, icmpOK := probeOK(result.TCP), probeOK(result.ICMP)
		tcpTimeout, icmpTimeout := probeTimeout(result.TCP), probeTimeout(result.ICMP)
		tcpRefused := result.TCP.Status == "refused"
		tcpObserved := tcpOK || tcpTimeout || tcpRefused
		refused = refused || tcpRefused
		icmpNoReply = icmpNoReply || tcpOK && icmpTimeout

		if node.Group == "overseas" {
			overseasObserved = overseasObserved || tcpObserved
			overseasTimeout = overseasTimeout || tcpTimeout
			evidence.overseasTCP = evidence.overseasTCP || tcpOK
			evidence.overseasBothOK = evidence.overseasBothOK || tcpOK && icmpOK
			continue
		}

		isp := strings.ToLower(node.ISP)
		observation := evidence.mainland[isp]
		if observation.name == "" || node.ISP < observation.name {
			observation.name = node.ISP
		}
		observation.tcpObserved = observation.tcpObserved || tcpObserved
		observation.tcpOK = observation.tcpOK || tcpOK
		observation.icmpOK = observation.icmpOK || icmpOK
		observation.bothOK = observation.bothOK || tcpOK && icmpOK
		observation.tcpTimeout = observation.tcpTimeout || tcpTimeout
		observation.tcpOnly = observation.tcpOnly || tcpTimeout && icmpOK
		observation.bothTimeout = observation.bothTimeout || tcpTimeout && icmpTimeout
		evidence.mainland[isp] = observation
	}
	if !evidence.comparable {
		return evidence
	}

	var mainlandTCP bool
	var mainlandObserved, mainlandTimeouts int
	var tcpOnly, bothTimeout []string
	for isp, observation := range evidence.mainland {
		mainlandTCP = mainlandTCP || observation.tcpOK
		if observation.tcpObserved {
			mainlandObserved++
		}
		if observation.tcpTimeout {
			mainlandTimeouts++
		}
		if !observation.tcpOK && observation.tcpOnly {
			tcpOnly = append(tcpOnly, isp)
		}
		if !observation.tcpOK && !observation.icmpOK && observation.bothTimeout {
			bothTimeout = append(bothTimeout, isp)
		}
	}
	switch {
	case len(bothTimeout) >= 2 && evidence.overseasBothOK:
		evidence.status, evidence.affectedISPs = verdictBothTimeout, bothTimeout
	case len(tcpOnly) >= 2 && evidence.overseasTCP:
		evidence.status, evidence.affectedISPs = verdictSuspectedPort, tcpOnly
	case mainlandTimeouts >= 2 && overseasTimeout && !mainlandTCP && !evidence.overseasTCP:
		evidence.status = verdictMultiRegion
	case mainlandObserved >= 2 && overseasObserved && refused && !mainlandTCP && !evidence.overseasTCP:
		evidence.status = verdictRefused
	case mainlandObserved >= 2 && mainlandTCP && evidence.overseasTCP && icmpNoReply:
		evidence.status = verdictICMPNoReply
	case mainlandObserved >= 2 && mainlandTCP && evidence.overseasTCP:
		evidence.status = verdictOK
	}
	return evidence
}

func (e windowEvidence) recovered(event eventRecord) bool {
	if !e.comparable || len(event.AffectedISPs) < 2 || event.ResolvedIP != e.resolvedIP {
		return false
	}
	both := event.Verdict == verdictBothTimeout
	if !e.overseasTCP || both && !e.overseasBothOK {
		return false
	}
	for _, isp := range event.AffectedISPs {
		observation := e.mainland[isp]
		if !observation.tcpOK || both && !observation.bothOK {
			return false
		}
	}
	return true
}

func (s *server) evaluateLoop(ctx context.Context) {
	now := time.Now()
	s.evaluateClosedWindows(now)
	s.evaluateProbeAvailability(now)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.evaluateClosedWindows(now)
			s.evaluateProbeAvailability(now)
		}
	}
}

func (s *server) evaluateClosedWindows(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	interval := s.state.ProbeIntervalSeconds
	step := int64(interval)
	last := protocol.WindowStart(now.Unix(), interval) - step
	if last < s.state.ScheduleStart || last <= s.state.LastEvaluated {
		return
	}
	if len(s.state.Targets) == 0 {
		s.state.LastEvaluated = last
		return
	}
	next := s.state
	next.Targets = maps.Clone(next.Targets)
	next.Events = slices.Clone(next.Events)
	first := max(next.LastEvaluated+step, next.ScheduleStart)
	oldest := last - int64(rawWindows-2)*step
	if first < oldest {
		first = oldest
		for id, target := range next.Targets {
			target.resetEvidenceStreaks()
			next.Targets[id] = target
		}
	}
	for window := first; window <= last; window += step {
		for id, target := range next.Targets {
			if window < protocol.WindowStart(target.monitoringSince().Unix(), interval) {
				continue
			}
			evidence := assess(next, id, window)
			next.recordTargetNotifications(&target, evidence, window, step)
			status := recordWindow(&next, &target, evidence, window, step)
			counts, sampled := evidence.counts, evidence.sampled
			history := slices.Clone(historyWithCounts(next, target))
			history = append(history, roundStatus{
				At: time.Unix(window, 0).UTC(), Status: status, Counts: &counts, Sampled: &sampled,
			})
			if len(history) > historyWindows {
				history = history[len(history)-historyWindows:]
			}
			target.History = history
			next.Targets[id] = target
		}
	}
	next.LastEvaluated = last
	for len(next.Events) > maxEvents {
		index := slices.IndexFunc(next.Events, func(event eventRecord) bool { return event.State == "resolved" })
		if index < 0 {
			break
		}
		next.Events = slices.Delete(next.Events, index, index+1)
	}
	if err := writeState(s.filename, next); err != nil {
		log.Printf("save evaluation: %v", err)
		return
	}
	s.state = next
}

func recordWindow(state *diskState, target *targetRecord, evidence windowEvidence, window, step int64) string {
	active := slices.IndexFunc(state.Events, func(event eventRecord) bool {
		return event.TargetID == target.ID && event.State == "active"
	})
	candidate := evidence.status == verdictSuspectedPort || evidence.status == verdictBothTimeout
	if !candidate || target.CandidateIP != evidence.resolvedIP || target.CandidateStatus != evidence.status {
		target.CandidateWindows = 0
		target.CandidateIP, target.CandidateStatus = "", ""
	}
	if candidate {
		target.CandidateIP, target.CandidateStatus = evidence.resolvedIP, evidence.status
		target.CandidateWindows = min(target.CandidateWindows+1, 3)
	}

	if active >= 0 && !candidate && evidence.recovered(state.Events[active]) {
		target.RecoveryWindows++
		if target.RecoveryWindows >= 2 {
			at := time.Unix(window, 0).UTC()
			state.Events[active].EndedAt, state.Events[active].State = &at, "resolved"
			target.RecoveryWindows = 0
		}
	} else {
		target.RecoveryWindows = 0
	}
	if !candidate {
		return evidence.status
	}
	if active >= 0 {
		event := &state.Events[active]
		if event.ResolvedIP != evidence.resolvedIP {
			return verdictInsufficient
		}
		if event.Verdict == evidence.status {
			return evidence.status
		}
	}
	if target.CandidateWindows < 3 {
		return verdictInsufficient
	}

	slices.Sort(evidence.affectedISPs)
	ispNames := make([]string, len(evidence.affectedISPs))
	for i, isp := range evidence.affectedISPs {
		ispNames[i] = evidence.mainland[isp].name
	}
	if active < 0 {
		state.Events = append(state.Events, eventRecord{
			ID: "event-" + randomHex(8), TargetID: target.ID, TargetName: target.Name,
			State: "active", Verdict: evidence.status, AffectedISPs: evidence.affectedISPs, ResolvedIP: evidence.resolvedIP,
			AffectedISPNames: ispNames,
			StartedAt:        time.Unix(window-2*step, 0).UTC(),
		})
	} else {
		state.Events[active].Verdict = evidence.status
		state.Events[active].AffectedISPs = evidence.affectedISPs
		state.Events[active].AffectedISPNames = ispNames
	}
	return evidence.status
}
