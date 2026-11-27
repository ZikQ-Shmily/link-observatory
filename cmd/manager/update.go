package main

import (
	"maps"
	"net/http"
	"time"

	"link-observatory/internal/protocol"
)

const (
	updateTimeout            = 20 * time.Minute
	updateSuccessFeedbackTTL = time.Minute
	updateLockReleaseGrace   = 10 * time.Second
	batchUpdateWait          = time.Duration(maxNodes+maxTargets) * (updateTimeout + time.Minute)
)

type updateTask struct {
	Offer       protocol.UpdateOffer
	Status      string
	ExpiresAt   int64
	CompletedAt int64 `json:",omitempty"`
	Batch       bool  `json:",omitempty"`
}

type updateView struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	Status       string `json:"status"`
	SuccessUntil int64  `json:"success_until,omitempty"`
}

func (task updateTask) active(now time.Time) bool {
	return (task.Status == "queued" || task.Status == "running") && now.Unix() < task.ExpiresAt
}

func (task updateTask) view(now time.Time) *updateView {
	status := task.Status
	if status == "" || status == "superseded" {
		return nil
	}
	if (status == "queued" || status == "running") && now.Unix() >= task.ExpiresAt {
		status = "expired"
	}
	view := &updateView{ID: task.Offer.ID, Version: task.Offer.Version, Status: status}
	if status == "succeeded" {
		view.SuccessUntil = task.CompletedAt + int64(updateSuccessFeedbackTTL/time.Second)
		if task.CompletedAt == 0 || now.Unix() >= view.SuccessUntil {
			return nil
		}
	}
	return view
}

func (node nodeRecord) updateView(now time.Time) *updateView {
	view := node.Update.view(now)
	if view != nil && (view.Status == "failed" || view.Status == "expired") && node.Version != "" &&
		(node.Version == view.Version || protocol.NewerVersion(node.Version, view.Version)) {
		return nil
	}
	return view
}

func (s *server) managedUpdateOffer(w http.ResponseWriter, r *http.Request) (protocol.UpdateOffer, bool) {
	release, err := s.probeRelease(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return protocol.UpdateOffer{}, false
	}
	offer := protocol.UpdateOffer{ID: randomHex(16), Version: release.officialTag(), InstallerSHA256: release.SHA256}
	if !offer.Valid() {
		writeError(w, http.StatusConflict, "管理端更新需要官方稳定发行版。")
		return protocol.UpdateOffer{}, false
	}
	return offer, true
}

func queuedUpdate(offer protocol.UpdateOffer, now time.Time, batch bool) updateTask {
	deadline := now.Add(updateTimeout)
	if batch {
		deadline = now.Add(batchUpdateWait)
	}
	return updateTask{Offer: offer, Status: "queued", ExpiresAt: deadline.Unix(), Batch: batch}
}

func (s *server) queueUpdate(w http.ResponseWriter, r *http.Request) {
	offer, ok := s.managedUpdateOffer(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	id := r.PathValue("id")
	node, exists := s.state.Nodes[id]
	if targetID := r.PathValue("target"); targetID != "" {
		target := s.state.Targets[targetID]
		node, exists = s.state.RouteRunners[target.ReturnRunner]
		exists = exists && node.ReturnTarget == targetID
	}
	if !exists || node.Credential == "" {
		writeError(w, http.StatusNotFound, "该探针或回程端尚未注册。")
		return
	}
	if node.Update.active(now) {
		writeJSON(w, http.StatusAccepted, node.Update.view(now))
		return
	}
	if !node.ManagedUpdates {
		writeError(w, http.StatusConflict, "请先在主机上用 install.sh 升级一次，启用管理端更新。")
		return
	}
	if !protocol.NewerVersion(offer.Version, node.Version) {
		if offer.Version == node.Version {
			writeError(w, http.StatusConflict, "当前已是所配置的发行版本。")
		} else {
			writeError(w, http.StatusConflict, "没有可用的正式升级版本。")
		}
		return
	}
	node.Update = queuedUpdate(offer, now, false)
	next := s.state
	next.setAgent(node)
	if s.commit(w, next) {
		writeJSON(w, http.StatusAccepted, node.Update.view(now))
	}
}

type bulkUpdateSummary struct {
	Version string `json:"version"`
	Queued  struct {
		Probes        int `json:"probes"`
		ReturnRunners int `json:"return_runners"`
	} `json:"queued"`
	Skipped struct {
		UpToDate           int `json:"up_to_date"`
		Active             int `json:"active"`
		Offline            int `json:"offline"`
		Unsupported        int `json:"unsupported"`
		Unregistered       int `json:"unregistered"`
		VersionUnavailable int `json:"version_unavailable"`
	} `json:"skipped"`
}

func (summary *bulkUpdateSummary) canQueue(node nodeRecord, now time.Time) bool {
	switch {
	case node.Credential == "":
		summary.Skipped.Unregistered++
	case node.Update.active(now):
		summary.Skipped.Active++
	case node.Version == summary.Version || protocol.NewerVersion(node.Version, summary.Version):
		summary.Skipped.UpToDate++
	case node.LastSeen == 0 || probeOffline(node, now):
		summary.Skipped.Offline++
	case !node.ManagedUpdates:
		summary.Skipped.Unsupported++
	case !protocol.NewerVersion(summary.Version, node.Version):
		summary.Skipped.VersionUnavailable++
	default:
		return true
	}
	return false
}

func (s *server) queueAllUpdates(w http.ResponseWriter, r *http.Request) {
	offer, ok := s.managedUpdateOffer(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	summary := bulkUpdateSummary{Version: offer.Version}
	next := s.state
	next.Nodes = maps.Clone(next.Nodes)
	next.RouteRunners = maps.Clone(next.RouteRunners)
	for id, node := range s.state.Nodes {
		if summary.canQueue(node, now) {
			offer.ID = randomHex(16)
			node.Update = queuedUpdate(offer, now, true)
			next.Nodes[id] = node
			summary.Queued.Probes++
		}
	}
	for id, node := range s.state.RouteRunners {
		target, exists := s.state.Targets[node.ReturnTarget]
		if node.ReturnTarget == "" || !exists || target.ReturnRunner != id {
			continue
		}
		if summary.canQueue(node, now) {
			offer.ID = randomHex(16)
			node.Update = queuedUpdate(offer, now, true)
			next.RouteRunners[id] = node
			summary.Queued.ReturnRunners++
		}
	}
	if summary.Queued.Probes+summary.Queued.ReturnRunners == 0 {
		writeJSON(w, http.StatusOK, summary)
	} else if s.commit(w, next) {
		writeJSON(w, http.StatusAccepted, summary)
	}
}

func (state diskState) canClaimUpdate(batch bool, now time.Time) bool {
	// Installers on the same host share a directory lock. The manager cannot
	// tell which instances share a host, so batch work uses one fleet-wide slot.
	for _, agents := range []map[string]nodeRecord{state.Nodes, state.RouteRunners} {
		for _, node := range agents {
			task := node.Update
			if !batch && !task.Batch {
				continue
			}
			if (task.Status == "running" && task.active(now)) ||
				(task.Status == "succeeded" && task.CompletedAt > 0 && now.Unix() < task.CompletedAt+int64(updateLockReleaseGrace/time.Second)) {
				return false
			}
		}
	}
	return true
}

func (state diskState) applyUpdatePoll(node *nodeRecord, input protocol.UpdatePoll, now time.Time) *protocol.UpdateOffer {
	node.ManagedUpdates = input.Ready
	task := &node.Update
	if task.Status != "queued" && task.Status != "running" && task.Status != "expired" {
		return nil
	}
	switch {
	case input.Version == task.Offer.Version:
		task.Status = "succeeded"
		task.CompletedAt = now.Unix()
		node.Version = input.Version
	case task.Batch && protocol.NewerVersion(input.Version, task.Offer.Version):
		task.Status = "superseded"
		node.Version = input.Version
	case input.FailedID == task.Offer.ID:
		task.Status = "failed"
	case now.Unix() >= task.ExpiresAt:
		task.Status = "expired"
	case input.Ready && protocol.NewerVersion(task.Offer.Version, input.Version):
		if task.Status != "running" {
			if !state.canClaimUpdate(task.Batch, now) {
				return nil
			}
			task.Status = "running"
			if task.Batch {
				task.ExpiresAt = now.Add(updateTimeout).Unix()
			}
		}
		return &task.Offer
	}
	return nil
}

func (s *server) pollUpdate(w http.ResponseWriter, r *http.Request) {
	var input protocol.UpdatePoll
	if !decodeJSON(w, r, &input, 2048) {
		return
	}
	if len(input.Version) > 64 || (input.FailedID != "" && !protocol.ValidUpdateID(input.FailedID)) {
		writeError(w, http.StatusBadRequest, "invalid update poll")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.agent(w, r)
	if !ok {
		return
	}
	prior := node
	offer := s.state.applyUpdatePoll(&node, input, time.Now())
	if node != prior {
		next := s.state
		next.setAgent(node)
		if !s.commit(w, next) {
			return
		}
	}
	writeJSON(w, http.StatusOK, offer)
}
