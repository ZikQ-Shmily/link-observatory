package main

import (
	"net/http"
	"time"

	"link-observatory/internal/protocol"
)

const updateTimeout = 20 * time.Minute

type updateTask struct {
	Offer     protocol.UpdateOffer
	Status    string
	ExpiresAt int64
}

type updateView struct {
	Version string `json:"version"`
	Status  string `json:"status"`
}

func (task updateTask) view(now time.Time) *updateView {
	status := task.Status
	if status == "" {
		return nil
	}
	if (status == "queued" || status == "running") && now.Unix() >= task.ExpiresAt {
		status = "expired"
	}
	return &updateView{Version: task.Offer.Version, Status: status}
}

func (s *server) queueUpdate(w http.ResponseWriter, r *http.Request) {
	release, err := s.probeRelease(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	tag := release.officialTag()
	offer := protocol.UpdateOffer{ID: randomHex(16), Version: tag, InstallerSHA256: release.SHA256}
	if !offer.Valid() {
		writeError(w, http.StatusConflict, "管理端更新需要官方稳定发行版。")
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
	if current := node.Update.view(now); current != nil && (current.Status == "queued" || current.Status == "running") {
		writeJSON(w, http.StatusAccepted, current)
		return
	}
	if !node.ManagedUpdates {
		writeError(w, http.StatusConflict, "请先在主机上用 install.sh 升级一次，启用管理端更新。")
		return
	}
	if !protocol.NewerVersion(tag, node.Version) {
		if tag == node.Version {
			writeError(w, http.StatusConflict, "当前已是所配置的发行版本。")
		} else {
			writeError(w, http.StatusConflict, "没有可用的正式升级版本。")
		}
		return
	}
	node.Update = updateTask{Offer: offer, Status: "queued", ExpiresAt: now.Add(updateTimeout).Unix()}
	next := s.state
	next.setAgent(node)
	if s.commit(w, next) {
		writeJSON(w, http.StatusAccepted, node.Update.view(now))
	}
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
	now := time.Now()
	priorVersion := node.Version
	task := node.Update
	var offer *protocol.UpdateOffer
	if task.Status == "queued" || task.Status == "running" || task.Status == "expired" {
		switch {
		case input.Version == task.Offer.Version:
			task.Status = "succeeded"
			node.Version = input.Version
		case input.FailedID == task.Offer.ID:
			task.Status = "failed"
		case now.Unix() >= task.ExpiresAt:
			task.Status = "expired"
		case input.Ready && protocol.NewerVersion(task.Offer.Version, input.Version):
			task.Status = "running"
			offer = &task.Offer
		}
	}
	if node.ManagedUpdates != input.Ready || node.Update != task || node.Version != priorVersion {
		node.ManagedUpdates, node.Update = input.Ready, task
		next := s.state
		next.setAgent(node)
		if !s.commit(w, next) {
			return
		}
	}
	writeJSON(w, http.StatusOK, offer)
}
