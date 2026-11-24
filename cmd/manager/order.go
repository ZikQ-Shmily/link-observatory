package main

import (
	"net/http"
	"slices"
)

func orderPositions(ids []string) map[string]int {
	positions := make(map[string]int, len(ids))
	for i, id := range ids {
		positions[id] = i - len(ids) // Unlisted entries (zero) follow the saved order.
	}
	return positions
}

func removeOrderEntry(ids []string, id string) []string {
	if index := slices.Index(ids, id); index >= 0 {
		return slices.Delete(slices.Clone(ids), index, index+1)
	}
	return ids
}

func (s *server) reorderNodes(w http.ResponseWriter, r *http.Request) {
	s.updateOrder(w, r, true)
}

func (s *server) reorderTargets(w http.ResponseWriter, r *http.Request) {
	s.updateOrder(w, r, false)
}

func (s *server) updateOrder(w http.ResponseWriter, r *http.Request, nodes bool) {
	var input struct {
		IDs []string `json:"ids"`
	}
	if !decodeJSON(w, r, &input, 8192) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state
	if (nodes && !validOrder(input.IDs, next.Nodes)) || (!nodes && !validOrder(input.IDs, next.Targets)) {
		writeError(w, http.StatusConflict, "列表已变化，请刷新后重新排序。")
		return
	}
	if nodes {
		next.NodeOrder = input.IDs
	} else {
		next.TargetOrder = input.IDs
	}
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func validOrder[T any](ids []string, entries map[string]T) bool {
	if len(ids) != len(entries) {
		return false
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, exists := entries[id]; !exists || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
