package main

import (
	"slices"

	"link-observatory/internal/protocol"
)

type reachabilityCount struct {
	Reachable int `json:"reachable"`
	Valid     int `json:"valid"`
}

type cohortCounts struct {
	TCP  reachabilityCount `json:"tcp"`
	ICMP reachabilityCount `json:"icmp"`
}

type roundCounts struct {
	Mainland cohortCounts `json:"mainland"`
	Overseas cohortCounts `json:"overseas"`
}

func (c *reachabilityCount) add(status string) {
	switch status {
	case "ok":
		c.Reachable++
		c.Valid++
	case "timeout", "refused", "reset", "unreachable":
		c.Valid++
	}
}

func (c *roundCounts) add(group string, result protocol.Result) bool {
	var cohort *cohortCounts
	switch group {
	case "mainland":
		cohort = &c.Mainland
	case "overseas":
		cohort = &c.Overseas
	default:
		return false
	}
	cohort.TCP.add(result.TCP.Status)
	cohort.ICMP.add(result.ICMP.Status)
	return true
}

// Older rounds may be accompanied by exact raw samples that are still retained.
// Leave missing rounds unknown and never replace a finalized count.
func historyWithCounts(state diskState, target targetRecord) []roundStatus {
	if target.History == nil {
		return []roundStatus{}
	}
	legacy := make(map[int64]int)
	for i, round := range target.History {
		if round.Counts == nil {
			legacy[round.At.Unix()] = i
		}
	}
	if len(legacy) == 0 {
		return target.History
	}

	var enriched []roundStatus
	sampled := true
	for id, node := range state.Nodes {
		for _, result := range state.Samples[id][target.ID].Results {
			i, needed := legacy[result.Window]
			if !needed {
				continue
			}
			if enriched == nil {
				enriched = slices.Clone(target.History)
			}
			round := &enriched[i]
			counts := round.Counts
			if counts == nil {
				counts = new(roundCounts)
			}
			if counts.add(node.Group, result) {
				round.Counts, round.Sampled = counts, &sampled
			}
		}
	}
	if enriched == nil {
		return target.History
	}
	return enriched
}
