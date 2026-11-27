package main

import (
	"encoding/json"
	"time"

	"link-observatory/internal/protocol"
)

func latestHostMetrics(previous *protocol.HostMetrics, raw json.RawMessage, now time.Time) *protocol.HostMetrics {
	// A malformed optional sample must not interfere with reachability reports.
	if len(raw) == 0 || len(raw) > 4096 {
		return previous
	}
	var metrics protocol.HostMetrics
	if err := json.Unmarshal(raw, &metrics); err != nil {
		return previous
	}
	observed := metrics.ObservedAt
	if observed.Unix() <= 0 || observed.After(now.Add(time.Duration(protocol.DefaultIntervalSeconds)*time.Second)) ||
		(previous != nil && !observed.After(previous.ObservedAt)) {
		return previous
	}
	metrics.ObservedAt = observed.UTC()
	metrics.OS, metrics.Arch = cleanLabel(metrics.OS), cleanLabel(metrics.Arch)
	if !validLabel(metrics.OS, 128) {
		metrics.OS = ""
	}
	if !validLabel(metrics.Arch, 32) {
		metrics.Arch = ""
	}
	if metrics.CPUCores < 1 || metrics.CPUCores > 1<<20 {
		metrics.CPUCores = 0
	}
	if metrics.CPUUsage != nil && !(*metrics.CPUUsage >= 0 && *metrics.CPUUsage <= 100) {
		metrics.CPUUsage = nil
	}
	if !validMetricCapacity(metrics.Memory) {
		metrics.Memory = nil
	}
	if !validMetricCapacity(metrics.Disk) {
		metrics.Disk = nil
	}
	if metrics.OS == "" && metrics.Arch == "" && metrics.CPUCores == 0 && metrics.CPUUsage == nil &&
		metrics.Memory == nil && metrics.Disk == nil {
		return previous
	}
	return &metrics
}

func validMetricCapacity(capacity *protocol.MetricCapacity) bool {
	return capacity != nil && capacity.TotalBytes > 0 && capacity.UsedBytes <= capacity.TotalBytes
}
