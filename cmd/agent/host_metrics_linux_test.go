package main

import (
	"strings"
	"testing"
)

func TestHostCPUUsageUsesTickDeltas(t *testing.T) {
	previous := parseCPUTicks("cpu 100 10 20 60 10 0 0 0 10 0")
	current := parseCPUTicks("cpu 120 10 25 80 15 0 0 0 30 0")
	if previous != (cpuTicks{total: 200, idle: 70}) || current != (cpuTicks{total: 250, idle: 95}) {
		t.Fatalf("CPU totals include guest counters or omit idle time: %+v to %+v", previous, current)
	}
	if usage := cpuUsage(previous, current); usage == nil || *usage != 50 {
		t.Fatalf("CPU usage = %v, want 50%%", usage)
	}
	if usage := cpuUsage(previous, parseCPUTicks("cpu 100 10 20 70 10 0 0 0")); usage == nil || *usage != 0 {
		t.Fatalf("idle CPU usage = %v, want 0%%", usage)
	}
	if cpuUsage(cpuTicks{}, previous) != nil || cpuUsage(current, previous) != nil ||
		parseCPUTicks("cpu not-a-number 0 0 123") != (cpuTicks{}) {
		t.Fatal("initial, reset, and invalid CPU counters must not produce usage")
	}
}

func TestHostMemoryUsesAvailableAndBuffers(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		used  uint64
	}{
		{"available", "MemTotal: 8000 kB\nMemAvailable: 5500 kB\nMemFree: 1000 kB\n", 2500},
		{"legacy", "MemTotal: 8000 kB\nMemFree: 1000 kB\nBuffers: 1000 kB\nCached: 2000 kB\n", 4000},
		{"fully used", "MemTotal: 8000 kB\nMemAvailable: 0 kB\n", 8000},
	} {
		t.Run(test.name, func(t *testing.T) {
			memory := parseMemory(strings.NewReader(test.input))
			if memory == nil || memory.TotalBytes != 8000*1024 || memory.UsedBytes != test.used*1024 {
				t.Fatalf("memory = %+v, want 8000 KiB total and %d KiB used", memory, test.used)
			}
		})
	}
	if parseMemory(strings.NewReader("MemTotal: 8000 kB")) != nil {
		t.Fatal("memory usage without available or free counters must be omitted")
	}
}
