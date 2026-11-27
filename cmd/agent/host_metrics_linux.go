package main

import (
	"bufio"
	"context"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"link-observatory/internal/protocol"
)

type cpuTicks struct {
	total uint64
	idle  uint64
}

func parseCPUTicks(line string) cpuTicks {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTicks{}
	}
	var ticks cpuTicks
	// Guest counters are already included in user and nice.
	for i, field := range fields[1:min(len(fields), 9)] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil || value > math.MaxUint64-ticks.total {
			return cpuTicks{}
		}
		ticks.total += value
		if i == 3 || i == 4 {
			ticks.idle += value
		}
	}
	return ticks
}

func readCPUTicks() cpuTicks {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTicks{}
	}
	defer file.Close()
	line, err := bufio.NewReader(file).ReadString('\n')
	if err != nil {
		return cpuTicks{}
	}
	return parseCPUTicks(line)
}

func cpuUsage(previous, current cpuTicks) *float64 {
	if previous.total == 0 || current.total <= previous.total || current.idle < previous.idle {
		return nil
	}
	total, idle := current.total-previous.total, current.idle-previous.idle
	if idle > total {
		return nil
	}
	usage := 100 * float64(total-idle) / float64(total)
	return &usage
}

func parseMemory(r io.Reader) *protocol.MetricCapacity {
	fields := make(map[string]uint64, 5)
	scanner := bufio.NewScanner(io.LimitReader(r, 16<<10))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 3 || parts[2] != "kB" {
			continue
		}
		switch parts[0] {
		case "MemTotal:", "MemAvailable:", "MemFree:", "Buffers:", "Cached:":
			value, err := strconv.ParseUint(parts[1], 10, 64)
			if err == nil && value <= math.MaxUint64/1024 {
				fields[parts[0]] = value
			}
		}
	}
	total := fields["MemTotal:"]
	if scanner.Err() != nil || total == 0 {
		return nil
	}
	available, ok := fields["MemAvailable:"]
	if !ok {
		free, ok := fields["MemFree:"]
		if !ok {
			return nil
		}
		available = free + fields["Buffers:"] + fields["Cached:"]
	}
	return &protocol.MetricCapacity{TotalBytes: total * 1024, UsedBytes: (total - min(available, total)) * 1024}
}

func readMemory() *protocol.MetricCapacity {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil
	}
	defer file.Close()
	return parseMemory(file)
}

func rootDiskCapacity() *protocol.MetricCapacity {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return nil
	}
	size := stat.Frsize
	if size <= 0 {
		size = stat.Bsize
	}
	if size <= 0 || stat.Blocks == 0 || stat.Bfree > stat.Blocks || stat.Blocks > math.MaxUint64/uint64(size) {
		return nil
	}
	return &protocol.MetricCapacity{TotalBytes: stat.Blocks * uint64(size), UsedBytes: (stat.Blocks - stat.Bfree) * uint64(size)}
}

func operatingSystemName() string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 16<<10))
		for scanner.Scan() {
			raw, found := strings.CutPrefix(scanner.Text(), "PRETTY_NAME=")
			if !found {
				continue
			}
			value, err := strconv.Unquote(raw)
			if err != nil {
				value = strings.Trim(raw, "\"'")
			}
			value = strings.Join(strings.Fields(value), " ")
			if value != "" && len(value) <= 128 {
				_ = file.Close()
				return value
			}
		}
		_ = file.Close()
	}
	return "Linux"
}

func watchHostMetrics(ctx context.Context) *atomic.Pointer[protocol.HostMetrics] {
	latest := new(atomic.Pointer[protocol.HostMetrics])
	go func() {
		osName := operatingSystemName()
		cores := runtime.NumCPU()
		ticker := time.NewTicker(configPollInterval)
		defer ticker.Stop()
		var previous cpuTicks
		for ctx.Err() == nil {
			at := time.Now().UTC()
			ticks := readCPUTicks()
			latest.Store(&protocol.HostMetrics{
				ObservedAt: at, OS: osName, Arch: runtime.GOARCH, CPUCores: cores,
				CPUUsage: cpuUsage(previous, ticks), Memory: readMemory(), Disk: rootDiskCapacity(),
			})
			previous = ticks
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return latest
}
