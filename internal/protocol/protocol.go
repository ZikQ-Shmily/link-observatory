// Package protocol defines the wire format shared by the manager and probes.
package protocol

import (
	"net/netip"
	"strings"
)

const (
	DefaultIntervalSeconds = 60
	MaxIntervalSeconds     = 600
	ScheduleHeader         = "X-Probe-Schedule"
	HostnamesHeader        = "X-Probe-Hostnames"
)

func ValidIntervalSeconds(seconds int) bool {
	return seconds >= DefaultIntervalSeconds && seconds <= MaxIntervalSeconds && seconds%60 == 0
}

func WindowStart(unix int64, seconds int) int64 {
	return unix - unix%int64(seconds)
}

func ParseTargetIP(value string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, false
	}
	return ip, true
}

// NormalizeTargetAddress accepts an IP literal or a fully qualified ASCII hostname.
func NormalizeTargetAddress(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if ip, ok := ParseTargetIP(value); ok {
		return ip.String(), true
	}

	name := strings.TrimSuffix(value, ".")
	if len(name) > 253 || !strings.Contains(name, ".") {
		return "", false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, char := range label {
			if !asciiLetter(char) && !(char >= '0' && char <= '9') && char != '-' {
				return "", false
			}
		}
	}
	if strings.IndexFunc(labels[len(labels)-1], asciiLetter) == -1 {
		return "", false
	}
	return strings.ToLower(name), true
}

func asciiLetter(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

type Enrollment struct {
	NodeID     string `json:"node_id"`
	Token      string `json:"token"`
	Credential string `json:"credential"`
	Version    string `json:"version"`
}

type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type Config struct {
	Targets         []Target `json:"targets"`
	Control         *Target  `json:"control,omitempty"` // Accepted from older managers.
	IntervalSeconds int      `json:"interval_seconds"`
	ScheduleStart   int64    `json:"schedule_start,omitempty"`
	ValidUntil      int64    `json:"valid_until"`
}

type Probe struct {
	Status    string  `json:"status"`
	Sent      int     `json:"sent"`
	Received  int     `json:"received"`
	RTTMillis float64 `json:"rtt_ms"`
	Detail    string  `json:"detail,omitempty"`
}

type Result struct {
	TargetID   string `json:"target_id"`
	Window     int64  `json:"window"`
	ResolvedIP string `json:"resolved_ip,omitempty"`
	TCP        Probe  `json:"tcp"`
	ICMP       Probe  `json:"icmp"`
}

type Report struct {
	Version string   `json:"version"`
	ICMPv4  bool     `json:"icmp_v4"`
	ICMPv6  bool     `json:"icmp_v6"`
	Results []Result `json:"results"`
}
