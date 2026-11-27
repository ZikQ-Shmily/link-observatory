// Package protocol defines the wire format shared by the manager and probes.
package protocol

import (
	"net/netip"
	"strings"
	"time"
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

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("3fff::/20"),
}

func PublicIP(value string, family int) (netip.Addr, bool) {
	ip, ok := ParseTargetIP(value)
	if !ok || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
		(family != 4 && family != 6) || ip.Is4() != (family == 4) {
		return netip.Addr{}, false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return netip.Addr{}, false
		}
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
	HostMetrics     bool     `json:"host_metrics,omitempty"`
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
	Version string       `json:"version"`
	ICMPv4  bool         `json:"icmp_v4"`
	ICMPv6  bool         `json:"icmp_v6"`
	Results []Result     `json:"results"`
	Metrics *HostMetrics `json:"metrics,omitempty"`
}

type HostMetrics struct {
	ObservedAt time.Time       `json:"observed_at"`
	OS         string          `json:"os,omitempty"`
	Arch       string          `json:"arch,omitempty"`
	CPUCores   int             `json:"cpu_cores,omitempty"`
	CPUUsage   *float64        `json:"cpu_usage_percent,omitempty"`
	Memory     *MetricCapacity `json:"memory,omitempty"`
	Disk       *MetricCapacity `json:"disk,omitempty"`
}

type MetricCapacity struct {
	TotalBytes uint64 `json:"total_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
}

const (
	RoutePollPath   = "/api/agent/routes/poll"
	RouteResultPath = "/api/agent/routes/result"
	MaxRouteHops    = 30
	RouteOut        = "out"
	RouteBack       = "back"
)

type RoutePoll struct {
	Manual  bool   `json:"manual,omitempty"`
	Busy    bool   `json:"busy,omitempty"`
	Ready   bool   `json:"ready"`
	Sampled bool   `json:"sampled"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
}

type RouteJob struct {
	ManualID   string `json:"manual_id,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	TargetID   string `json:"target_id"`
	Generation string `json:"generation"`
	ProbeID    string `json:"probe_id"`
	Direction  string `json:"direction"`
	Family     int    `json:"family"`
	Address    string `json:"address"`
	Window     int64  `json:"window"`
}

type RouteHop struct {
	TTL      int     `json:"ttl"`
	IP       string  `json:"ip"`
	RTT      float64 `json:"rtt_ms"`
	ASN      string  `json:"asn,omitempty"`
	Location string  `json:"location,omitempty"`
	Network  string  `json:"network,omitempty"`
	Hostname string  `json:"hostname,omitempty"`
}

type RouteResult struct {
	Job   RouteJob   `json:"job"`
	IP    string     `json:"destination_ip,omitempty"`
	Hops  []RouteHop `json:"hops,omitempty"`
	Error string     `json:"error,omitempty"`
}
