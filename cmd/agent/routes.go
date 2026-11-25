package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"link-observatory/internal/protocol"
)

const routeProgramFile = "route-program"

var routeJSONStart = regexp.MustCompile(`\{\s*"Hops"\s*:`)

func nextTraceProgram() string {
	if data, err := os.ReadFile(routeProgramFile); err == nil && len(data) <= 4096 {
		path := strings.TrimSpace(string(data))
		if filepath.IsAbs(path) {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				return path
			}
		}
	}
	return ""
}

func egressIP(ctx context.Context, family int) string {
	endpoint, network := "https://api.ipify.org", "tcp4"
	if family == 6 {
		endpoint, network = "https://api6.ipify.org", "tcp6"
	}
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	response, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 100))
	if err == nil {
		if ip, valid := protocol.PublicIP(strings.TrimSpace(string(data)), family); valid {
			return ip.String()
		}
	}
	return ""
}

func runRoutes(parent context.Context, state credentials) {
	ctx, cancel := context.WithCancel(parent)
	var worker sync.WaitGroup
	defer func() {
		cancel()
		worker.Wait()
	}()
	client := newManagerClient(state)
	defer client.http.CloseIdleConnections()
	var lastSample time.Time
	var jobsDone <-chan struct{}
	ticker := time.NewTicker(configPollInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case <-jobsDone:
			jobsDone = nil
		default:
		}
		program := nextTraceProgram()
		poll := protocol.RoutePoll{Ready: program != "", Busy: jobsDone != nil}
		if time.Since(lastSample) >= heartbeatInterval {
			poll.Sampled = true
			var sample sync.WaitGroup
			sample.Go(func() { poll.IPv4 = egressIP(ctx, 4) })
			sample.Go(func() { poll.IPv6 = egressIP(ctx, 6) })
			sample.Wait()
		}
		var jobs []protocol.RouteJob
		err := client.request(ctx, http.MethodPost, protocol.RoutePollPath, poll, &jobs, true)
		if authFailure(err) {
			return
		}
		if err == nil {
			if poll.Sampled {
				lastSample = time.Now()
			}
			if program != "" && jobsDone == nil && len(jobs) > 0 && len(jobs) <= 4 {
				done := make(chan struct{})
				jobsDone = done
				worker.Go(func() {
					defer close(done)
					runRouteJobs(ctx, client, program, jobs)
				})
			}
		} else {
			var status responseError
			if errors.As(err, &status) && status == http.StatusNotFound {
				// A new probe can still monitor through an older manager.
				lastSample = time.Now()
			} else if ctx.Err() == nil {
				log.Printf("poll routes: %v", err)
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func runRouteJobs(ctx context.Context, client managerClient, program string, jobs []protocol.RouteJob) {
	var workers sync.WaitGroup
	for _, job := range jobs {
		workers.Go(func() {
			result := traceRoute(ctx, program, job)
			if ctx.Err() != nil {
				return
			}
			err := client.request(ctx, http.MethodPost, protocol.RouteResultPath, result, nil, true)
			var status responseError
			if err != nil && (!errors.As(err, &status) || status != http.StatusConflict) {
				log.Printf("send route result: %v", err)
			}
		})
	}
	workers.Wait()
}

func routeDestination(ctx context.Context, job protocol.RouteJob) (netip.Addr, error) {
	if job.Family != 4 && job.Family != 6 {
		return netip.Addr{}, errors.New("unsupported route address family")
	}
	if job.Direction == protocol.RouteBack {
		if ip, valid := protocol.PublicIP(job.Address, job.Family); valid {
			return ip, nil
		}
		return netip.Addr{}, errors.New("no public probe egress for this family")
	}
	if job.Direction != protocol.RouteOut {
		return netip.Addr{}, errors.New("unsupported route direction")
	}
	if ip, valid := protocol.ParseTargetIP(job.Address); valid {
		if ip.Is4() == (job.Family == 4) {
			return ip, nil
		}
		return netip.Addr{}, errors.New("target has a different address family")
	}
	if _, valid := protocol.NormalizeTargetAddress(job.Address); !valid {
		return netip.Addr{}, errors.New("invalid route target")
	}
	network := "ip4"
	if job.Family == 6 {
		network = "ip6"
	}
	lookup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookup, network, job.Address+".")
	if err == nil {
		for _, address := range addresses {
			if ip, valid := protocol.ParseTargetIP(address.String()); valid && ip.Is4() == (job.Family == 4) {
				return ip, nil
			}
		}
	}
	return netip.Addr{}, errors.New("target has no resolved address for this family")
}

type routeOutput struct {
	bytes.Buffer
}

func (output *routeOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > 2<<20 {
		return 0, errors.New("NextTrace output exceeds size limit")
	}
	return output.Buffer.Write(data)
}

func traceRoute(ctx context.Context, program string, job protocol.RouteJob) protocol.RouteResult {
	result := protocol.RouteResult{Job: job}
	ip, err := routeDestination(ctx, job)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.IP = ip.String()
	run := func(disableGeo bool) ([]protocol.RouteHop, error) {
		traceContext, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		family := "-4"
		if job.Family == 6 {
			family = "-6"
		}
		args := []string{family, "-j", "-M", "-C", "-a", "-m", "30", "-q", "3"}
		if disableGeo {
			args = append(args, "-d", "disable-geoip")
		}
		command := exec.CommandContext(traceContext, program, append(args, result.IP)...)
		var output routeOutput
		command.Stdout = &output
		if err := command.Run(); err != nil {
			return nil, err
		}
		return parseNextTrace(output.Bytes(), job.Family)
	}
	hops, err := run(false)
	if err != nil && ctx.Err() == nil {
		hops, err = run(true)
	}
	if err != nil {
		result.Error = "NextTrace failed to return route JSON"
	} else {
		result.Hops = hops
	}
	return result
}

func parseNextTrace(data []byte, family int) ([]protocol.RouteHop, error) {
	var output struct {
		Hops [][]struct {
			Success  bool
			Address  struct{ IP string }
			TTL      int
			RTT      int64
			Hostname string
			Geo      struct {
				Country, Prov, City, Whois, ISP string
				ASNumber                        string `json:"asnumber"`
			}
		}
	}
	start := routeJSONStart.FindIndex(data)
	if start == nil {
		return nil, errors.New("missing NextTrace Hops")
	}
	if err := json.NewDecoder(bytes.NewReader(data[start[0]:])).Decode(&output); err != nil {
		return nil, fmt.Errorf("read NextTrace JSON: %w", err)
	}
	if output.Hops == nil || len(output.Hops) > protocol.MaxRouteHops {
		return nil, errors.New("invalid NextTrace hops")
	}
	var hops []protocol.RouteHop
	for index, replies := range output.Hops {
		seen := make(map[string]bool)
		for _, reply := range replies {
			ip, ok := protocol.ParseTargetIP(reply.Address.IP)
			if !reply.Success || !ok || ip.Is4() != (family == 4) || seen[ip.String()] || len(seen) == 3 ||
				reply.RTT < 0 || reply.RTT > int64(90*time.Second) {
				continue
			}
			seen[ip.String()] = true
			geo := reply.Geo
			var location []string
			for _, value := range []string{geo.Country, geo.Prov, geo.City} {
				value = routeText(value, 48)
				if value != "" && !slices.Contains(location, value) {
					location = append(location, value)
				}
			}
			network := routeText(geo.Whois, 96)
			if network == "" {
				network = routeText(geo.ISP, 96)
			}
			asn := strings.TrimPrefix(strings.ToUpper(geo.ASNumber), "AS")
			if asn == "" || len(asn) > 10 || strings.IndexFunc(asn, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				asn = ""
			} else {
				asn = "AS" + asn
			}
			hops = append(hops, protocol.RouteHop{TTL: index + 1, IP: ip.String(), RTT: float64(reply.RTT) / float64(time.Millisecond),
				ASN: asn, Location: strings.Join(location, " · "), Network: network, Hostname: routeText(reply.Hostname, 160)})
		}
	}
	return hops, nil
}

func routeText(value string, maxBytes int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value))
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
