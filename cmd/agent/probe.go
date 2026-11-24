package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"link-observatory/internal/protocol"
)

const (
	attemptsPerProbe = 3
	attemptTimeout   = 2 * time.Second
	dnsLookupTimeout = 2 * time.Second
	parallelTargets  = 16
)

type attempt struct {
	status string
	sent   bool
	rtt    time.Duration
	detail string
}

func measure(ctx context.Context, config protocol.Config, window int64) protocol.Report {
	targets := append([]protocol.Target(nil), config.Targets...)
	if config.Control != nil {
		targets = append(targets, *config.Control)
	}
	lookups := make(map[string]func() (netip.Addr, string))
	for i := range targets {
		address, _ := protocol.NormalizeTargetAddress(targets[i].IP) // Validated with the manager config.
		targets[i].IP = address
		if _, literal := protocol.ParseTargetIP(address); !literal && lookups[address] == nil {
			lookups[address] = sync.OnceValues(func() (netip.Addr, string) {
				return resolveDomain(ctx, address, net.DefaultResolver.LookupNetIP)
			})
		}
	}
	report := newReport()
	report.Results = make([]protocol.Result, len(targets))
	workers := make(chan struct{}, parallelTargets)
	var group sync.WaitGroup
	for i, target := range targets {
		group.Go(func() {
			select {
			case workers <- struct{}{}:
				defer func() { <-workers }()
			case <-ctx.Done():
				return
			}
			report.Results[i] = measureTarget(ctx, target, window, lookups[target.IP])
		})
	}
	group.Wait()
	return report
}

func resolveDomain(ctx context.Context, hostname string, lookup func(context.Context, string, string) ([]netip.Addr, error)) (netip.Addr, string) {
	ctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	// Query the configured name as absolute so search suffixes cannot select a different target.
	answers, err := lookup(ctx, "ip", hostname+".")
	if err != nil {
		var dnsError net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &dnsError) && dnsError.Timeout()) {
			return netip.Addr{}, "DNS lookup timed out"
		}
		return netip.Addr{}, "DNS lookup failed"
	}
	var best netip.Addr
	for _, answer := range answers {
		// Compare orders IPv4 before IPv6 and then uses the numerical address.
		if ip, valid := protocol.ParseTargetIP(answer.String()); valid && (!best.IsValid() || ip.Compare(best) < 0) {
			best = ip
		}
	}
	if !best.IsValid() {
		return netip.Addr{}, "DNS lookup returned no usable address"
	}
	return best, ""
}

func measureTarget(ctx context.Context, target protocol.Target, window int64, resolve func() (netip.Addr, string)) protocol.Result {
	result := protocol.Result{TargetID: target.ID, Window: window}
	ip, _ := protocol.ParseTargetIP(target.IP)
	if resolve != nil {
		var detail string
		ip, detail = resolve()
		if detail != "" {
			result.TCP = protocol.Probe{Status: "error", Detail: detail}
			result.ICMP = result.TCP
			return result
		}
		result.ResolvedIP = ip.String()
	}
	tcp := make(chan protocol.Probe, 1)
	go func() { tcp <- probeTCP(ctx, ip, target.Port) }()
	result.ICMP = probeICMP(ctx, ip)
	result.TCP = <-tcp
	return result
}

func newReport() protocol.Report {
	return protocol.Report{
		Version: version,
		ICMPv4:  pingAvailable(false),
		ICMPv6:  pingAvailable(true),
		Results: []protocol.Result{},
	}
}

func pingAvailable(v6 bool) bool {
	conn, err := openPing(v6)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probeTCP(ctx context.Context, ip netip.Addr, port int) protocol.Probe {
	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	dialer := net.Dialer{Timeout: attemptTimeout, KeepAlive: -1}
	return summarize(ctx, func(_ int) attempt {
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			status, detail := failure(err)
			return attempt{status: status, sent: true, detail: detail}
		}
		rtt := time.Since(start)
		_ = conn.Close()
		return attempt{status: "ok", sent: true, rtt: rtt}
	})
}

func probeICMP(ctx context.Context, ip netip.Addr) protocol.Probe {
	conn, err := openPing(ip.Is6())
	if err != nil {
		status, detail := failure(err)
		return protocol.Probe{Status: status, Detail: detail}
	}
	defer conn.Close()
	return exchangeICMPEcho(ctx, conn, ip)
}

func exchangeICMPEcho(ctx context.Context, conn net.PacketConn, ip netip.Addr) protocol.Probe {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()

	v6 := ip.Is6()
	_, raw := conn.(*net.IPConn)
	destination := net.IP(ip.AsSlice())
	var address net.Addr = &net.UDPAddr{IP: destination}
	if raw {
		address = &net.IPAddr{IP: destination}
	}
	message := make([]byte, 8+16)
	message[0] = 8 // Echo Request, IPv4
	replyType := byte(0)
	if v6 {
		message[0], replyType = 128, 129 // Echo Request and Reply, IPv6
	}
	if _, err := rand.Read(message[4:]); err != nil {
		return protocol.Probe{Status: "error", Detail: "could not generate an echo payload"}
	}
	// IPConn.ReadFrom strips the raw IPv4 header. Its buffer must still fit
	// that header (up to 60 bytes) plus the ICMP message before stripping.
	response := make([]byte, 256)
	return summarize(ctx, func(seq int) attempt {
		binary.BigEndian.PutUint16(message[6:8], uint16(seq))
		if raw && !v6 {
			// Linux supplies the checksum for ICMP datagrams and raw ICMPv6.
			binary.BigEndian.PutUint16(message[2:4], 0)
			binary.BigEndian.PutUint16(message[2:4], icmpChecksum(message))
		}
		start := time.Now()
		if err := conn.SetDeadline(start.Add(attemptTimeout)); err != nil {
			status, detail := failure(err)
			return attempt{status: status, detail: detail}
		}
		if _, err := conn.WriteTo(message, address); err != nil {
			status, detail := failure(err)
			return attempt{status: status, detail: detail}
		}
		for {
			n, peer, err := conn.ReadFrom(response)
			if err != nil {
				status, detail := failure(err)
				return attempt{status: status, sent: true, detail: detail}
			}
			if n >= 8 && matchesICMPReply(response[:n], message, peer, destination, replyType, raw) {
				return attempt{status: "ok", sent: true, rtt: time.Since(start)}
			}
		}
	})
}

func matchesICMPReply(reply, request []byte, peer net.Addr, destination net.IP, replyType byte, raw bool) bool {
	var source net.IP
	switch address := peer.(type) {
	case *net.IPAddr:
		source = address.IP
	case *net.UDPAddr:
		source = address.IP
	}
	if !source.Equal(destination) || len(reply) < 8 || len(reply) != len(request) || reply[0] != replyType || reply[1] != 0 {
		return false
	}
	start := 6 // Linux replaces the identifier in datagram Echo Requests.
	if raw {
		start = 4
	}
	return bytes.Equal(reply[start:], request[start:])
}

func icmpChecksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[:2]))
		packet = packet[2:]
	}
	if len(packet) == 1 {
		sum += uint32(packet[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func summarize(ctx context.Context, probe func(int) attempt) protocol.Probe {
	result := protocol.Probe{Status: "error", Detail: "probe interrupted"}
	var rtt time.Duration
	for seq := 1; seq <= attemptsPerProbe && ctx.Err() == nil; seq++ {
		reading := probe(seq)
		if reading.sent {
			result.Sent++
		}
		if reading.status == "ok" {
			result.Received++
			rtt += reading.rtt
		}
		if seq == 1 || resultPriority(reading.status) > resultPriority(result.Status) {
			result.Status, result.Detail = reading.status, reading.detail
		}
		if reading.status == "unavailable" {
			break
		}
	}
	if result.Received > 0 {
		result.RTTMillis = float64(rtt) / float64(result.Received) / float64(time.Millisecond)
	}
	return result
}

func resultPriority(status string) int {
	// A positive or explicit response has stronger reachability evidence than silence.
	switch status {
	case "ok":
		return 6
	case "refused", "reset":
		return 5
	case "unreachable":
		return 4
	case "unavailable":
		return 3
	case "error":
		return 2
	default:
		return 1
	}
}

func failure(err error) (status, detail string) {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "unavailable", "local network permission denied"
	case errors.Is(err, syscall.EPROTONOSUPPORT), errors.Is(err, syscall.EAFNOSUPPORT):
		return "unavailable", "socket protocol is unavailable"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused", "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset", "connection reset"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EHOSTDOWN):
		return "unreachable", "network or host unreachable"
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout", "response timed out"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "timeout", "response timed out"
		}
		return "error", "local probe error"
	}
}
