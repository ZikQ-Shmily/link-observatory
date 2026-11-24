package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestResolveDomain(t *testing.T) {
	cases := []struct {
		name    string
		answers []string
		want    string
	}{
		{name: "prefers lowest IPv4", answers: []string{"2001:db8::1", "192.0.2.100", "::ffff:192.0.2.11"}, want: "192.0.2.11"},
		{name: "ignores unusable addresses", answers: []string{"0.0.0.0", "224.0.0.1", "2001:db8::8", "2001:db8::3"}, want: "2001:db8::3"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ip, detail := resolveDomain(context.Background(), "example.test", func(ctx context.Context, network, name string) ([]netip.Addr, error) {
				deadline, ok := ctx.Deadline()
				if network != "ip" || name != "example.test." || !ok || time.Until(deadline) > dnsLookupTimeout {
					t.Fatalf("unexpected DNS lookup (%q, %q), deadline %v", network, name, deadline)
				}
				answers := make([]netip.Addr, len(test.answers))
				for i, answer := range test.answers {
					answers[i] = netip.MustParseAddr(answer)
				}
				return answers, nil
			})
			if ip.String() != test.want || detail != "" {
				t.Fatalf("got %v (%s), want %s", ip, detail, test.want)
			}
		})
	}
}

func TestDNSFailureSkipsConnectivityProbes(t *testing.T) {
	ctx := context.Background()
	target := protocol.Target{ID: "test-domain", IP: "unresolvable.test", Port: 443}
	const window = 600
	result := measureTarget(ctx, target, window, func() (netip.Addr, string) {
		return resolveDomain(ctx, target.IP, func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, &net.DNSError{IsTimeout: true}
		})
	})
	want := protocol.Probe{Status: "error", Detail: "DNS lookup timed out"}
	if result.TargetID != target.ID || result.Window != window || result.ResolvedIP != "" || result.TCP != want || result.ICMP != want {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestICMPChecksum(t *testing.T) {
	// RFC 1071 example and a complete Echo Request using the calculated checksum.
	if got := icmpChecksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); got != 0x220d {
		t.Fatalf("checksum = %04x, want 220d", got)
	}
	request := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 0xab}
	binary.BigEndian.PutUint16(request[2:4], icmpChecksum(request))
	if got := icmpChecksum(request); got != 0 {
		t.Fatalf("checksummed packet produced %04x, want 0", got)
	}
}

func TestMatchesICMPReply(t *testing.T) {
	request := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p'}
	reply := append([]byte(nil), request...)
	reply[0] = 0
	ip := net.IPv4(127, 0, 0, 1)
	source := &net.IPAddr{IP: ip}
	if !matchesICMPReply(reply, request, source, ip, 0, true) {
		t.Fatal("rejected matching raw reply")
	}
	if matchesICMPReply(request, request, source, ip, 0, true) ||
		matchesICMPReply(reply[:len(reply)-1], request, source, ip, 0, true) ||
		matchesICMPReply(reply, request, source, net.IPv4(127, 0, 0, 2), 0, true) {
		t.Fatal("accepted nonreply, truncated packet, or wrong source")
	}
	reply[4]++
	if matchesICMPReply(reply, request, source, ip, 0, true) {
		t.Fatal("accepted raw reply with the wrong identifier")
	}
	if !matchesICMPReply(reply, request, &net.UDPAddr{IP: ip}, ip, 0, false) {
		t.Fatal("rejected datagram reply with a kernel-assigned identifier")
	}
	reply[6]++
	if matchesICMPReply(reply, request, &net.UDPAddr{IP: ip}, ip, 0, false) {
		t.Fatal("accepted datagram reply with the wrong sequence")
	}
}
