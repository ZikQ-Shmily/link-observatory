package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestLinuxPingModes(t *testing.T) {
	mode := os.Getenv("LINK_TEST_ICMP_MODE")
	switch mode {
	case "":
		t.Skip("requires a Linux network namespace with explicitly configured ping permissions")
	case "dgram", "raw", "denied":
	default:
		t.Fatalf("unknown LINK_TEST_ICMP_MODE %q", mode)
	}
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(mode+"/"+address, func(t *testing.T) {
			ip := netip.MustParseAddr(address)
			conn, err := openPing(ip.Is6())
			if mode == "denied" {
				if err == nil {
					conn.Close()
				}
				if !errors.Is(err, os.ErrPermission) {
					t.Fatalf("socket error = %v, want a permission error", err)
				}
				result := probeICMP(context.Background(), ip)
				if result.Status != "unavailable" || result.Sent != 0 {
					t.Fatalf("unexpected permission-denied result: %+v", result)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_, datagram := conn.(*net.UDPConn)
			_, raw := conn.(*net.IPConn)
			if mode == "dgram" && !datagram || mode == "raw" && !raw {
				t.Fatalf("selected socket type %T, want %s", conn, mode)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if result := exchangeICMPEcho(ctx, conn, ip); result.Status != "ok" || result.Received != attemptsPerProbe {
				t.Fatalf("unexpected loopback result: %+v", result)
			}
		})
	}
}
