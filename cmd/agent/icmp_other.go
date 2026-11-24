//go:build !linux

package main

import (
	"net"
	"syscall"
)

func openPing(bool) (net.PacketConn, error) {
	return nil, syscall.EPROTONOSUPPORT
}
