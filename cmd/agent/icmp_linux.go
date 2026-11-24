package main

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func openPing(v6 bool) (net.PacketConn, error) {
	conn, err := openPingDatagram(v6)
	if err == nil || !(errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPROTONOSUPPORT)) {
		return conn, err
	}
	// Linux can deny ping datagrams even to root. The raw socket uses only
	// capabilities the process already has. The kernel rejects it otherwise.
	return openPingRaw(v6)
}

func openPingRaw(v6 bool) (net.PacketConn, error) {
	if v6 {
		return net.ListenIP("ip6:58", &net.IPAddr{IP: net.IPv6unspecified})
	}
	return net.ListenIP("ip4:1", &net.IPAddr{IP: net.IPv4zero})
}

func openPingDatagram(v6 bool) (net.PacketConn, error) {
	family, protocol := syscall.AF_INET, syscall.IPPROTO_ICMP
	var address syscall.Sockaddr = &syscall.SockaddrInet4{}
	if v6 {
		family, protocol = syscall.AF_INET6, syscall.IPPROTO_ICMPV6
		address = &syscall.SockaddrInet6{}
	}
	// SOCK_DGRAM is the kernel's unprivileged ping socket, distinct from a raw socket.
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, protocol)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "icmp-ping")
	defer file.Close()
	if err := syscall.Bind(fd, address); err != nil {
		return nil, err
	}
	return net.FilePacketConn(file)
}
