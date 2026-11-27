//go:build !linux

package main

import (
	"context"
	"sync/atomic"

	"link-observatory/internal/protocol"
)

func watchHostMetrics(context.Context) *atomic.Pointer[protocol.HostMetrics] {
	return new(atomic.Pointer[protocol.HostMetrics])
}
