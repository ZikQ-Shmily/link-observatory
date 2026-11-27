package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestDueWindow(t *testing.T) {
	cases := []struct {
		name                    string
		seconds                 int
		scheduleStart, expiry   int64
		now, lastWindow, window int64
		due                     bool
	}{
		{name: "legacy minute", seconds: 60, expiry: 1200, now: 659, lastWindow: 540, window: 600, due: true},
		{name: "before transition", seconds: 300, scheduleStart: 900, expiry: 1500, now: 899, lastWindow: 660},
		{name: "transition boundary", seconds: 300, scheduleStart: 900, expiry: 1500, now: 900, lastWindow: 660, window: 900, due: true},
		{name: "already measured", seconds: 300, scheduleStart: 900, expiry: 1500, now: 1199, lastWindow: 900},
		{name: "next window", seconds: 300, scheduleStart: 900, expiry: 1500, now: 1201, lastWindow: 900, window: 1200, due: true},
		{name: "expired", seconds: 300, scheduleStart: 900, expiry: 1500, now: 1500, lastWindow: 1200},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			config := protocol.Config{IntervalSeconds: test.seconds, ScheduleStart: test.scheduleStart, ValidUntil: test.expiry}
			window, due := dueWindow(config, test.now, test.lastWindow)
			if due != test.due || due && window != test.window {
				t.Fatalf("dueWindow() = (%d, %t), want (%d, %t)", window, due, test.window, test.due)
			}
		})
	}
}

type scheduleTransport func(*http.Request) (*http.Response, error)

func (transport scheduleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func TestHeartbeatBeforeScheduleStarts(t *testing.T) {
	t.Chdir(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	const seconds = 600
	start := protocol.WindowStart(time.Now().Unix(), seconds) + seconds
	config := protocol.Config{IntervalSeconds: seconds, ScheduleStart: start, ValidUntil: start + seconds}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	gotHeartbeat := false
	client := newManagerClient(credentials{Manager: "https://manager.example.com", NodeID: "test-node", Credential: "test-credential"})
	client.http.Transport = scheduleTransport(func(req *http.Request) (*http.Response, error) {
		switch req.Method + " " + req.URL.Path {
		case "GET " + configPath:
			if req.Header.Get(protocol.ScheduleHeader) != "1" {
				t.Error("missing schedule capability header")
			}
			if req.Header.Get(protocol.HostnamesHeader) != "1" {
				t.Error("missing hostname capability header")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
		case "POST " + reportPath:
			var report protocol.Report
			if err := json.NewDecoder(req.Body).Decode(&report); err != nil || len(report.Results) != 0 || report.Metrics != nil {
				t.Errorf("expected an empty heartbeat report, got %+v (%v)", report, err)
			}
			gotHeartbeat = true
			cancel()
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})
	if err := runMonitor(ctx, client); err != nil || !gotHeartbeat {
		t.Fatalf("heartbeat received = %t, monitor error = %v", gotHeartbeat, err)
	}
}

func TestFlushReportsSendsMetricsWithLatestReport(t *testing.T) {
	t.Chdir(t.TempDir())
	client := newManagerClient(credentials{Manager: "https://manager.example.com"})
	sample := &protocol.HostMetrics{ObservedAt: time.Now().UTC(), CPUCores: 4}
	queue := []protocol.Report{
		{Results: []protocol.Result{{TargetID: "target", Window: 60}}},
		{Results: []protocol.Result{{TargetID: "target", Window: 120}}},
	}
	attempts := 0
	client.http.Transport = scheduleTransport(func(req *http.Request) (*http.Response, error) {
		attempts++
		var received protocol.Report
		if err := json.NewDecoder(req.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		if len(received.Results) != 1 {
			t.Fatalf("expected queued reachability result: %+v", received)
		}
		if attempts == 1 {
			if received.Results[0].Window != 120 || received.Metrics == nil || received.Metrics.CPUCores != sample.CPUCores ||
				!received.Metrics.ObservedAt.Equal(sample.ObservedAt) {
				t.Fatalf("expected current telemetry with newest report: %+v", received)
			}
		} else if received.Results[0].Window != 60 || received.Metrics != nil {
			t.Fatalf("expected old reachability report without telemetry: %+v", received)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})
	if err := flushReports(context.Background(), client, &queue, sample); err != nil || attempts != 2 || len(queue) != 0 {
		t.Fatalf("flushed = %d, queued = %d, error = %v", attempts, len(queue), err)
	}
}

func TestFlushReportsDoesNotReplayPersistedMetrics(t *testing.T) {
	t.Chdir(t.TempDir())
	client := newManagerClient(credentials{Manager: "https://manager.example.com"})
	queue := []protocol.Report{{Metrics: &protocol.HostMetrics{CPUCores: 32}}}
	gotReport := false
	client.http.Transport = scheduleTransport(func(req *http.Request) (*http.Response, error) {
		gotReport = true
		var received protocol.Report
		if err := json.NewDecoder(req.Body).Decode(&received); err != nil || received.Metrics != nil {
			t.Fatalf("cached telemetry must not be replayed: %+v (%v)", received, err)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})
	if err := flushReports(context.Background(), client, &queue, nil); err != nil || !gotReport || len(queue) != 0 {
		t.Fatalf("flushed = %t, queued = %d, error = %v", gotReport, len(queue), err)
	}
}
