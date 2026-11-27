package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"link-observatory/internal/protocol"
)

const (
	configPollInterval = 20 * time.Second
	heartbeatInterval  = time.Minute
	maxTargets         = 100
	maxQueuedReports   = 24
	queueFile          = "reports.json"
	configPath         = "/api/agent/config"
	reportPath         = "/api/agent/report"
)

type managerClient struct {
	state credentials
	http  *http.Client
}

type responseError int

func (status responseError) Error() string {
	return fmt.Sprintf("manager returned HTTP %d", status)
}

func validateManagerURL(raw string) (string, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Hostname() == "" || base.User != nil ||
		base.RawQuery != "" || base.ForceQuery || strings.Contains(raw, "#") ||
		(base.Path != "" && base.Path != "/") {
		return "", errors.New("manager URL must be an origin without credentials, path, query, or fragment")
	}
	if base.Scheme != "https" {
		host := base.Hostname()
		ip, _ := netip.ParseAddr(host)
		if base.Scheme != "http" || (!strings.EqualFold(host, "localhost") && !ip.IsLoopback()) {
			return "", errors.New("manager URL must use HTTPS, or HTTP on loopback for local testing")
		}
	}
	return strings.TrimRight(base.String(), "/"), nil
}

func newManagerClient(state credentials) managerClient {
	return managerClient{
		state: state,
		http: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (client managerClient) request(ctx context.Context, method, path string, body, output any, authenticate bool) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.state.Manager+path, payload)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticate {
		request.Header.Set("Authorization", "Bearer "+client.state.Credential)
		request.Header.Set("X-Node-ID", client.state.NodeID)
	}
	if path == configPath {
		request.Header.Set(protocol.ScheduleHeader, "1")
		request.Header.Set(protocol.HostnamesHeader, "1")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response.StatusCode)
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil
	}
	const maxResponse = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return errors.New("manager response exceeds size limit")
	}
	return json.Unmarshal(data, output)
}

func configValid(config protocol.Config) error {
	if !protocol.ValidIntervalSeconds(config.IntervalSeconds) || config.ValidUntil <= time.Now().Unix() {
		return errors.New("manager config is expired or specifies an unsupported interval")
	}
	if len(config.Targets) > maxTargets {
		return fmt.Errorf("manager config exceeds %d monitored targets", maxTargets)
	}
	ids := make(map[string]bool, len(config.Targets)+1)
	targets := append([]protocol.Target(nil), config.Targets...)
	if config.Control != nil {
		targets = append(targets, *config.Control)
	}
	for _, target := range targets {
		if _, valid := protocol.NormalizeTargetAddress(target.IP); !valid || !nodeIDRE.MatchString(target.ID) ||
			ids[target.ID] || target.Port < 1 || target.Port > 65535 {
			return errors.New("manager config contains an invalid or duplicate target")
		}
		ids[target.ID] = true
	}
	return nil
}

func authFailure(err error) bool {
	var status responseError
	return errors.As(err, &status) && (status == http.StatusUnauthorized || status == http.StatusForbidden)
}

func dueWindow(config protocol.Config, now, lastWindow int64) (int64, bool) {
	if now >= config.ValidUntil {
		return 0, false
	}
	window := protocol.WindowStart(now, config.IntervalSeconds)
	return window, window >= config.ScheduleStart && window > lastWindow
}

func runMonitor(ctx context.Context, client managerClient) error {
	defer client.http.CloseIdleConnections()
	var reports []protocol.Report
	if err := readPrivateJSON(queueFile, &reports); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("read cached reports: %v", err)
	}
	var config protocol.Config
	var lastWindow int64
	var lastReportAt time.Time
	var hostMetrics *atomic.Pointer[protocol.HostMetrics]
	for ctx.Err() == nil {
		var next protocol.Config
		err := client.request(ctx, http.MethodGet, configPath, nil, &next, true)
		if err == nil {
			err = configValid(next)
			if err == nil {
				config = next
				if config.HostMetrics && hostMetrics == nil {
					hostMetrics = watchHostMetrics(ctx)
				}
			}
		}
		if ctx.Err() != nil {
			break
		}
		if authFailure(err) {
			return fmt.Errorf("probe credentials rejected: %w", err)
		}
		if err != nil {
			log.Printf("refresh configuration: %v", err)
		}
		if window, due := dueWindow(config, time.Now().Unix(), lastWindow); due {
			lastWindow = window
			probeContext, cancel := context.WithDeadline(ctx, time.Unix(config.ValidUntil, 0))
			report := measure(probeContext, config, window)
			if probeContext.Err() == nil {
				reports = append(reports, report)
				if len(reports) > maxQueuedReports {
					reports = append([]protocol.Report(nil), reports[len(reports)-maxQueuedReports:]...)
				}
				storeQueue(reports)
			}
			cancel()
		}
		if ctx.Err() == nil && (len(reports) > 0 || time.Since(lastReportAt) >= heartbeatInterval) {
			var metrics *protocol.HostMetrics
			if config.HostMetrics && hostMetrics != nil && time.Now().Unix() < config.ValidUntil {
				metrics = hostMetrics.Load()
			}
			var err error
			if len(reports) > 0 {
				err = flushReports(ctx, client, &reports, metrics)
			} else {
				report := newReport()
				report.Metrics = metrics
				err = client.request(ctx, http.MethodPost, reportPath, report, nil, true)
			}
			if authFailure(err) {
				return fmt.Errorf("probe credentials rejected: %w", err)
			}
			if err == nil {
				lastReportAt = time.Now()
			} else if ctx.Err() == nil {
				log.Printf("send reports: %v", err)
			}
		}
		// Poll on seconds that divide every supported probe interval, even if an
		// earlier request or probe took longer than one poll.
		nextPoll := time.Now().Truncate(configPollInterval).Add(configPollInterval)
		timer := time.NewTimer(time.Until(nextPoll))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}

func storeQueue(reports []protocol.Report) {
	if err := writePrivateJSON(queueFile, reports); err != nil {
		log.Printf("save cached reports: %v", err)
	}
}

func flushReports(parent context.Context, client managerClient, reports *[]protocol.Report, metrics *protocol.HostMetrics) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	queue := *reports
	defer func() {
		if len(queue) != len(*reports) {
			*reports = queue
			storeQueue(queue)
		}
	}()
	for attempt := range 5 {
		if len(queue) == 0 {
			return nil
		}
		// The current result should remain visible even when historical delivery is delayed.
		index := 0
		if attempt == 0 {
			index = len(queue) - 1
		}
		report := queue[index]
		report.Version = version
		// Metrics describe the current host, not the potentially older probe round.
		report.Metrics = metrics
		if err := client.request(ctx, http.MethodPost, reportPath, report, nil, true); err != nil {
			var status responseError
			if !errors.As(err, &status) || status != http.StatusBadRequest && status != http.StatusUnprocessableEntity && status != http.StatusRequestEntityTooLarge {
				return err
			}
			log.Printf("discard rejected report: %v", err)
		} else {
			metrics = nil
		}
		queue = append(queue[:index], queue[index+1:]...)
	}
	return nil
}
