package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestRouteChangeQueuesOneMailForTwoMatchingRounds(t *testing.T) {
	const target, probe, endpoint = "target-a", "probe-a", "8.8.8.8"
	state := diskState{
		Mail:  mailSettings{Enabled: true, Events: []mailKind{mailRouteChange}},
		Nodes: map[string]nodeRecord{probe: {ID: probe, Name: "盐城", ISP: "China Telecom"}},
		Targets: map[string]targetRecord{target: {
			Target: protocol.Target{ID: target, Name: "香港", IP: endpoint},
			Route:  routeSettings{Enabled: true, Minutes: 15},
		}},
	}
	job := protocol.RouteJob{TargetID: target, ProbeID: probe, Family: 4, Direction: protocol.RouteOut, Generation: target}
	record := func(window int64, ip string) bool {
		job.Window = window * 900
		hops := []protocol.RouteHop{{TTL: 2, IP: endpoint}}
		if ip != "" {
			hops = append(hops, protocol.RouteHop{TTL: 1, IP: ip, ASN: "AS4134"})
		}
		return state.addRoute(protocol.RouteResult{Job: job, IP: endpoint, Hops: hops}, job.Window)
	}
	record(1, "1.1.1.1")
	record(2, "1.0.0.1")
	record(3, "")
	record(4, "1.0.0.1")
	if len(state.MailQueue) != 0 || len(state.RouteChanges) != 0 {
		t.Fatal("unconfirmed candidate triggered an alert")
	}
	record(5, "1.0.0.1")
	if record(5, "1.0.0.1") {
		t.Fatal("duplicate route result was accepted")
	}
	record(6, "1.0.0.1")
	if len(state.MailQueue) != 1 || len(state.RouteChanges) != 1 {
		t.Fatalf("want one change and one email, got %d changes and %d emails", len(state.RouteChanges), len(state.MailQueue))
	}
	s := newPasswordTestServer(t)
	s.state = state
	var sends int
	s.deliverNextMail(context.Background(), func(_ context.Context, _ mailSettings, notice mailNotice, _, url string) error {
		sends++
		content := notificationContent(notice, url)
		if !strings.Contains(content.Subject, "去程路由变化") || content.Endpoint != endpoint ||
			len(content.Facts) < 5 || content.Facts[0].Value != "盐城" ||
			!strings.Contains(content.Facts[4].Value, "1.1.1.1 (AS4134) → 1.0.0.1 (AS4134)") {
			t.Fatalf("unexpected route mail: %+v", content)
		}
		return nil
	})
	if sends != 1 || len(s.state.MailQueue) != 0 {
		t.Fatal("confirmed notification did not leave queue")
	}

	job.SourceIP = "9.9.9.9"
	record(7, "1.1.1.1")
	record(8, "1.1.1.1")
	if len(state.RouteChanges) != 1 {
		t.Fatal("a new source IP must establish its own baseline")
	}
}

func TestReturnRunnerOnlyReceivesItsTargetAndPublicEgress(t *testing.T) {
	s := newPasswordTestServer(t)
	const probe, target, runner = "probe-a", "target-a", "return-a"
	const credential = "test-credential-with-at-least-32-bytes"
	now := time.Now().Unix()
	s.state.Nodes[probe] = nodeRecord{ID: probe}
	s.state.Targets[target] = targetRecord{
		Target: protocol.Target{ID: target, IP: "example.com", Port: 443},
		Route:  routeSettings{Enabled: true, Minutes: 15}, ReturnRunner: runner,
	}
	s.state.Targets["target-b"] = targetRecord{
		Target: protocol.Target{ID: "target-b", IP: "other.example.com", Port: 443},
		Route:  routeSettings{Enabled: true, Minutes: 15},
	}
	s.state.RouteRunners = map[string]nodeRecord{
		runner: {ID: runner, ReturnTarget: target, Credential: digest(credential)},
	}
	s.state.Nodes["other"] = nodeRecord{ID: "other", Credential: digest(credential)}
	handler := s.routes()
	request := func(method, path, id string, input any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Node-ID", id)
		req.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	w := request(http.MethodGet, "/api/agent/config", runner, nil)
	passwordStatus(t, w, 200)
	var config protocol.Config
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil || len(config.Targets) != 0 {
		t.Fatalf("return runner received regular targets: %s", w.Body)
	}
	view := s.state.Nodes[probe]
	s.state.setEgress(&view, "100.64.1.2", 4, now)
	s.state.setEgress(&view, "8.8.4.4", 4, now)
	s.state.setEgress(&view, "fd00::a", 6, now)
	s.state.Nodes[probe] = view
	w = request(http.MethodPost, protocol.RoutePollPath, runner, protocol.RoutePoll{Ready: true})
	passwordStatus(t, w, 200)
	var jobs []protocol.RouteJob
	if err := json.Unmarshal(w.Body.Bytes(), &jobs); err != nil || len(jobs) != 1 ||
		jobs[0].TargetID != target || jobs[0].Direction != protocol.RouteBack || jobs[0].Address != "8.8.4.4" {
		t.Fatalf("unexpected return route assignments: %s", w.Body)
	}
	result := protocol.RouteResult{Job: jobs[0], IP: jobs[0].Address, Hops: []protocol.RouteHop{{TTL: 3, IP: jobs[0].Address}}}
	passwordStatus(t, request(http.MethodPost, protocol.RouteResultPath, "other", result), http.StatusConflict)
	passwordStatus(t, request(http.MethodPost, protocol.RouteResultPath, runner, result), http.StatusNoContent)

	s.state.setEgress(&view, "1.1.1.1", 4, now)
	s.state.Nodes[probe] = view
	passwordStatus(t, request(http.MethodPost, protocol.RouteResultPath, runner, result), http.StatusConflict)
	if len(s.state.EgressChanges) != 1 {
		t.Fatal("probe egress change was not recorded")
	}

	reloaded, err := loadState(s.filename, time.Now())
	if err != nil || len(reloaded.Routes) != 1 {
		t.Fatalf("route result was not persisted: %v", err)
	}
}
