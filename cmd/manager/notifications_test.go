package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"link-observatory/internal/protocol"
)

func TestTargetMailSeparatesProtocolsAcrossRestart(t *testing.T) {
	const start, step = 1800000000, protocol.DefaultIntervalSeconds
	target := targetRecord{Target: protocol.Target{ID: "t", Name: "Tokyo", IP: "probe.example.com", Port: 443}}
	s := &server{
		filename: filepath.Join(t.TempDir(), "state.json"),
		state:    assessmentRound(target, start),
	}
	s.state.LastEvaluated = start - step
	s.state.ProbeIntervalSeconds = step
	s.state.Mail = mailSettings{Enabled: true, Events: mailKinds}
	ok := protocol.Probe{Status: "ok", Sent: 1, Received: 1}
	timeout := protocol.Probe{Status: "timeout", Sent: 1}
	unavailable := protocol.Probe{Status: "unavailable"}
	round := func(i int64, tcp, icmp protocol.Probe, edit func(diskState)) {
		t.Helper()
		window := start + i*step
		sample := assessmentRound(target, window)
		for _, id := range []string{"east", "west"} {
			sample.Samples[id]["t"].Results[0].TCP = tcp
			sample.Samples[id]["t"].Results[0].ICMP = icmp
		}
		if edit != nil {
			edit(sample)
		}
		s.state.Samples = sample.Samples
		s.evaluateClosedWindows(time.Unix(window+step, 0))
	}
	check := func(kinds ...mailKind) {
		t.Helper()
		var actual []mailKind
		for _, job := range s.state.MailQueue {
			actual = append(actual, job.Notice.Kind)
		}
		if !slices.Equal(actual, kinds) {
			t.Fatalf("mail events = %v, want %v", actual, kinds)
		}
	}

	round(0, timeout, timeout, nil)
	round(1, timeout, unavailable, nil)
	round(2, timeout, timeout, nil)
	check(mailTCPFailure)
	round(3, timeout, timeout, nil)
	round(4, timeout, timeout, func(state diskState) {
		state.Samples["sg"]["t"].Results[0].ResolvedIP = "192.0.2.2"
	})
	round(5, timeout, timeout, nil)
	round(6, timeout, timeout, nil)
	check(mailTCPFailure)
	round(7, timeout, timeout, nil)
	check(mailTCPFailure, mailICMPFailure)

	saved, err := loadState(s.filename, time.Unix(start+8*step, 0))
	if err != nil {
		t.Fatal(err)
	}
	s = &server{filename: s.filename, state: saved}
	round(8, timeout, ok, nil)
	round(9, timeout, ok, func(state diskState) {
		delete(state.Samples, "west")
	})
	round(10, timeout, ok, nil)
	check(mailTCPFailure, mailICMPFailure)
	round(11, timeout, ok, nil)
	check(mailTCPFailure, mailICMPFailure, mailICMPRecovery)
	got := s.state.MailQueue[2].Notice
	if got.Address != target.IP || got.IP != assessmentIP || got.Mainland.Reachable != 2 ||
		got.Previous.Valid != 2 || !slices.Equal(got.ISPs, []string{"East", "West"}) {
		t.Fatalf("unexpected ICMP recovery details: %+v", got)
	}
	round(12, ok, unavailable, nil)
	round(13, ok, unavailable, nil)
	check(mailTCPFailure, mailICMPFailure, mailICMPRecovery, mailTCPRecovery)
	if got := s.state.MailQueue[3].Notice.Address; got != "probe.example.com:443" {
		t.Fatalf("TCP endpoint = %s", got)
	}
}

func TestLegacyTCPIncidentNotifiesOnlyOnRecovery(t *testing.T) {
	const start, step = 1800000000, protocol.DefaultIntervalSeconds
	target := targetRecord{Target: protocol.Target{ID: "t", IP: assessmentIP, Port: 443}}
	state := assessmentRound(target, start)
	state.Events = []eventRecord{{TargetID: "t", State: "active", Verdict: verdictSuspectedPort,
		AffectedISPs: []string{"east", "west"}, StartedAt: time.Unix(start-5*step, 0)}}
	state.recordTargetNotifications(&target, assess(state, "t", start), start, step)
	if target.TCPAlert.Active == nil || len(state.MailQueue) != 0 {
		t.Fatal("active event was not loaded as the silent baseline")
	}
	state.Mail = mailSettings{Enabled: true, Events: []mailKind{mailTCPRecovery}}
	for i := int64(1); i <= 2; i++ {
		window := start + i*step
		round := assessmentRound(target, window)
		for _, samples := range round.Samples {
			samples["t"].Results[0].TCP = protocol.Probe{Status: "ok", Sent: 1, Received: 1}
		}
		state.recordTargetNotifications(&target, assess(round, "t", window), window, step)
	}
	if len(state.MailQueue) != 1 || state.MailQueue[0].Notice.Kind != mailTCPRecovery {
		t.Fatalf("expected one recovery, got %+v", state.MailQueue)
	}
}

func TestProbeMailSendsOncePerHeartbeatTransition(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := &server{
		filename: filepath.Join(t.TempDir(), "state.json"),
		state: diskState{
			Mail: mailSettings{Enabled: true, Events: mailKinds},
			Nodes: map[string]nodeRecord{
				"probe":   {ID: "probe", LastSeen: now.Unix() - 181, Credential: digest("credential")},
				"pending": {ID: "pending"},
			},
			Samples: make(map[string]map[string]sampleSeries), ProbeIntervalSeconds: 60,
		},
	}
	s.evaluateProbeAvailability(now.Add(-2 * time.Second))
	if len(s.state.MailQueue) != 0 || s.state.Nodes["probe"].MailOfflineSince != 0 {
		t.Fatal("probe was marked offline before missing heartbeats for three minutes")
	}
	s.evaluateProbeAvailability(now)
	s.evaluateProbeAvailability(now)
	for range 2 {
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, scheduleRequest(t, http.MethodPost, "/api/agent/report", protocol.Report{}))
		if w.Code != http.StatusNoContent {
			t.Fatalf("heartbeat status = %d: %s", w.Code, w.Body)
		}
	}
	if len(s.state.MailQueue) != 2 || s.state.MailQueue[0].Notice.Kind != mailProbeOffline ||
		s.state.MailQueue[1].Notice.Kind != mailProbeRecovery || s.state.Nodes["probe"].MailOfflineSince != 0 {
		t.Fatalf("expected a single offline/recovery pair, got %+v", s.state.MailQueue)
	}
}

func TestProbeRecoveryMailIncludesFullHeartbeatGap(t *testing.T) {
	lastHeartbeat := time.Date(2026, 11, 26, 1, 39, 29, 0, beijing)
	recovered := lastHeartbeat.Add(3*time.Minute + 33*time.Second)
	// A queued recovery notice stores the threshold time and the new heartbeat.
	notice := mailNotice{Kind: mailProbeRecovery, StartedAt: lastHeartbeat.Add(offlineAfter), At: recovered, LastSeen: recovered}
	content := notificationContent(notice, "https://monitor.example.com")
	want := []mailFact{{"最后心跳", "2026-11-26 01:39:29"}, {"恢复时间", "2026-11-26 01:43:02"}, {"离线时长", "3 分钟 33 秒"}}
	if got := content.Facts[3:]; !slices.Equal(got, want) {
		t.Fatalf("recovery mail facts = %v, want %v", got, want)
	}
}

func TestMailSettingsNeverReturnPassword(t *testing.T) {
	now := time.Now()
	s := &server{
		filename: filepath.Join(t.TempDir(), "state.json"),
		sessions: map[string]time.Time{"admin": now.Add(time.Hour)},
	}
	cfg := mailSettings{Enabled: true, Host: "smtp.example.com", Port: 465, Security: "tls",
		Username: "monitor@example.com", Password: "smtp-not-for-browser", From: "monitor@example.com",
		Recipients: []string{"ops@example.com"}, Events: []mailKind{mailTCPFailure}}
	adminTestRequest(t, s, http.MethodPut, "/api/admin/mail", cfg, http.StatusNoContent)
	s.state.enqueueMail(mailNotice{Kind: mailTCPFailure, At: now})
	body := adminTestRequest(t, s, http.MethodGet, "/api/admin/mail", nil, http.StatusOK).Body.String()
	if strings.Contains(body, cfg.Password) || !strings.Contains(body, `"has_password":true`) {
		t.Fatalf("password was exposed or indicator missing: %s", body)
	}
	cfg.Password = ""
	cfg.Events = []mailKind{mailICMPRecovery}
	adminTestRequest(t, s, http.MethodPut, "/api/admin/mail", cfg, http.StatusNoContent)
	if s.state.Mail.Password != "smtp-not-for-browser" || len(s.state.MailQueue) != 0 {
		t.Fatal("saving switches did not retain the credential and cancel disabled notices")
	}
	cfg.Host = "other.example.com"
	adminTestRequest(t, s, http.MethodPut, "/api/admin/mail", cfg, http.StatusBadRequest)
	adminTestRequest(t, s, http.MethodPost, "/api/admin/mail/test", cfg, http.StatusBadRequest)
}

func TestFailedMailRetriesWithoutRepeatingAcceptedJobs(t *testing.T) {
	s := &server{filename: filepath.Join(t.TempDir(), "state.json")}
	s.state.Mail = mailSettings{Enabled: true, Events: mailKinds}
	s.state.enqueueMail(mailNotice{Kind: mailTCPFailure})
	s.state.enqueueMail(mailNotice{Kind: mailTCPRecovery})
	s.state.enqueueMail(mailNotice{Kind: mailICMPRecovery})
	var delivered []string
	send := func(_ context.Context, _ mailSettings, notice mailNotice, id, _ string) error {
		delivered = append(delivered, id)
		if notice.Kind == mailTCPFailure && len(delivered) == 1 {
			return errors.New("temporarily rejected")
		}
		return nil
	}
	ctx := context.Background()
	if !s.deliverNextMail(ctx, send) || !s.deliverNextMail(ctx, send) || s.deliverNextMail(ctx, send) {
		t.Fatal("due jobs did not drain around the delayed retry")
	}
	s.state.MailQueue[0].NextTry = time.Time{}
	if !s.deliverNextMail(ctx, send) || !s.deliverNextMail(ctx, send) || s.deliverNextMail(ctx, send) ||
		len(delivered) != 4 || delivered[0] != delivered[2] || delivered[1] == delivered[0] || delivered[3] == delivered[0] {
		t.Fatalf("incorrect retry identity or duplicate success: %v", delivered)
	}
}

func TestNotificationMIMEIncludesEscapedHTMLAndChinesePlainText(t *testing.T) {
	cfg := mailSettings{From: "monitor@example.com", Recipients: []string{"ops@example.com", "admin@example.com"}}
	notice := mailNotice{Kind: mailICMPRecovery, Name: "机房 <a>", Address: "probe.example.com", IP: assessmentIP,
		At: time.Unix(1800000120, 0).UTC(), StartedAt: time.Unix(1800000000, 0).UTC()}
	raw, err := notificationMessage(cfg, notice, "mail-id", "https://monitor.example.com")
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != "[链路观测] 目标 ICMP 恢复 · 机房 <a>" {
		t.Fatalf("invalid subject %q: %v", subject, err)
	}
	media, parameters, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || media != "multipart/alternative" {
		t.Fatalf("invalid content type %q: %v", media, err)
	}
	reader := multipart.NewReader(message.Body, parameters["boundary"])
	for _, expected := range []string{"机房 <a>", "机房 &lt;a&gt;"} {
		part, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(part)
		if err != nil || !strings.Contains(string(body), expected) || !strings.Contains(string(body), "https://monitor.example.com") {
			t.Fatalf("invalid email body: %s (%v)", body, err)
		}
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatalf("multipart did not terminate cleanly: %v", err)
	}
}

func TestSMTPDoesNotSendCredentialsWithoutStartTLS(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	commands := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			commands <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprint(conn, "220 localhost ready\r\n")
		lines := bufio.NewReader(conn)
		line, _ := lines.ReadString('\n')
		fmt.Fprint(conn, "250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
		next, _ := lines.ReadString('\n')
		commands <- line + next
	}()
	_, portString, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	cfg := mailSettings{Host: "127.0.0.1", Port: port, Security: "starttls",
		Username: "test", Password: "private", From: "monitor@example.com", Recipients: []string{"ops@example.com"}}
	err = sendNotification(t.Context(), cfg, mailNotice{Kind: mailTest, At: time.Now()}, "test-id", "https://monitor.example.com")
	if err == nil || !strings.Contains(err.Error(), "未提供 STARTTLS") {
		t.Fatalf("insecure relay should be rejected, got %v", err)
	}
	if got := <-commands; got != "EHLO localhost\r\n" {
		t.Fatalf("unexpected SMTP commands before TLS: %q", got)
	}
}

func adminTestRequest(t *testing.T, s *server, method, path string, body any, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := scheduleRequest(t, method, path, body)
	req.AddCookie(s.cookie("admin", 60))
	reply := httptest.NewRecorder()
	s.routes().ServeHTTP(reply, req)
	if reply.Code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, reply.Code, want, reply.Body)
	}
	return reply
}

func TestSMTPSubmitsMailOverVerifiedTLS(t *testing.T) {
	peer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(peer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(peer.Certificate())
	for _, mode := range []string{"tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			message := []byte("Subject: Test\r\n\r\n.Message\r\n")
			result := make(chan error, 1)
			go func() { result <- receiveTestSMTP(listener, peer.TLS, mode, message) }()
			_, portString, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portString)
			cfg := mailSettings{Host: "127.0.0.1", Port: port, Security: mode, Username: "app",
				Password: "test-pass", From: "monitor@example.com", Recipients: []string{"ops@example.com"}}
			tlsConfig := &tls.Config{ServerName: cfg.Host, RootCAs: roots, MinVersion: tls.VersionTLS12}
			if err := sendSMTP(t.Context(), cfg, tlsConfig, message); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func receiveTestSMTP(listener net.Listener, tlsConfig *tls.Config, mode string, expected []byte) error {
	wire, err := listener.Accept()
	if err != nil {
		return err
	}
	defer wire.Close()
	_ = wire.SetDeadline(time.Now().Add(3 * time.Second))
	var conn net.Conn = wire
	if mode == "tls" {
		conn = tls.Server(conn, tlsConfig)
	}
	protocol := textproto.NewConn(conn)
	if err := protocol.PrintfLine("220 SMTP test"); err != nil {
		return err
	}
	if mode == "starttls" {
		if err := expectSMTPLine(protocol, "EHLO localhost", "250-hello\r\n250 STARTTLS"); err != nil {
			return err
		}
		if err := expectSMTPLine(protocol, "STARTTLS", "220 start TLS"); err != nil {
			return err
		}
		protocol = textproto.NewConn(tls.Server(conn, tlsConfig))
	}
	for _, exchange := range [][2]string{
		{"EHLO localhost", "250-hello\r\n250 AUTH LOGIN"},
		{"AUTH LOGIN", "334 " + base64.StdEncoding.EncodeToString([]byte("Username:"))},
		{base64.StdEncoding.EncodeToString([]byte("app")), "334 " + base64.StdEncoding.EncodeToString([]byte("Password:"))},
		{base64.StdEncoding.EncodeToString([]byte("test-pass")), "235 ok"},
		{"MAIL FROM:<monitor@example.com>", "250 ok"},
		{"RCPT TO:<ops@example.com>", "250 ok"},
		{"DATA", "354 submit"},
	} {
		if err := expectSMTPLine(protocol, exchange[0], exchange[1]); err != nil {
			return err
		}
	}
	body, err := protocol.ReadDotBytes()
	if err != nil {
		return err
	}
	if string(body) != strings.ReplaceAll(string(expected), "\r\n", "\n") {
		return fmt.Errorf("SMTP data = %q", body)
	}
	return protocol.PrintfLine("250 queued")
}

func expectSMTPLine(conn *textproto.Conn, want, response string) error {
	line, err := conn.ReadLine()
	if err != nil {
		return err
	}
	if line != want {
		return fmt.Errorf("SMTP line = %q, want %q", line, want)
	}
	return conn.PrintfLine("%s", response)
}

func TestNewResolvedIPCanOpenItsOwnIncident(t *testing.T) {
	const start, step = 1800000000, protocol.DefaultIntervalSeconds
	target := targetRecord{Target: protocol.Target{ID: "t", IP: "probe.example.com", Port: 443}}
	state := diskState{Mail: mailSettings{Enabled: true, Events: []mailKind{mailTCPFailure, mailTCPRecovery}}}
	for i := int64(0); i < 8; i++ {
		window := start + i*step
		round := assessmentRound(target, window)
		for _, samples := range round.Samples {
			result := &samples["t"].Results[0]
			if i >= 3 {
				result.ResolvedIP = "192.0.2.2"
			}
			if i >= 6 {
				result.TCP = protocol.Probe{Status: "ok", Sent: 1, Received: 1}
			}
		}
		state.recordTargetNotifications(&target, assess(round, "t", window), window, step)
	}
	if len(state.MailQueue) != 3 || state.MailQueue[0].Notice.IP != assessmentIP ||
		state.MailQueue[1].Notice.Kind != mailTCPFailure || state.MailQueue[1].Notice.IP != "192.0.2.2" ||
		state.MailQueue[2].Notice.Kind != mailTCPRecovery || state.MailQueue[2].Notice.IP != "192.0.2.2" ||
		len(target.TCPAlert.Active) != 1 || target.TCPAlert.Active[0].IP != assessmentIP {
		t.Fatalf("unexpected tracking across DNS changes: notices=%+v, active=%+v", state.MailQueue, target.TCPAlert.Active)
	}
}
