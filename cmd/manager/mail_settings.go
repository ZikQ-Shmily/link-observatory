package main

import (
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"

	"link-observatory/internal/protocol"
)

type mailSettings struct {
	Enabled    bool       `json:"enabled"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Security   string     `json:"security"`
	Username   string     `json:"username"`
	Password   string     `json:"password,omitempty"`
	From       string     `json:"from"`
	Recipients []string   `json:"recipients"`
	Events     []mailKind `json:"events"`
}

type mailSettingsView struct {
	mailSettings
	HasPassword bool `json:"has_password"`
}

type mailKind string

const (
	mailProbeOffline  mailKind = "probe_offline"
	mailProbeRecovery mailKind = "probe_recovery"
	mailTCPFailure    mailKind = "tcp_failure"
	mailTCPRecovery   mailKind = "tcp_recovery"
	mailICMPFailure   mailKind = "icmp_failure"
	mailICMPRecovery  mailKind = "icmp_recovery"
	mailRouteChange   mailKind = "route_change"
	mailProbeStatus   mailKind = "probe_status"
	mailTCPStatus     mailKind = "tcp_status"
	mailICMPStatus    mailKind = "icmp_status"
	mailTest          mailKind = "test"
)

var mailKinds = []mailKind{
	mailProbeStatus, mailTCPStatus, mailICMPStatus, mailRouteChange,
}

func (kind mailKind) failureKind() mailKind {
	switch kind {
	case mailTCPRecovery:
		return mailTCPFailure
	case mailICMPRecovery:
		return mailICMPFailure
	case mailProbeRecovery:
		return mailProbeOffline
	default:
		return kind
	}
}

func (kind mailKind) group() mailKind {
	switch kind.failureKind() {
	case mailProbeOffline:
		return mailProbeStatus
	case mailTCPFailure:
		return mailTCPStatus
	case mailICMPFailure:
		return mailICMPStatus
	default:
		return kind
	}
}

func groupedMailEvents(events []mailKind) []mailKind {
	grouped := make([]mailKind, 0, len(mailKinds))
	for _, event := range events {
		if group := event.group(); !slices.Contains(grouped, group) {
			grouped = append(grouped, group)
		}
	}
	return grouped
}

func (m mailSettings) wants(kind mailKind) bool {
	return m.Enabled && slices.ContainsFunc(m.Events, func(event mailKind) bool { return event.group() == kind.group() })
}

func (m mailSettings) sameLogin(other mailSettings) bool {
	return m.Host == other.Host && m.Port == other.Port &&
		m.Security == other.Security && m.Username == other.Username
}

func (m mailSettings) sameRoute(other mailSettings) bool {
	return m.sameLogin(other) && m.From == other.From && slices.Equal(m.Recipients, other.Recipients)
}

func (s *server) getMailSettings(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	cfg := s.state.Mail
	s.mu.Unlock()
	hasPassword := cfg.Password != ""
	cfg.Password = ""
	cfg.Events = groupedMailEvents(cfg.Events)
	writeJSON(w, http.StatusOK, mailSettingsView{mailSettings: cfg, HasPassword: hasPassword})
}

func readMailSettings(w http.ResponseWriter, r *http.Request, test bool) (mailSettings, bool) {
	var cfg mailSettings
	if !decodeJSON(w, r, &cfg, 16<<10) {
		return cfg, false
	}
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.From = strings.TrimSpace(cfg.From)
	if name, ok := protocol.NormalizeTargetAddress(cfg.Host); ok {
		cfg.Host = name
	} else {
		cfg.Host = strings.ToLower(cfg.Host)
	}
	seen := make(map[string]bool)
	recipients := make([]string, 0, len(cfg.Recipients))
	for _, raw := range cfg.Recipients {
		address := strings.TrimSpace(raw)
		if address != "" && !seen[address] {
			recipients = append(recipients, address)
			seen[address] = true
		}
	}
	cfg.Recipients = recipients
	cfg.Events = groupedMailEvents(cfg.Events)
	if err := validateMailSettings(cfg, test); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return cfg, false
	}
	return cfg, true
}

func validateMailSettings(cfg mailSettings, test bool) error {
	for _, kind := range cfg.Events {
		if !slices.Contains(mailKinds, kind) {
			return errors.New("请选择支持的邮件通知事件。")
		}
	}
	if cfg.Enabled && len(cfg.Events) == 0 && !test {
		return errors.New("请至少选择一种邮件通知。")
	}
	if !test && !cfg.Enabled && cfg.Host == "" && cfg.From == "" && len(cfg.Recipients) == 0 && cfg.Username == "" && cfg.Password == "" {
		return nil
	}
	if _, ok := protocol.NormalizeTargetAddress(cfg.Host); !ok && cfg.Host != "localhost" {
		return errors.New("请输入有效的 SMTP 主机名或 IP 地址。")
	}
	if cfg.Port < 1 || cfg.Port > 65535 || (cfg.Security != "tls" && cfg.Security != "starttls") {
		return errors.New("请检查 SMTP 端口和加密方式。")
	}
	if !validMailbox(cfg.From) || len(cfg.Recipients) == 0 || len(cfg.Recipients) > 10 {
		return errors.New("请填写有效的发件地址和 1–10 个收件地址。")
	}
	for _, recipient := range cfg.Recipients {
		if !validMailbox(recipient) {
			return errors.New("请检查收件地址，多个地址用逗号或换行分隔。")
		}
	}
	if len(cfg.Password) > 1024 || strings.ContainsAny(cfg.Password, "\x00\r\n") ||
		(cfg.Username != "" && !validLabel(cfg.Username, 254)) || (cfg.Username == "" && cfg.Password != "") {
		return errors.New("请检查 SMTP 用户名和密码。")
	}
	return nil
}

func validMailbox(value string) bool {
	if !validLabel(value, 254) || strings.Count(value, "@") != 1 {
		return false
	}
	for _, char := range value {
		if char > 126 {
			return false
		}
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Name == "" && parsed.Address == value
}

func (s *server) updateMailSettings(w http.ResponseWriter, r *http.Request) {
	cfg, ok := readMailSettings(w, r, false)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyStoredMailPassword(&cfg)
	if cfg.Username != "" && cfg.Password == "" {
		writeError(w, http.StatusBadRequest, "请输入 SMTP 密码或授权码。")
		return
	}
	next := s.state
	next.Mail = cfg
	if cfg.sameRoute(s.state.Mail) {
		next.MailQueue = slices.DeleteFunc(slices.Clone(next.MailQueue), func(job mailJob) bool {
			return !cfg.wants(job.Notice.Kind)
		})
	} else {
		next.MailQueue = nil
	}
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) applyStoredMailPassword(cfg *mailSettings) {
	if cfg.Password == "" && cfg.sameLogin(s.state.Mail) {
		cfg.Password = s.state.Mail.Password
	}
}

func (s *server) testMailSettings(w http.ResponseWriter, r *http.Request) {
	cfg, ok := readMailSettings(w, r, true)
	if !ok {
		return
	}
	s.mu.Lock()
	s.applyStoredMailPassword(&cfg)
	s.mu.Unlock()
	if cfg.Username != "" && cfg.Password == "" {
		writeError(w, http.StatusBadRequest, "请输入 SMTP 密码或授权码。")
		return
	}
	if !s.mailTestGate.TryLock() {
		writeError(w, http.StatusTooManyRequests, "测试邮件正在发送，请稍后重试。")
		return
	}
	defer s.mailTestGate.Unlock()
	now := time.Now()
	if now.Before(s.nextMailTest) {
		writeError(w, http.StatusTooManyRequests, "请稍等几秒再发送测试邮件。")
		return
	}
	s.nextMailTest = now.Add(5 * time.Second)
	if err := sendNotification(r.Context(), cfg, mailNotice{Kind: mailTest, At: now}, randomHex(16), s.cfg.publicURL); err != nil {
		writeError(w, http.StatusBadGateway, "测试发送失败。"+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
