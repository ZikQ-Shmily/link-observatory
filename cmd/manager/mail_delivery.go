package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"

	"link-observatory/internal/protocol"
)

const mailTimeLimit = 12 * time.Second

func (s *server) mailLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		for ctx.Err() == nil && s.deliverNextMail(ctx, sendNotification) {
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type mailSender func(context.Context, mailSettings, mailNotice, string, string) error

func (s *server) deliverNextMail(ctx context.Context, send mailSender) bool {
	s.mu.Lock()
	cfg := s.state.Mail
	now := time.Now()
	type eventStream struct {
		id   string
		kind mailKind
	}
	waiting := make(map[eventStream]bool)
	index := slices.IndexFunc(s.state.MailQueue, func(job mailJob) bool {
		if !cfg.wants(job.Notice.Kind) {
			return false
		}
		stream := eventStream{job.Notice.ID, job.Notice.Kind.failureKind()}
		if job.NextTry.After(now) {
			waiting[stream] = true
			return false
		}
		return !waiting[stream]
	})
	if index < 0 {
		s.mu.Unlock()
		return false
	}
	job := s.state.MailQueue[index]
	s.mu.Unlock()

	err := send(ctx, cfg, job.Notice, job.ID, s.cfg.publicURL)
	if err != nil && ctx.Err() != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index = slices.IndexFunc(s.state.MailQueue, func(item mailJob) bool { return item.ID == job.ID })
	if index < 0 {
		return true
	}
	next := s.state
	next.MailQueue = slices.Clone(next.MailQueue)
	job.Attempts++
	if err == nil || job.Attempts >= 6 {
		next.MailQueue = slices.Delete(next.MailQueue, index, index+1)
	} else {
		job.NextTry = time.Now().Add(30 * time.Second << (job.Attempts - 1))
		next.MailQueue[index] = job
	}
	if err != nil {
		log.Printf("mail %s for %s (attempt %d/6): %v", job.Notice.Kind, job.Notice.ID, job.Attempts, err)
	}
	// Keep SMTP acceptance in memory even if persisting the queue fails, so
	// the running manager never repeats an accepted delivery on its next tick.
	s.state = next
	if err := writeState(s.filename, next); err != nil {
		log.Printf("save mail queue: %v", err)
	}
	return true
}

type mailFact struct {
	Label string
	Value string
}

type mailContent struct {
	Subject  string
	Heading  string
	State    string
	Summary  string
	Endpoint string
	Facts    []mailFact
	Link     string
	Success  bool
}

var mailHTML = template.Must(template.New("notification").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:20px;background:#f6f6f8;color:#1c2024;font-family:Arial,'PingFang SC','Microsoft YaHei',sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:auto;background:#fff;border:1px solid #dcdee0;border-radius:16px">
<tr><td style="padding:20px 24px;border-bottom:1px solid #f0f0f3"><strong>链路观测</strong></td></tr>
<tr><td style="padding:24px">
<p style="margin:0;color:{{if .Success}}#167342{{else}}#a12f37{{end}};font-weight:bold">{{.State}}</p>
<h1 style="margin:10px 0;font-size:25px;line-height:1.35">{{.Heading}}</h1>
{{if .Endpoint}}<p style="margin:0;color:#60646c;overflow-wrap:anywhere">{{.Endpoint}}</p>{{end}}
<p style="margin:16px 0;line-height:1.6">{{.Summary}}</p>
{{if .Facts}}<table width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #f0f0f3;border-radius:8px">
{{range .Facts}}<tr><th scope="row" align="left" style="padding:8px 12px;background:#f6f6f8;color:#60646c;font-weight:normal;white-space:nowrap">{{.Label}}</th><td style="padding:8px 12px;overflow-wrap:anywhere">{{.Value}}</td></tr>{{end}}
</table><p style="margin:12px 0;color:#60646c;font-size:12px">北京时间（UTC+8）</p>{{end}}
<p style="margin:20px 0 0"><a href="{{.Link}}" style="display:inline-block;padding:10px 16px;background:#000;color:#fff;text-decoration:none;border-radius:24px">打开管理端</a></p>
</td></tr></table></body></html>`))

var beijing = time.FixedZone("UTC+8", 8*60*60)

func mailTime(at time.Time) string { return at.In(beijing).Format("2006-01-02 15:04:05") }

func mailDuration(duration time.Duration) string {
	minutes := int(max(duration, 0) / time.Minute)
	if minutes == 0 {
		return "不足 1 分钟"
	}
	hours := minutes / 60
	if hours == 0 {
		return fmt.Sprintf("%d 分钟", minutes)
	}
	return fmt.Sprintf("%d 小时 %d 分钟", hours, minutes%60)
}

func mailHeartbeatDuration(duration time.Duration) string {
	duration = max(duration, 0).Truncate(time.Second)
	seconds := int(duration / time.Second % 60)
	if duration < time.Minute {
		return fmt.Sprintf("%d 秒", seconds)
	}
	if seconds == 0 {
		return mailDuration(duration)
	}
	return fmt.Sprintf("%s %d 秒", mailDuration(duration), seconds)
}

func formatReachability(count reachabilityCount) string {
	return fmt.Sprintf("%d/%d", count.Reachable, count.Valid)
}

func routeMailIPs(hops []protocol.RouteHop) string {
	labels := make([]string, 0, len(hops))
	for _, hop := range hops {
		label := hop.IP
		if hop.ASN != "" {
			label += " (" + hop.ASN + ")"
		}
		labels = append(labels, label)
	}
	return strings.Join(labels, "、")
}

func notificationContent(notice mailNotice, link string) mailContent {
	content := mailContent{Link: link}
	if notice.Kind == mailTest {
		content.Subject = "[链路观测] 邮件设置测试"
		content.Heading = "测试邮件发送成功"
		content.State = "SMTP 测试"
		content.Summary = "链路观测已通过当前 SMTP 设置发送这封测试邮件。"
		content.Success = true
		return content
	}

	if notice.Kind == mailRouteChange && notice.Route != nil {
		change := notice.Route
		direction := "去程"
		if change.Job.Direction == protocol.RouteBack {
			direction = "回程"
		}
		content.Subject = "[链路观测] " + direction + "路由变化 · " + notice.Name
		content.Heading = notice.Name + " 的" + direction + "路由已变化"
		content.State = fmt.Sprintf("%s · IPv%d", direction, change.Job.Family)
		content.Endpoint = notice.IP
		content.Summary = "连续两轮观察到相同的跳点变化。"
		content.Facts = []mailFact{{"探针", notice.ProbeName}, {"运营商", notice.ISP},
			{"首次发现", mailTime(notice.StartedAt)}, {"确认时间", mailTime(notice.At)}}
		for _, hop := range change.Hops {
			content.Facts = append(content.Facts, mailFact{fmt.Sprintf("第 %d 跳", hop.TTL),
				routeMailIPs(hop.Before) + " → " + routeMailIPs(hop.After)})
		}
		return content
	}

	if notice.Kind == mailProbeOffline || notice.Kind == mailProbeRecovery {
		group := "大陆观测"
		if notice.Group == "overseas" {
			group = "境外观测"
		}
		content.Endpoint = notice.ID
		content.Facts = []mailFact{{"运营商", notice.ISP}, {"地区", notice.Location}, {"分组", group}}
		if notice.Version != "" {
			content.Facts = append(content.Facts, mailFact{"版本", notice.Version})
		}
		content.Success = notice.Kind == mailProbeRecovery
		if content.Success {
			content.Subject = "[链路观测] 探针恢复 · " + notice.Name
			content.Heading = notice.Name + "探针已恢复在线"
			content.State = "离线 → 在线"
			content.Summary = "管理端已重新收到该探针的心跳。"
			// StartedAt is the offline threshold crossing time in stored notices.
			lastHeartbeat := notice.StartedAt.Add(-offlineAfter)
			content.Facts = append(content.Facts, mailFact{"最后心跳", mailTime(lastHeartbeat)},
				mailFact{"恢复时间", mailTime(notice.At)}, mailFact{"离线时长", mailHeartbeatDuration(notice.At.Sub(lastHeartbeat))})
		} else {
			content.Subject = "[链路观测] 探针离线 · " + notice.Name
			content.Heading = notice.Name + "探针已离线"
			content.State = "在线 → 离线"
			content.Summary = "管理端已超过 3 分钟未收到该探针的心跳。"
			content.Facts = append(content.Facts, mailFact{"最后心跳", mailTime(notice.LastSeen)},
				mailFact{"发现时间", mailTime(notice.At)})
		}
		return content
	}

	name, failed, working := "TCPing", "超时", "连接成功"
	if notice.Kind == mailICMPFailure || notice.Kind == mailICMPRecovery {
		name, failed, working = "ICMP", "无回包", "有回包"
	}
	content.Endpoint = notice.Address
	if ip, valid := protocol.ParseTargetIP(notice.IP); valid {
		if notice.Address != notice.IP && !strings.HasPrefix(notice.Address, notice.IP+":") && !strings.HasPrefix(notice.Address, "["+notice.IP+"]:") {
			content.Endpoint += " · " + notice.IP
		}
		if ip.Is4() {
			content.Endpoint += " · IPv4"
		} else {
			content.Endpoint += " · IPv6"
		}
	}
	operatorLabel := "受影响运营商"
	mainland := formatReachability(notice.Mainland)
	content.Success = notice.Kind == mailTCPRecovery || notice.Kind == mailICMPRecovery
	if content.Success {
		content.Subject = "[链路观测] 目标 " + name + " 恢复 · " + notice.Name
		content.Heading = notice.Name + " 的 " + name + " 已恢复"
		content.State = failed + " → " + working
		content.Summary = fmt.Sprintf("原受影响运营商的大陆探针已连续 %d 轮确认同一 IP 的 %s 恢复，境外同期可达。", alertRecoveryRounds, name)
		operatorLabel = "恢复运营商"
		if notice.Previous.Valid > 0 {
			mainland = formatReachability(notice.Previous) + " → " + mainland
		}
	} else {
		content.Subject = "[链路观测] 目标 " + name + " 异常 · " + notice.Name
		content.Heading = notice.Name + " 的 " + name + " 连续" + failed
		content.State = working + " → " + failed
		content.Summary = fmt.Sprintf("大陆探针对同一 IP 的 %s 连续 %d 轮%s，境外同期可达。", name, alertFailureRounds, failed)
	}
	content.Facts = []mailFact{{"大陆 " + name, mainland}, {"境外 " + name, formatReachability(notice.Overseas)},
		{operatorLabel, strings.Join(notice.ISPs, "、")}, {"首次异常", mailTime(notice.StartedAt)}}
	if content.Success {
		content.Facts = append(content.Facts, mailFact{"恢复时间", mailTime(notice.At)},
			mailFact{"异常时长", mailDuration(notice.At.Sub(notice.StartedAt))})
	}
	return content
}

func notificationMessage(cfg mailSettings, notice mailNotice, id, link string) ([]byte, error) {
	content := notificationContent(notice, link)
	var html bytes.Buffer
	if err := mailHTML.Execute(&html, content); err != nil {
		return nil, err
	}
	var plain strings.Builder
	fmt.Fprintf(&plain, "%s\n%s\n%s\n\n%s\n", content.State, content.Heading, content.Endpoint, content.Summary)
	for _, fact := range content.Facts {
		fmt.Fprintf(&plain, "%s　%s\n", fact.Label, fact.Value)
	}
	if len(content.Facts) > 0 {
		plain.WriteString("北京时间（UTC+8）\n")
	}
	fmt.Fprintf(&plain, "\n打开管理端　%s\n", content.Link)

	var message bytes.Buffer
	mimeBody := multipart.NewWriter(&message)
	_, domain, _ := strings.Cut(cfg.From, "@")
	fmt.Fprintf(&message, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n",
		(&mail.Address{Name: "链路观测", Address: cfg.From}).String(), strings.Join(cfg.Recipients, ",\r\n "),
		mime.BEncoding.Encode("UTF-8", content.Subject), notice.At.Format(time.RFC1123Z), id, domain, mimeBody.Boundary())
	for _, part := range []struct{ kind, body string }{{"plain", plain.String()}, {"html", html.String()}} {
		writer, err := mimeBody.CreatePart(textproto.MIMEHeader{
			"Content-Type": {"text/" + part.kind + "; charset=UTF-8"}, "Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		encoded := quotedprintable.NewWriter(writer)
		if _, err := encoded.Write([]byte(part.body)); err != nil {
			return nil, err
		}
		if err := encoded.Close(); err != nil {
			return nil, err
		}
	}
	if err := mimeBody.Close(); err != nil {
		return nil, err
	}
	return message.Bytes(), nil
}

func sendNotification(ctx context.Context, cfg mailSettings, notice mailNotice, id, link string) error {
	message, err := notificationMessage(cfg, notice, id, link)
	if err != nil {
		return errors.New("无法生成邮件内容。")
	}
	tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	return sendSMTP(ctx, cfg, tlsConfig, message)
}

func sendSMTP(ctx context.Context, cfg mailSettings, tlsConfig *tls.Config, message []byte) error {
	ctx, cancel := context.WithTimeout(ctx, mailTimeLimit)
	defer cancel()
	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("无法连接 SMTP 主机，请检查地址、端口和网络。")
	}
	rawConn := conn
	defer rawConn.Close()
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return errors.New("无法设置 SMTP 连接超时。")
	}

	if cfg.Security == "tls" {
		secure := tls.Client(conn, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return errors.New("SMTP TLS 握手失败，请检查证书和端口。")
		}
		conn = secure
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return smtpError("SMTP 服务未能建立会话。", err)
	}
	defer client.Close()
	if cfg.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP 服务未提供 STARTTLS。")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return errors.New("SMTP STARTTLS 握手失败，请检查证书和端口。")
		}
	}
	if cfg.Username != "" {
		_, methods := client.Extension("AUTH")
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		methods = strings.ToUpper(methods)
		if slices.Contains(strings.Fields(methods), "LOGIN") && !slices.Contains(strings.Fields(methods), "PLAIN") {
			auth = smtpLoginAuth{cfg.Username, cfg.Password, cfg.Host}
		}
		if err := client.Auth(auth); err != nil {
			return smtpError("SMTP 认证失败，请检查用户名和授权码。", err)
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return smtpError("SMTP 服务拒绝发件地址。", err)
	}
	for _, recipient := range cfg.Recipients {
		if err := client.Rcpt(recipient); err != nil {
			return smtpError("SMTP 服务拒绝收件地址。", err)
		}
	}
	data, err := client.Data()
	if err != nil {
		return smtpError("SMTP 服务拒绝接收邮件。", err)
	}
	if _, err := data.Write(message); err != nil {
		return smtpError("SMTP 邮件传输失败。", err)
	}
	if err := data.Close(); err != nil {
		return smtpError("SMTP 服务未确认邮件送达。", err)
	}
	return nil
}

func smtpError(message string, err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		return fmt.Errorf("%s SMTP %d", message, reply.Code)
	}
	return errors.New(message)
}

type smtpLoginAuth struct{ username, password, host string }

func (a smtpLoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS || server.Name != a.host {
		return "", nil, errors.New("SMTP LOGIN requires verified TLS")
	}
	return "LOGIN", nil, nil
}

func (a smtpLoginAuth) Next(challenge []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(challenge))) {
	case "username:":
		return []byte(a.username), nil
	case "password:":
		return []byte(a.password), nil
	default:
		return nil, errors.New("unexpected SMTP LOGIN challenge")
	}
}
