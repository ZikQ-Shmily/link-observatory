package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"link-observatory/internal/protocol"
)

//go:embed web/*
var web embed.FS

//go:embed install_bootstrap.sh
var installBootstrap string

const (
	adminCookie = "link_observatory_session"
	sessionTTL  = 8 * time.Hour
	enrollTTL   = 15 * time.Minute
)

type settings struct {
	passwordHash string
	publicURL    string
	releaseURL   string
	installHash  string
	cookieSecure bool
}

type loginFailures struct {
	count int
	until time.Time
}

type server struct {
	adminGate              sync.RWMutex
	loginGate              sync.Mutex
	mu                     sync.Mutex
	mailTestGate           sync.Mutex
	nextMailTest           time.Time // Protected by mailTestGate.
	cfg                    settings
	state                  diskState
	filename               string
	sessions               map[string]time.Time
	failures               map[string]loginFailures
	passwordFailures       loginFailures // Protected by adminGate's exclusive lock.
	resolveLatestInstaller func(context.Context) (installerRelease, error)
}

func main() {
	cfg, err := loadSettings()
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now().UTC()
	filename, lock, state, err := openStore(envOr("DATA_DIR", "./data"), now)
	if err != nil {
		log.Fatal(err)
	}
	defer lock.Close()
	app := &server{
		cfg: cfg, state: state, filename: filename,
		sessions: make(map[string]time.Time), failures: make(map[string]loginFailures),
	}
	app.resolveLatestInstaller = newLatestInstaller().Resolve
	httpd := &http.Server{
		Addr: envOr("ADDR", ":8080"), Handler: app.routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute,
	}
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var workers sync.WaitGroup
	workers.Go(func() { app.evaluateLoop(stop) })
	workers.Go(func() { app.mailLoop(stop) })
	defer func() {
		cancel()
		workers.Wait()
	}()
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpd.ListenAndServe() }()
	log.Printf("manager listening on %s", httpd.Addr)
	select {
	case <-stop.Done():
		ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := httpd.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func loadSettings() (settings, error) {
	var cfg settings
	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		return cfg, errors.New("ADMIN_PASSWORD is required")
	}
	cfg.passwordHash = digest(password)
	public, err := url.Parse(envOr("PUBLIC_URL", "http://localhost:8080"))
	if err != nil || public == nil || public.Hostname() == "" ||
		public.User != nil || public.RawQuery != "" || public.Fragment != "" ||
		(public.Path != "" && public.Path != "/") {
		return cfg, errors.New("PUBLIC_URL must be an absolute origin")
	}
	if public.Scheme != "https" && !(public.Scheme == "http" && isLoopbackHost(public.Hostname())) {
		return cfg, errors.New("PUBLIC_URL must use HTTPS, or HTTP on loopback for local testing")
	}
	cfg.publicURL = strings.TrimRight(public.String(), "/")
	cfg.cookieSecure = public.Scheme == "https"

	cfg.releaseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("RELEASE_URL")), "/")
	if cfg.releaseURL == "latest" {
		cfg.releaseURL = ""
	}
	if cfg.releaseURL != "" {
		release, err := url.Parse(cfg.releaseURL)
		if err != nil || release == nil || release.Scheme != "https" || release.Host != "github.com" ||
			release.User != nil || release.RawQuery != "" || release.Fragment != "" {
			return cfg, errors.New("RELEASE_URL must be a pinned GitHub release download URL")
		}
		parts := strings.Split(strings.TrimPrefix(release.Path, "/"), "/")
		if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[2] != "releases" ||
			parts[3] != "download" || parts[4] == "" || parts[4] == "." || parts[4] == ".." {
			return cfg, errors.New("RELEASE_URL must end in /releases/download/<tag>")
		}
		cfg.installHash = strings.ToLower(strings.TrimSpace(os.Getenv("INSTALL_SHA256")))
		if cfg.installHash != "" {
			if _, err := hex.DecodeString(cfg.installHash); err != nil || len(cfg.installHash) != 64 {
				return cfg, errors.New("INSTALL_SHA256 must contain the 64-character installer SHA-256")
			}
		}
	}
	return cfg, nil
}

func (cfg settings) releaseConfigured() bool {
	return cfg.cookieSecure && (cfg.releaseURL == "" || cfg.installHash != "")
}

func (s *server) routes() http.Handler {
	assets, err := fs.Sub(web, "web")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	files := http.FileServer(http.FS(assets))
	for _, path := range []string{"/styles.css", "/app.js", "/logo.svg", "/icon.svg"} {
		mux.Handle("GET "+path, files)
	}
	mux.Handle("GET /{$}", files)
	mux.HandleFunc("GET /install.sh", s.installScript)
	mux.HandleFunc("GET /api/agent/installer-release", s.probeReleaseMetadata)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/admin/login", s.login)
	mux.HandleFunc("POST /api/admin/logout", s.admin(s.logout))
	mux.HandleFunc("POST /api/admin/password", s.protectAdmin(s.changePassword, &s.adminGate))
	mux.HandleFunc("GET /api/admin/state", s.admin(s.adminState))
	mux.HandleFunc("PUT /api/admin/settings", s.admin(s.updateSettings))
	mux.HandleFunc("GET /api/admin/mail", s.admin(s.getMailSettings))
	mux.HandleFunc("PUT /api/admin/mail", s.admin(s.updateMailSettings))
	mux.HandleFunc("POST /api/admin/mail/test", s.admin(s.testMailSettings))
	mux.HandleFunc("PUT /api/admin/nodes/order", s.admin(s.reorderNodes))
	mux.HandleFunc("PUT /api/admin/targets/order", s.admin(s.reorderTargets))
	mux.HandleFunc("POST /api/admin/nodes", s.admin(s.addNode))
	mux.HandleFunc("PUT /api/admin/nodes/{id}", s.admin(s.editNode))
	mux.HandleFunc("POST /api/admin/nodes/{id}/token", s.admin(s.rotateToken))
	mux.HandleFunc("POST /api/admin/nodes/{id}/update", s.admin(s.queueUpdate))
	mux.HandleFunc("POST /api/admin/nodes/{id}/install-command", s.admin(s.nodeInstallCommand))
	mux.HandleFunc("DELETE /api/admin/nodes/{id}", s.admin(s.deleteNode))
	mux.HandleFunc("POST /api/admin/targets", s.admin(s.addTarget))
	mux.HandleFunc("GET /api/admin/targets/{id}/routes", s.admin(s.targetRoutes))
	mux.HandleFunc("PUT /api/admin/targets/{id}/routes", s.admin(s.updateTargetRoutes))
	mux.HandleFunc("POST /api/admin/targets/{id}/routes/trace", s.admin(s.traceTargetNow))
	mux.HandleFunc("POST /api/admin/targets/{target}/return-update", s.admin(s.queueUpdate))
	mux.HandleFunc("POST /api/admin/targets/{id}/return-command", s.admin(s.returnInstallCommand))
	mux.HandleFunc("DELETE /api/admin/targets/{id}/return-runner", s.admin(s.removeReturnRunner))
	mux.HandleFunc("PUT /api/admin/targets/{id}", s.admin(s.editTarget))
	mux.HandleFunc("DELETE /api/admin/targets/{id}", s.admin(s.deleteTarget))
	mux.HandleFunc("POST /api/agent/register", s.register)
	mux.HandleFunc("GET /api/agent/config", s.agentConfig)
	mux.HandleFunc("POST /api/agent/report", s.agentReport)
	mux.HandleFunc("POST "+protocol.UpdatePollPath, s.pollUpdate)
	mux.HandleFunc("POST "+protocol.RoutePollPath, s.routePoll)
	mux.HandleFunc("POST "+protocol.RouteResultPath, s.routeResult)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, into any, limit int64) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "application/json required")
		return false
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func digest(value string) string {
	d := sha256.Sum256([]byte(value))
	return hex.EncodeToString(d[:])
}

func matchesDigest(expected, value string) bool {
	actual := digest(value)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func randomHex(bytes int) string {
	data := make([]byte, bytes)
	_, err := rand.Read(data)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

func (s *server) allowedOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" || origin == s.cfg.publicURL {
		return true
	}
	parsed, err := url.Parse(origin)
	return !s.cfg.cookieSecure && err == nil && parsed.Scheme == "http" && parsed.Host == r.Host &&
		parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" &&
		isLoopbackHost(parsed.Hostname())
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (s *server) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: adminCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.cookieSecure, SameSite: http.SameSiteStrictMode,
	}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !s.allowedOrigin(r) {
		writeError(w, http.StatusForbidden, "request origin rejected")
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input, 8192) {
		return
	}
	// At most one unauthenticated password derivation can run at a time.
	if !s.loginGate.TryLock() {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "another login attempt is in progress")
		return
	}
	defer s.loginGate.Unlock()
	s.adminGate.RLock()
	defer s.adminGate.RUnlock()

	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	s.mu.Lock()
	for ip, failure := range s.failures {
		if !failure.until.After(now) {
			delete(s.failures, ip)
		}
	}
	failure := s.failures[peer]
	if failure.count >= 12 {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	password := s.state.AdminPassword
	s.mu.Unlock()
	correct := matchesAdminPassword(password, s.cfg.passwordHash, input.Password)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !correct {
		if len(s.failures) < 512 || failure.count > 0 {
			if failure.count == 0 {
				failure.until = now.Add(time.Minute)
			}
			failure.count++
			s.failures[peer] = failure
		}
		writeError(w, http.StatusUnauthorized, "invalid password")
		return
	}
	delete(s.failures, peer)
	for key, expiry := range s.sessions {
		if !expiry.After(now) {
			delete(s.sessions, key)
		}
	}
	if old, err := r.Cookie(adminCookie); err == nil {
		delete(s.sessions, old.Value)
	}
	if len(s.sessions) >= 128 {
		var oldestKey string
		oldest := now.Add(sessionTTL)
		for key, expires := range s.sessions {
			if expires.Before(oldest) {
				oldestKey, oldest = key, expires
			}
		}
		delete(s.sessions, oldestKey)
	}
	session := randomHex(32)
	s.sessions[session] = now.Add(sessionTTL)
	http.SetCookie(w, s.cookie(session, int(sessionTTL.Seconds())))
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) admin(next http.HandlerFunc) http.HandlerFunc {
	return s.protectAdmin(next, s.adminGate.RLocker())
}

func (s *server) protectAdmin(next http.HandlerFunc, gate sync.Locker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !s.allowedOrigin(r) {
			writeError(w, http.StatusForbidden, "request origin rejected")
			return
		}
		session, err := r.Cookie(adminCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "sign in required")
			return
		}
		// Password changes are exclusive. Prior requests finish before a change,
		// and later requests validate their session after it has been revoked.
		gate.Lock()
		defer gate.Unlock()
		s.mu.Lock()
		valid := s.sessions[session.Value].After(time.Now())
		s.mu.Unlock()
		if !valid {
			writeError(w, http.StatusUnauthorized, "sign in required")
			return
		}
		next(w, r)
	}
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if session, err := r.Cookie(adminCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, session.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, s.cookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

func cleanLabel(value string) string {
	return strings.TrimSpace(value)
}

func validLabel(value string, max int) bool {
	return value != "" && utf8.RuneCountInString(value) <= max &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

func (s *server) commit(w http.ResponseWriter, state diskState) bool {
	if err := writeState(s.filename, state); err != nil {
		log.Printf("write state: %v", err)
		writeError(w, http.StatusInternalServerError, "could not save changes")
		return false
	}
	s.state = state
	return true
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	var input protocol.Enrollment
	if !decodeJSON(w, r, &input, 8192) {
		return
	}
	if len(input.Credential) < 32 || len(input.Credential) > 128 ||
		strings.IndexFunc(input.Credential, unicode.IsSpace) >= 0 || len(input.Version) > 80 {
		writeError(w, http.StatusBadRequest, "invalid agent credential or version")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.state.lookupAgent(input.NodeID)
	if node.Credential != "" && matchesDigest(node.Credential, input.Credential) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	now := time.Now().Unix()
	if !exists || node.Credential != "" || node.TokenExpiry <= now ||
		!matchesDigest(node.Enrollment, input.Token) {
		writeError(w, http.StatusUnauthorized, "invalid or expired enrollment")
		return
	}
	node.Credential, node.Version, node.LastSeen = digest(input.Credential), input.Version, now
	node.Enrollment, node.TokenExpiry = "", 0
	next := s.state
	next.setAgent(node)
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) agent(w http.ResponseWriter, r *http.Request) (nodeRecord, bool) {
	node, _ := s.state.lookupAgent(r.Header.Get("X-Node-ID"))
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || node.Credential == "" || len(bearer) > 128 || !matchesDigest(node.Credential, bearer) {
		writeError(w, http.StatusUnauthorized, "invalid node credential")
		return nodeRecord{}, false
	}
	return node, true
}

func (s *server) agentConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.agent(w, r)
	if !ok {
		return
	}
	targets := make([]protocol.Target, 0, len(s.state.Targets))
	allowHostnames := r.Header.Get(protocol.HostnamesHeader) == "1"
	for _, target := range s.state.Targets {
		if node.ReturnTarget != "" {
			break
		}
		if !allowHostnames {
			if _, literal := protocol.ParseTargetIP(target.IP); !literal {
				continue
			}
		}
		probeTarget := target.Target
		probeTarget.ID = target.wireID()
		targets = append(targets, probeTarget)
	}
	config := protocol.Config{
		Targets: targets, IntervalSeconds: protocol.DefaultIntervalSeconds,
		ValidUntil: time.Now().Add(10 * time.Minute).Unix(),
	}
	if r.Header.Get(protocol.ScheduleHeader) == "1" {
		config.IntervalSeconds = s.state.ProbeIntervalSeconds
		config.ScheduleStart = s.state.ScheduleStart
	}
	writeJSON(w, http.StatusOK, config)
}

func validProbe(p protocol.Probe) bool {
	switch p.Status {
	case "ok", "timeout", "refused", "reset", "unreachable", "unavailable", "error":
	default:
		return false
	}
	return p.Sent >= 0 && p.Sent <= 16 && p.Received >= 0 && p.Received <= p.Sent &&
		p.RTTMillis >= 0 && p.RTTMillis <= 60000 && len(p.Detail) <= 500
}

func (s *server) agentReport(w http.ResponseWriter, r *http.Request) {
	var report protocol.Report
	if !decodeJSON(w, r, &report, 768<<10) {
		return
	}
	now := time.Now().UTC()
	minute := protocol.DefaultIntervalSeconds
	latest := protocol.WindowStart(now.Unix(), minute) + int64(minute)
	if len(report.Version) > 80 || len(report.Results) > 768 {
		writeError(w, http.StatusBadRequest, "report too large")
		return
	}
	for i := range report.Results {
		result := &report.Results[i]
		if result.Window <= 0 || result.Window%int64(minute) != 0 || result.Window > latest ||
			!validProbe(result.TCP) || !validProbe(result.ICMP) {
			writeError(w, http.StatusBadRequest, "invalid probe result")
			return
		}
		if result.ResolvedIP != "" {
			address, valid := protocol.ParseTargetIP(strings.TrimSpace(result.ResolvedIP))
			if !valid {
				writeError(w, http.StatusBadRequest, "invalid resolved IP in probe result")
				return
			}
			result.ResolvedIP = address.String()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.agent(w, r)
	if !ok {
		return
	}
	node.LastSeen = now.Unix()
	node.ICMPv4, node.ICMPv6 = report.ICMPv4, report.ICMPv6
	if report.Version != "" {
		node.Version = report.Version
	}
	next := s.state
	if node.ReturnTarget != "" {
		next.setAgent(node)
		if s.commit(w, next) {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	interval := next.ProbeIntervalSeconds
	present := protocol.WindowStart(now.Unix(), interval)
	next.Nodes = maps.Clone(next.Nodes)
	if node.MailOfflineSince != 0 {
		next.enqueueMail(probeNotice(node, mailProbeRecovery, now))
		node.MailOfflineSince = 0
	}
	next.Nodes[node.ID] = node
	next.Samples = maps.Clone(next.Samples)
	items := maps.Clone(next.Samples[node.ID])
	if items == nil {
		items = make(map[string]sampleSeries)
	}
	targetsByWireID := make(map[string]targetRecord, len(next.Targets))
	for _, target := range next.Targets {
		targetsByWireID[target.wireID()] = target
	}
	for _, result := range report.Results {
		// Old agents can keep running at one minute. Accept their heartbeat and
		// use only observations on the current schedule for comparisons.
		if result.Window < max(next.ScheduleStart, node.EvidenceStart) || result.Window%int64(interval) != 0 {
			continue
		}
		target, targetExists := targetsByWireID[result.TargetID]
		if !targetExists || (!target.monitoringSince().IsZero() && result.Window < protocol.WindowStart(target.monitoringSince().Unix(), interval)) {
			continue
		}
		if ip, literal := protocol.ParseTargetIP(target.IP); literal && result.ResolvedIP != "" && result.ResolvedIP != ip.String() {
			continue
		}
		result.TargetID = target.ID
		series := items[target.ID]
		items[target.ID] = updateSeries(series, result, present, interval)
	}
	next.Samples[node.ID] = items
	if s.commit(w, next) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (s *server) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-shellscript; charset=utf-8")
	release, err := s.probeRelease(r.Context())
	if err != nil {
		writeInstallerFailure(w, err.Error())
		return
	}
	config := fmt.Sprintf("manager=%s\nrelease=%s\ninstaller_hash=%s",
		shellQuote(s.cfg.publicURL), shellQuote(release.URL), shellQuote(release.SHA256))
	_, _ = io.WriteString(w, strings.Replace(installBootstrap, "# MANAGER_BOOTSTRAP_CONFIG", config, 1))
}

func writeInstallerFailure(w io.Writer, message string) {
	// wget -q drops an HTTP error body. Serve an executable diagnostic instead.
	_, _ = fmt.Fprintf(w, "#!/usr/bin/env bash\nprintf '%%s\\n' %s >&2\nexit 1\n", shellQuote(message))
}
