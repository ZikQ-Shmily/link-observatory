package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const bootstrapPassword = "starter password 123"

func newPasswordTestServer(t *testing.T) *server {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "state.json")
	state, err := loadState(filename, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &server{
		cfg:   settings{passwordHash: digest(bootstrapPassword), publicURL: "https://monitor.example.com", cookieSecure: true},
		state: state, filename: filename, sessions: make(map[string]time.Time), failures: make(map[string]loginFailures),
	}
}

func passwordRequest(routes http.Handler, method, path, origin string, session *http.Cookie, body map[string]string) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	if session != nil {
		req.AddCookie(session)
	}
	w := httptest.NewRecorder()
	routes.ServeHTTP(w, req)
	return w
}

func passwordStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status %d, want %d: %s", response.Code, want, response.Body)
	}
}

func passwordSession(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminCookie {
		t.Fatalf("unexpected session cookies: %+v", cookies)
	}
	return cookies[0]
}

func TestAdminPasswordChangePersistsAndRevokesSessions(t *testing.T) {
	s := newPasswordTestServer(t)
	routes := s.routes()
	login := func(routes http.Handler, password string) *httptest.ResponseRecorder {
		return passwordRequest(routes, http.MethodPost, "/api/admin/login", s.cfg.publicURL, nil, map[string]string{"password": password})
	}
	old := login(routes, bootstrapPassword)
	passwordStatus(t, old, http.StatusNoContent)
	first := passwordSession(t, old)
	second := passwordSession(t, login(routes, bootstrapPassword))

	next := " " + strings.Repeat("𠮷", 126) + " "
	change := map[string]string{"current_password": bootstrapPassword, "new_password": next}
	passwordStatus(t, passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, nil, change), 401)
	passwordStatus(t, passwordRequest(routes, http.MethodPost, "/api/admin/password", "https://other.example.com", first, change), 403)
	change["current_password"] = "wrong"
	passwordStatus(t, passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, first, change), 403)
	passwordStatus(t, passwordRequest(routes, http.MethodGet, "/api/admin/state", "", first, nil), 200)
	change["current_password"] = bootstrapPassword

	for _, invalid := range []string{"short", strings.Repeat(" ", 12), bootstrapPassword, "has\nline breaks", "has\rline breaks"} {
		change["new_password"] = invalid
		passwordStatus(t, passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, first, change), 400)
	}
	change["new_password"] = next
	result := passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, first, change)
	passwordStatus(t, result, 204)
	if cookie := passwordSession(t, result); cookie.MaxAge >= 0 || cookie.Value != "" {
		t.Fatal("password change did not expire client session")
	}
	for _, old := range []*http.Cookie{first, second} {
		passwordStatus(t, passwordRequest(routes, http.MethodGet, "/api/admin/state", "", old, nil), 401)
	}

	bytes, err := os.ReadFile(s.filename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), next) || strings.Contains(string(bytes), bootstrapPassword) {
		t.Fatal("plain text password persisted")
	}
	persisted, err := loadState(s.filename, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if persisted.AdminPassword == nil {
		t.Fatal("password record did not survive reload")
	}
	restarted := &server{
		cfg: s.cfg, state: persisted, filename: s.filename, sessions: make(map[string]time.Time), failures: make(map[string]loginFailures),
	}
	routes = restarted.routes()
	passwordStatus(t, login(routes, bootstrapPassword), 401)
	passwordStatus(t, login(routes, strings.TrimSpace(next)), 401)
	passwordStatus(t, login(routes, next), 204)
}

func TestAdminPasswordChangeThrottleAcrossSessions(t *testing.T) {
	s := newPasswordTestServer(t)
	s.sessions["first"], s.sessions["second"] = time.Now().Add(time.Hour), time.Now().Add(time.Hour)
	routes := s.routes()
	change := map[string]string{"current_password": "wrong", "new_password": "valid next password"}
	for i := 0; i < passwordAttemptLimit; i++ {
		session := s.cookie("first", 60)
		if i%2 == 1 {
			session = s.cookie("second", 60)
		}
		passwordStatus(t, passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, session, change), 403)
	}
	change["current_password"] = bootstrapPassword
	got := passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, s.cookie("second", 60), change)
	passwordStatus(t, got, 429)
	if got.Header().Get("Retry-After") == "" {
		t.Fatal("throttle does not report a retry time")
	}
	passwordStatus(t, passwordRequest(routes, http.MethodGet, "/api/admin/state", "", s.cookie("first", 60), nil), 200)

	s.passwordFailures.until = time.Now().Add(-time.Second)
	change["new_password"] = bootstrapPassword
	passwordStatus(t, passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, s.cookie("second", 60), change), 400)
}

func TestAdminPasswordChangeSerializesWithOldCredentials(t *testing.T) {
	s := newPasswordTestServer(t)
	s.sessions["first"], s.sessions["second"] = time.Now().Add(time.Hour), time.Now().Add(time.Hour)
	routes := s.routes()
	start := make(chan struct{})
	var group sync.WaitGroup
	var changed [2]*httptest.ResponseRecorder
	for i, session := range []string{"first", "second"} {
		group.Go(func() {
			<-start
			changed[i] = passwordRequest(routes, http.MethodPost, "/api/admin/password", s.cfg.publicURL, s.cookie(session, 60),
				map[string]string{"current_password": bootstrapPassword, "new_password": "concurrent password 123"})
		})
	}
	var login *httptest.ResponseRecorder
	group.Go(func() {
		<-start
		login = passwordRequest(routes, http.MethodPost, "/api/admin/login", s.cfg.publicURL, nil,
			map[string]string{"password": bootstrapPassword})
	})
	close(start)
	group.Wait()
	statuses := []int{changed[0].Code, changed[1].Code}
	if statuses[0] > statuses[1] {
		statuses[0], statuses[1] = statuses[1], statuses[0]
	}
	if statuses[0] != 204 || statuses[1] != 401 {
		t.Fatalf("concurrent changes statuses = %v, want one success and one revoked session", statuses)
	}
	if login.Code == 204 {
		passwordStatus(t, passwordRequest(routes, http.MethodGet, "/api/admin/state", "", passwordSession(t, login), nil), 401)
	} else {
		passwordStatus(t, login, 401)
	}
}
