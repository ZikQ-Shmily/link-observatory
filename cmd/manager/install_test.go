package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyBootstrapRunsOnlyVerifiedLauncherPayload(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum unavailable")
	}
	dir := t.TempDir()
	script := "#!/bin/bash\n" +
		"printf 'installer ran\\n'\n" +
		"printf '<%s>\\n' \"$@\"\n" +
		"if [[ $LEGACY_STDIN == 1 ]]; then IFS= read -r token && printf '<%s>\\n' \"$token\"; fi\n"
	wget := "#!/bin/sh\n" +
		"if [ \"$#\" -eq 2 ] && [ \"$1\" = -qO- ] && [ \"$2\" = \"$BOOTSTRAP_URL\" ]; then\n" +
		"    exec cat \"$BOOTSTRAP_FILE\"\n" +
		"fi\n" +
		"[ \"$#\" -eq 3 ] && [ \"$1\" = -qO ] && [ \"$3\" = \"$INSTALL_URL\" ] || exit 2\n" +
		"printf '%s\\n' \"$2\" > \"$INSTALL_TEMP\"\n" +
		"cat \"$INSTALL_FIXTURE\" > \"$2\"\n"
	fixture := filepath.Join(dir, "fixture.sh")
	bootstrap := filepath.Join(dir, "bootstrap.sh")
	destination := filepath.Join(dir, "destination")
	if err := os.WriteFile(fixture, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wget"), []byte(wget), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("INSTALL_FIXTURE", fixture)
	t.Setenv("INSTALL_TEMP", destination)

	const base = "https://github.com/example/project/releases/download/"
	const public = "https://monitor.example.com"
	const token = "one'time $VALUE"
	t.Setenv("BOOTSTRAP_URL", public+"/install.sh")
	t.Setenv("BOOTSTRAP_FILE", bootstrap)
	cases := []struct {
		name, tag, managerFlag string
		legacyStdin, badHash   bool
		update                 bool
	}{
		{name: "enroll", tag: "v0.1.3", managerFlag: "-e"},
		{name: "update without TTY", tag: "v0.1.4", managerFlag: "-e", update: true},
		{name: "legacy enrollment", tag: "v0.1.2", managerFlag: "--manager", legacyStdin: true},
		{name: "checksum mismatch", tag: "v0.1.3", managerFlag: "-e", badHash: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			release := base + c.tag
			t.Setenv("INSTALL_URL", release+"/install.sh")
			if c.legacyStdin {
				t.Setenv("LEGACY_STDIN", "1")
			} else {
				t.Setenv("LEGACY_STDIN", "0")
			}
			hash := digest(script)
			if c.badHash {
				hash = digest("different script")
			}
			s := &server{cfg: settings{publicURL: public, releaseURL: release, installHash: hash, cookieSecure: true}}
			launcher := getInstallScript(t, s)
			if strings.Contains(launcher, token) {
				t.Fatal("public bootstrap included enrollment token")
			}
			if err := os.WriteFile(bootstrap, []byte(launcher), 0600); err != nil {
				t.Fatal(err)
			}
			launcherArgs := "-t " + shellQuote("probe-1:"+token)
			if c.update {
				launcherArgs = "--node 'probe-1'"
			}
			command := "wget -qO- 'https://monitor.example.com/install.sh' | bash -s -- " + launcherArgs
			body, err := exec.Command(bash, "-c", command).CombinedOutput()
			path, readErr := os.ReadFile(destination)
			if readErr != nil {
				t.Fatalf("downloader did not run: %s, %v", body, readErr)
			}
			if _, statErr := os.Stat(strings.TrimSpace(string(path))); !os.IsNotExist(statErr) {
				t.Fatalf("temporary installer left behind: %v", statErr)
			}
			if c.badHash {
				if err == nil || strings.Contains(string(body), "installer ran") {
					t.Fatalf("bad checksum did not block installer: %s, %v", body, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("install command failed: %s, %v", body, err)
			}
			args := []string{c.managerFlag, public, "--node", "probe-1", "--release-url", release}
			switch {
			case c.update:
				args = append(args, "--update")
			case c.legacyStdin:
				args = append(args, token)
			default:
				args = append(args, "-t", token)
			}
			want := "installer ran\n<" + strings.Join(args, ">\n<") + ">\n"
			if !strings.HasSuffix(string(body), want) {
				t.Fatalf("unexpected installer args/stdin: %q", body)
			}
		})
	}
}

func TestInstallScriptResolvesReleaseMetadata(t *testing.T) {
	release := installerRelease{
		URL: "https://github.com/example/project/releases/download/v0.1.4", SHA256: digest("release"),
	}
	s := &server{
		cfg: settings{publicURL: "https://monitor.example.com", cookieSecure: true},
		resolveLatestInstaller: func(context.Context) (installerRelease, error) {
			return release, nil
		},
	}
	launcher := getInstallScript(t, s)
	for _, assignment := range []string{
		"manager=" + shellQuote(s.cfg.publicURL), "release=" + shellQuote(release.URL),
		"installer_hash=" + shellQuote(release.SHA256),
	} {
		if !strings.Contains(launcher, assignment+"\n") {
			t.Fatalf("missing configured assignment %q", assignment)
		}
	}
	s.resolveLatestInstaller = func(context.Context) (installerRelease, error) {
		return installerRelease{}, errors.New("upstream unavailable")
	}
	if failure := getInstallScript(t, s); !strings.Contains(failure, "exit 1") || strings.Contains(failure, "upstream unavailable") {
		t.Fatalf("expected a friendly failure script without upstream details: %q", failure)
	}

	s.cfg.cookieSecure = false
	if s.cfg.releaseConfigured() {
		t.Fatal("loopback HTTP unexpectedly enabled release")
	}
	if failure := getInstallScript(t, s); !strings.Contains(failure, "exit 1") {
		t.Fatalf("expected failure script when HTTPS is unconfigured: %q", failure)
	}
}

func TestReleaseSettingsDefaultToLatest(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "test")
	t.Setenv("PUBLIC_URL", "https://monitor.example.com")
	t.Setenv("INSTALL_SHA256", digest("stale pin"))
	for _, release := range []string{"", "latest"} {
		t.Setenv("RELEASE_URL", release)
		cfg, err := loadSettings()
		if err != nil || cfg.releaseURL != "" || cfg.installHash != "" || !cfg.releaseConfigured() {
			t.Fatalf("release mode %q did not enable latest: %+v, %v", release, cfg, err)
		}
	}

	const pin = "https://github.com/example/project/releases/download/v0.1.3"
	t.Setenv("RELEASE_URL", pin)
	t.Setenv("INSTALL_SHA256", "")
	cfg, err := loadSettings()
	if err != nil || cfg.releaseURL != pin || cfg.releaseConfigured() {
		t.Fatalf("unverified pinned release was enabled: %+v, %v", cfg, err)
	}
	t.Setenv("INSTALL_SHA256", digest("release"))
	cfg, err = loadSettings()
	if err != nil || cfg.releaseURL != pin || !cfg.releaseConfigured() {
		t.Fatalf("verified pinned release was not enabled: %+v, %v", cfg, err)
	}
}

func getInstallScript(t *testing.T, s *server) string {
	t.Helper()
	got := httptest.NewRecorder()
	s.routes().ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/install.sh", nil))
	if got.Code != http.StatusOK || got.Header().Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(got.Header().Get("Content-Type"), "application/x-shellscript") {
		t.Fatalf("bootstrap response = %d, %v", got.Code, got.Header())
	}
	body := got.Body.String()
	if !strings.HasPrefix(body, "#!/usr/bin/env bash\n") || strings.Contains(body, "# MANAGER_BOOTSTRAP_CONFIG") {
		t.Fatalf("incorrect bootstrap output: %q", body)
	}
	return body
}

func TestInstallCommandRequiresCurrentEnrollmentToken(t *testing.T) {
	now := time.Now()
	filename := filepath.Join(t.TempDir(), "state.json")
	state, err := loadState(filename, now)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		cfg: settings{
			publicURL: "https://monitor.example.com", cookieSecure: true,
			releaseURL: "https://github.com/example/project/releases/download/v0.1.11",
		},
		filename: filename, state: state, sessions: map[string]time.Time{"admin": now.Add(time.Hour)},
	}
	routes := s.routes()
	request := func(method, path string, body any, status int, into any) string {
		t.Helper()
		r := scheduleRequest(t, method, path, body)
		r.AddCookie(s.cookie("admin", 60))
		got := httptest.NewRecorder()
		routes.ServeHTTP(got, r)
		if got.Code != status {
			t.Fatalf("%s %s = %d: %s", method, path, got.Code, got.Body)
		}
		if err := json.Unmarshal(got.Body.Bytes(), into); err != nil {
			t.Fatal(err)
		}
		return got.Body.String()
	}

	var initial, rotated nodeEnrollment
	request(http.MethodPost, "/api/admin/nodes", map[string]string{
		"name": "Probe", "location": "Example", "isp": "Example ISP", "group": "mainland",
	}, http.StatusCreated, &initial)
	request(http.MethodPost, "/api/admin/nodes/"+initial.Node.ID+"/token", nil, http.StatusOK, &rotated)
	if initial.Token == "" || rotated.Token == "" || initial.Token == rotated.Token {
		t.Fatal("issued or rotated token missing")
	}
	commandPath := "/api/admin/nodes/" + initial.Node.ID + "/install-command"
	var output map[string]string
	request(http.MethodPost, commandPath, map[string]string{"token": initial.Token}, http.StatusConflict, &output)
	request(http.MethodPost, commandPath, map[string]string{}, http.StatusConflict, &output)
	request(http.MethodPost, commandPath, map[string]string{"token": rotated.Token, "gh_proxy": "http://insecure.example.com"}, http.StatusBadRequest, &output)
	request(http.MethodPost, commandPath, map[string]string{"token": rotated.Token, "gh_proxy": " https://gh.example.com/cache/ "}, http.StatusOK, &output)
	command := output["command"]
	if !strings.Contains(command, shellQuote(rotated.Token)) || !strings.Contains(command, shellQuote("https://gh.example.com/cache")) ||
		!strings.Contains(command, shellQuote(s.cfg.releaseURL)) || strings.Contains(command, s.cfg.publicURL+"/install.sh") {
		t.Fatalf("unexpected proxy install command: %q", command)
	}
	var view adminView
	public := request(http.MethodGet, "/api/admin/state", nil, http.StatusOK, &view)
	if len(view.Nodes) != 1 || !view.ReleaseConfigured {
		t.Fatal("admin list did not report installation availability")
	}
	var ignored any
	req := scheduleRequest(t, http.MethodPost, "/api/agent/register", map[string]string{
		"node_id": initial.Node.ID, "token": rotated.Token, "credential": strings.Repeat("a", 64),
	})
	report := httptest.NewRecorder()
	routes.ServeHTTP(report, req)
	if report.Code != http.StatusNoContent {
		t.Fatalf("could not register node: %d: %s", report.Code, report.Body)
	}
	request(http.MethodPost, commandPath, map[string]string{}, http.StatusOK, &output)
	if !strings.HasSuffix(output["command"], "  --update") || strings.Contains(output["command"], rotated.Token) {
		t.Fatal("registered update included enrollment token or lacked update flag")
	}
	request(http.MethodPost, commandPath, map[string]string{"token": rotated.Token}, http.StatusConflict, &ignored)
	snapshot, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{initial.Token, rotated.Token} {
		if strings.Contains(public, token) || strings.Contains(string(snapshot), token) {
			t.Fatal("enrollment token appeared in state")
		}
	}
}

func TestGitHubInstallCommandUsesMultilineCurlAndKeepsPinnedInstallersWorking(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	curl := `#!/bin/sh
[ "$#" -eq 4 ] && [ "$1" = -fsSL ] && [ "$2" = --proto ] && [ "$3" = =https ] && [ "$4" = "$EXPECTED_URL" ] || exit 7
printf '%s' "$INSTALL_SCRIPT"
`
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(curl), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("INSTALL_SCRIPT", "#!/bin/bash\nprintf '<%s>\\n' \"$@\"\n")
	const manager = "https://monitor.example.com"
	const token = "one'time $VALUE"
	for _, c := range []struct {
		name, release, proxy string
		stream, update       bool
	}{
		{"latest direct", "", "", true, false},
		{"latest proxy", "", "https://proxy.example.com/cache", true, false},
		{"registered update", "", "", true, true},
		{"fork pin", "https://github.com/example/project/releases/download/v0.1.11", "https://proxy.example.com", true, false},
		{"legacy pin", officialReleaseDownloadPrefix + "v0.1.10", "", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			url := mainInstallerURL
			if c.release != "" {
				url = c.release + "/install.sh"
			}
			if c.proxy != "" {
				url = c.proxy + "/" + url
			}
			t.Setenv("EXPECTED_URL", url)
			newToken := token
			if c.update {
				newToken = ""
			}
			command := buildInstallCommand(c.release, manager, "probe-1", newToken, c.proxy)
			lines := strings.Split(command, "\n")
			if !strings.HasPrefix(lines[0], "curl -fsSL --proto '=https' "+shellQuote(url)+" | bash ") || len(lines) < 4 ||
				strings.Contains(command, "sha256") || strings.Contains(lines[0], shellQuote(token)) {
				t.Fatalf("unexpected download command: %q", command)
			}
			managerFlag, tokenFlag := "--manager", "--token"
			if !c.stream {
				managerFlag, tokenFlag = "-e", "-t"
			} else if !strings.Contains(lines[0], "| bash -s --") {
				t.Fatalf("expected official installer to run from stdin: %q", lines[0])
			}
			args := []string{managerFlag, manager, "--node", "probe-1"}
			if c.release != "" && (!c.stream || !strings.HasPrefix(c.release, officialReleaseDownloadPrefix)) {
				args = append(args, "--release-url", c.release)
			}
			if c.proxy != "" || !c.stream {
				args = append(args, "--gh-proxy", c.proxy)
			}
			if c.update {
				args = append(args, "--update")
			} else {
				args = append(args, tokenFlag, token)
			}
			want := "<" + strings.Join(args, ">\n<") + ">\n"
			if output, err := exec.Command(bash, "-c", command).CombinedOutput(); err != nil || string(output) != want {
				t.Fatalf("command did not pass arguments: %q, %v; want %q", output, err, want)
			}
		})
	}
}

func TestProbeReleaseMetadataIsPlainAndPinned(t *testing.T) {
	release := installerRelease{URL: officialReleaseDownloadPrefix + "v0.1.10", SHA256: digest("release")}
	s := &server{
		cfg: settings{publicURL: "https://monitor.example.com", cookieSecure: true},
		resolveLatestInstaller: func(context.Context) (installerRelease, error) {
			return release, nil
		},
	}
	path := "/api/agent/installer-release"
	resp := httptest.NewRecorder()
	s.routes().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
	if resp.Code != 200 || !strings.HasPrefix(resp.Header().Get("Content-Type"), "text/plain") ||
		resp.Body.String() != release.URL+"\n"+release.SHA256+"\ntrue\n" {
		t.Fatalf("incorrect metadata: %d %s: %s", resp.Code, resp.Header().Get("Content-Type"), resp.Body.String())
	}
}

func TestAdminAddsLatestVersionWithoutChangingReportedVersions(t *testing.T) {
	s := &server{
		state: diskState{Nodes: map[string]nodeRecord{
			"new": {ID: "new", Name: "Latest", Version: "v0.1.11"},
			"old": {ID: "old", Name: "Older", Version: "v0.1.6"},
		}},
		sessions: map[string]time.Time{"admin": time.Now().Add(time.Hour)},
	}
	lookups := 0
	s.resolveLatestInstaller = func(context.Context) (installerRelease, error) {
		lookups++
		return installerRelease{URL: officialReleaseDownloadPrefix + "v0.1.11", validUntil: time.Now().Add(time.Minute)}, nil
	}
	read := func(path string) adminView {
		t.Helper()
		reply := adminTestRequest(t, s, http.MethodGet, path, nil, http.StatusOK)
		var view adminView
		if err := json.Unmarshal(reply.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	if view := read("/api/admin/state"); lookups != 0 || view.LatestProbeVersion != "" {
		t.Fatalf("unrequested version lookup: %d, %q", lookups, view.LatestProbeVersion)
	}
	view := read("/api/admin/state?probe_version=1")
	if lookups != 1 || view.LatestProbeVersion != "v0.1.11" ||
		view.Nodes[0].Version != "v0.1.11" || view.Nodes[1].Version != "v0.1.6" {
		t.Fatalf("incorrect release metadata: %+v", view)
	}
	s.resolveLatestInstaller = func(context.Context) (installerRelease, error) {
		return installerRelease{URL: officialReleaseDownloadPrefix + "v0.1.11", validUntil: time.Now().Add(-time.Minute)}, nil
	}
	if view := read("/api/admin/state?probe_version=1"); view.LatestProbeVersion != "" {
		t.Fatalf("unconfirmed latest version: %s", view.LatestProbeVersion)
	}
}
