package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	mainInstallerURL          = "https://raw.githubusercontent.com/" + installerRepo + "/refs/heads/main/install.sh"
	firstProxyInstallerPatch  = 10
	firstStreamInstallerPatch = 11
)

var (
	ghProxyPrefix   = regexp.MustCompile(`^https://([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*$`)
	proxyReleaseTag = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[A-Za-z0-9.-]+)?$`)
)

func (s *server) probeRelease(ctx context.Context) (installerRelease, error) {
	if !s.cfg.releaseConfigured() {
		return installerRelease{}, errors.New("请设置 HTTPS 管理端地址。固定发行版本还需配置安装脚本 SHA-256。")
	}
	if s.cfg.releaseURL != "" {
		return installerRelease{URL: s.cfg.releaseURL, SHA256: s.cfg.installHash}, nil
	}
	if s.resolveLatestInstaller != nil {
		if release, err := s.resolveLatestInstaller(ctx); err == nil {
			return release, nil
		}
	}
	return installerRelease{}, errors.New("暂时无法获取 GitHub 发行版校验值，请稍后重试。")
}

func (s *server) probeReleaseMetadata(w http.ResponseWriter, r *http.Request) {
	release, err := s.probeRelease(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s\n%s\n%t\n", release.URL, release.SHA256, installerSupports(path.Base(release.URL), firstProxyInstallerPatch))
}

func normalizeGHProxy(value string) (string, bool) {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	if len(value) > 512 || !ghProxyPrefix.MatchString(value) {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return "", false
	}
	if port := parsed.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return "", false
		}
	}
	return value, true
}

func installerSupports(tag string, firstPatch int) bool {
	parts := proxyReleaseTag.FindStringSubmatch(tag)
	if parts == nil {
		return false
	}
	major, _ := strconv.Atoi(parts[1])
	minor, _ := strconv.Atoi(parts[2])
	patch, _ := strconv.Atoi(parts[3])
	return major > 0 || minor > 1 || (minor == 1 && patch >= firstPatch)
}

func (s *server) nodeInstallCommand(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token   string `json:"token"`
		GHProxy string `json:"gh_proxy"`
	}
	if !decodeJSON(w, r, &input, 8192) {
		return
	}
	var proxy string
	if input.GHProxy != "" {
		var ok bool
		proxy, ok = normalizeGHProxy(input.GHProxy)
		if !ok {
			writeError(w, http.StatusBadRequest, "请输入有效的 gh-proxy HTTPS 地址。可包含端口或路径前缀。")
			return
		}
	}
	id := r.PathValue("id")
	s.mu.Lock()
	node, exists := s.state.Nodes[id]
	s.mu.Unlock()
	switch {
	case !exists:
		writeError(w, http.StatusNotFound, "找不到该探针。")
		return
	case input.Token != "" && (node.Credential != "" || node.TokenExpiry <= time.Now().Unix() ||
		!matchesDigest(node.Enrollment, input.Token)):
		writeError(w, http.StatusConflict, "注册令牌已失效，请重新生成。")
		return
	case input.Token == "" && node.Credential == "":
		writeError(w, http.StatusConflict, "探针尚未注册，请先生成注册令牌。")
		return
	}
	if !s.cfg.cookieSecure {
		writeError(w, http.StatusServiceUnavailable, "请设置 HTTPS 管理端地址。")
		return
	}
	releaseURL := s.cfg.releaseURL
	if releaseURL != "" && proxy != "" && !installerSupports(path.Base(releaseURL), firstProxyInstallerPatch) {
		writeError(w, http.StatusConflict, "gh-proxy 需要 v0.1.10 或更新的探针发行版。")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"command": buildInstallCommand(releaseURL, s.cfg.publicURL, id, input.Token, proxy)})
}

func buildInstallCommand(releaseURL, manager, id, token, proxy string) string {
	downloadURL := mainInstallerURL
	if releaseURL != "" {
		downloadURL = releaseURL + "/install.sh"
	}
	if proxy != "" {
		downloadURL = proxy + "/" + downloadURL
	}
	tag := path.Base(releaseURL)
	stream := releaseURL == "" || installerSupports(tag, firstStreamInstallerPatch)
	managerFlag, tokenFlag := "-e", "-t"
	if stream {
		managerFlag, tokenFlag = "--manager", "--token"
	}
	legacyManager := tag == "v0.1.0" || tag == "v0.1.1" || tag == "v0.1.2"
	if legacyManager {
		managerFlag = "--manager"
	}
	legacyMenu := legacyManager || tag == "v0.1.3"
	args := []string{managerFlag + " " + shellQuote(manager), "--node " + shellQuote(id)}
	if releaseURL != "" && (!stream || !strings.HasPrefix(releaseURL, officialReleaseDownloadPrefix)) {
		args = append(args, "--release-url "+shellQuote(releaseURL))
	}
	if proxy != "" || (!stream && installerSupports(tag, firstProxyInstallerPatch)) {
		args = append(args, "--gh-proxy "+shellQuote(proxy))
	}
	if token != "" && !legacyManager {
		args = append(args, tokenFlag+" "+shellQuote(token))
	} else if token == "" && !legacyMenu {
		args = append(args, "--update")
	}

	run := "bash -s --"
	if !stream {
		// Older release installers use their file path to save a local copy.
		script := `umask 077; f=$(mktemp) || exit; cleanup() { rm -f -- "$f"; }; trap cleanup EXIT; cat > "$f" && test -s "$f" || exit; `
		switch {
		case legacyManager && token != "":
			script += `token=$1; shift; printf "%s\n" "$token" | bash "$f" "$@"`
		case legacyMenu && token == "":
			script += `bash "$f" "$@" </dev/tty`
		default:
			script += `bash "$f" "$@"`
		}
		run = "bash -c " + shellQuote(script) + " --"
		if legacyManager && token != "" {
			run += " " + shellQuote(token)
		}
	}
	continuation := " " + string('\\') + "\n  "
	return "curl -fsSL --proto '=https' " + shellQuote(downloadURL) + " | " + run +
		continuation + strings.Join(args, continuation)
}
