package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInstalledScriptKeepsProxyForUpdatesAndReportsStatus(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("isolated installer test uses the non-root installation directory")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum unavailable")
	}
	entry, err := filepath.Abs("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	trace := filepath.Join(home, "downloads")
	write(filepath.Join(bin, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 2 ;; esac\n", 0700)
	write(filepath.Join(bin, "timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n", 0700)
	write(filepath.Join(bin, "nexttrace"), "#!/bin/sh\nexit 1\n", 0700)
	write(filepath.Join(bin, "nexttrace-tiny"), "#!/bin/sh\necho --json\n", 0700)
	write(filepath.Join(bin, "flock"), "#!/bin/sh\nexit 0\n", 0700)
	write(filepath.Join(bin, "curl"), `#!/bin/sh
if [ "$#" -eq 4 ] && [ "$1" = -fsSL ]; then
    [ "$4" = "$TEST_PROXY/$TEST_ENTRY_URL" ] || exit 4
    printf '%s\n' "$4" >> "$TEST_TRACE"
    exec cat "$TEST_ENTRY_FILE"
fi
until [ "$1" = -o ] || [ "$#" -eq 0 ]; do shift; done
[ "$#" -eq 3 ] || exit 4
printf '%s\n' "$3" >> "$TEST_TRACE"
case "$3" in
    "$TEST_MANAGER/api/agent/installer-release") file=metadata ;;
    "$TEST_PROXY/$TEST_LATEST_URL") file=initial-script ;;
    "$TEST_PROXY/$TEST_INITIAL/link-probe-linux-amd64") file=initial-binary ;;
    "$TEST_PROXY/$TEST_UPDATE/install.sh") file=update-script ;;
    "$TEST_PROXY/$TEST_UPDATE/link-probe-linux-amd64") file=update-binary ;;
    *) exit 4 ;;
esac
cp "$HOME/$file" "$2"
`, 0700)
	t.Setenv("HOME", home)
	t.Setenv("TMPDIR", home)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	const (
		manager   = "https://monitor.example.com"
		proxy     = "https://proxy.example.com/cache"
		initial   = officialReleaseDownloadPrefix + "v0.1.11"
		update    = officialReleaseDownloadPrefix + "v0.1.12"
		latest    = "https://github.com/" + installerRepo + "/releases/latest/download/install.sh"
		nextTrace = "https://github.com/nxtrace/NTrace-core/releases/download/v1.7.6/nexttrace_linux_amd64"
	)
	t.Setenv("TEST_TRACE", trace)
	t.Setenv("TEST_MANAGER", manager)
	t.Setenv("TEST_PROXY", proxy)
	t.Setenv("TEST_INITIAL", initial)
	t.Setenv("TEST_ENTRY_URL", mainInstallerURL)
	t.Setenv("TEST_ENTRY_FILE", entry)
	t.Setenv("TEST_LATEST_URL", latest)
	t.Setenv("TEST_UPDATE", update)
	for _, release := range []struct{ name, tag string }{{"initial", "v0.1.11"}, {"update", "v0.1.12"}} {
		probe := "#!/bin/bash\nversion=" + release.tag + "\n" + `
dir=${!#}
case $1 in
    register)
        if [[ ! -f $dir/credentials.json ]]; then
            IFS= read -r token && [[ $token == test-token ]] || exit 1
            touch "$dir/credentials.json" "$dir/running"
        fi
        ;;
    run) touch "$dir/running"; sleep 0.4 ;;
    status) [[ -f $dir/running ]] ;;
    stop) rm -f "$dir/running" ;;
    version) echo "$version" ;;
    *) exit 1 ;;
esac
`
		write(filepath.Join(home, release.name+"-binary"), probe, 0600)
		installer, err := exec.Command(bash, "../../scripts/package-install.sh", release.tag, installerRepo, digest(probe), digest(probe)).Output()
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(home, release.name+"-script"), string(installer), 0600)
	}
	run := func(success bool, args ...string) string {
		t.Helper()
		output, err := exec.Command(bash, args...).CombinedOutput()
		if success != (err == nil) {
			t.Fatalf("unexpected installer result: %v\n%s", err, output)
		}
		return string(output)
	}
	command := buildInstallCommand("", manager, "probe-1", "test-token", proxy)
	node := filepath.Join(home, ".local/share/link-monitor/nodes/probe-1")
	download := filepath.Join(home, "initial-script")
	complete := read(download)
	cut := strings.LastIndex(complete, "\nLINK_OBSERVATORY_INSTALLER\n")
	if cut < 0 {
		t.Fatal("missing installer terminator")
	}
	write(download, complete[:cut], 0600)
	run(false, "-c", command)
	if _, err := os.Stat(node); !os.IsNotExist(err) {
		t.Fatalf("partial download started installation: %v", err)
	}
	write(download, complete, 0600)
	run(true, "-c", command)
	script := filepath.Join(node, "install.sh")
	settings := filepath.Join(node, "settings")
	if saved := read(settings); saved != manager+"\n"+initial+"\n"+proxy+"\n" {
		t.Fatalf("incorrect saved proxy or release: %q", saved)
	}
	before := read(trace)
	for _, expected := range []string{"运行状态：运行中", "版本：v0.1.11", manager, proxy} {
		if status := run(true, script, "--status"); !strings.Contains(status, expected) {
			t.Fatalf("status is missing %q: %s", expected, status)
		}
	}
	if read(trace) != before {
		t.Fatal("status initiated a network request")
	}

	metadata := filepath.Join(home, "metadata")
	write(metadata, update+"\n"+digest("tampered")+"\ntrue\n", 0600)
	if output := run(false, script, "--update"); !strings.Contains(output, "下载文件校验失败：install.sh") {
		t.Fatalf("modified release script did not fail verification: %s", output)
	}
	if read(settings) != manager+"\n"+initial+"\n"+proxy+"\n" {
		t.Fatal("failed verification altered the previous installation")
	}
	write(metadata, update+"\n"+digest(read(filepath.Join(home, "update-script")))+"\ntrue\n", 0600)
	run(true, script, "--update")
	if saved := read(settings); saved != manager+"\n"+update+"\n"+proxy+"\n" {
		t.Fatalf("update did not retain saved proxy: %q", saved)
	}
	if got := run(true, script, "--status"); !strings.Contains(got, "版本：v0.1.12") {
		t.Fatalf("updated probe version missing: %s", got)
	}
	if err := os.Remove(filepath.Join(node, "running")); err != nil {
		t.Fatal(err)
	}
	if got := run(true, script, "--status"); !strings.Contains(got, "运行状态：已停止") {
		t.Fatalf("stopped probe status missing: %s", got)
	}
	want := []string{
		proxy + "/" + mainInstallerURL, proxy + "/" + latest,
		proxy + "/" + mainInstallerURL, proxy + "/" + latest, proxy + "/" + initial + "/link-probe-linux-amd64", proxy + "/" + nextTrace,
		manager + "/api/agent/installer-release", proxy + "/" + update + "/install.sh",
		manager + "/api/agent/installer-release", proxy + "/" + update + "/install.sh",
		proxy + "/" + update + "/link-probe-linux-amd64", proxy + "/" + nextTrace,
	}
	if downloads := strings.Split(strings.TrimSpace(read(trace)), "\n"); !slices.Equal(downloads, want) {
		t.Fatalf("unexpected download routes: %v", downloads)
	}
	// A compatible system copy takes priority and the previously managed Tiny
	// copy is removed only after the completed upgrade.
	systemNextTrace := filepath.Join(bin, "nexttrace")
	write(systemNextTrace, "#!/bin/sh\necho --json\n", 0700)
	legacy := filepath.Join(node, "nexttrace-tiny")
	write(legacy, "#!/bin/sh\n", 0700)
	before = read(trace)
	run(true, script, "--update")
	newDownloads := strings.Split(strings.TrimSpace(strings.TrimPrefix(read(trace), before)), "\n")
	if slices.Contains(newDownloads, proxy+"/"+nextTrace) {
		t.Fatalf("downloaded NextTrace despite a compatible local installation: %v", newDownloads)
	}
	resolved, err := filepath.EvalSymlinks(systemNextTrace)
	if err != nil || strings.TrimSpace(read(filepath.Join(node, "route-program"))) != resolved {
		t.Fatalf("existing NextTrace was not selected: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("managed Tiny copy was not removed: %v", err)
	}
}
