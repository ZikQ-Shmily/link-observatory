package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testInstallerSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testReleaseBody(tag, digest string) string {
	return fmt.Sprintf(`{"tag_name":%q,"draft":false,"prerelease":false,"assets":[{"name":"install.sh","digest":%q,"browser_download_url":"https://example.com/untrusted.sh"}]}`, tag, digest)
}

func TestDecodeInstallerRelease(t *testing.T) {
	valid := testReleaseBody("v1.2.3", "sha256:"+strings.ToUpper(testInstallerSHA))
	want := installerRelease{URL: "https://github.com/ZikQ-Shmily/link-observatory/releases/download/v1.2.3", SHA256: testInstallerSHA}
	if got, err := decodeInstallerRelease([]byte(valid)); err != nil || got != want {
		t.Fatalf("decode valid release = %+v, %v; want %+v", got, err, want)
	}
	for name, body := range map[string]string{
		"draft":              strings.Replace(valid, `"draft":false`, `"draft":true`, 1),
		"prerelease":         strings.Replace(valid, `"prerelease":false`, `"prerelease":true`, 1),
		"missing flag":       strings.Replace(valid, `"prerelease":false,`, ``, 1),
		"prerelease tag":     testReleaseBody("v1.2.3-rc.1", "sha256:"+testInstallerSHA),
		"path in tag":        testReleaseBody("v1.2.3/../../other", "sha256:"+testInstallerSHA),
		"missing installer":  strings.Replace(valid, `"install.sh"`, `"other.sh"`, 1),
		"duplicate install":  strings.Replace(valid, `]}`, `,{"name":"install.sh","digest":"sha256:`+testInstallerSHA+`"}]}`, 1),
		"missing digest":     testReleaseBody("v1.2.3", ""),
		"wrong digest kind":  testReleaseBody("v1.2.3", "sha512:"+testInstallerSHA),
		"wrong digest size":  testReleaseBody("v1.2.3", "sha256:"+testInstallerSHA[:60]),
		"invalid digest hex": testReleaseBody("v1.2.3", "sha256:g"+testInstallerSHA[1:]),
		"trailing JSON":      valid + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeInstallerRelease([]byte(body)); err == nil {
				t.Fatal("invalid release accepted")
			}
		})
	}
}

func TestLatestInstallerCache(t *testing.T) {
	var requests atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			t.Errorf("expected anonymous GET, got %s", r.Method)
		}
		switch requests.Add(1) {
		case 1, 3:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			fmt.Fprint(w, testReleaseBody("v1.2.3", "sha256:"+testInstallerSHA))
		default:
			fmt.Fprint(w, testReleaseBody("v1.2.4", "sha256:"+testInstallerSHA))
		}
	}))
	t.Cleanup(host.Close)
	cache := newLatestInstaller()
	cache.endpoint = host.URL
	var elapsed atomic.Int64
	cache.now = func() time.Time { return time.Unix(0, elapsed.Load()) }

	check := func(wantTag string, wantRequests int32) {
		t.Helper()
		got, err := cache.Resolve(context.Background())
		if wantTag == "" {
			if err == nil || got != (installerRelease{}) {
				t.Fatalf("cold lookup = %+v, %v; want error", got, err)
			}
		} else if err != nil || got.URL != officialReleaseDownloadPrefix+wantTag || got.SHA256 != testInstallerSHA {
			t.Fatalf("lookup = %+v, %v; want %s", got, err, wantTag)
		}
		if count := requests.Load(); count != wantRequests {
			t.Fatalf("lookups = %d; want %d", count, wantRequests)
		}
	}
	check("", 1)
	check("", 1)
	elapsed.Add(int64(installerLookupRetry))
	check("v1.2.3", 2)
	elapsed.Add(int64(installerLookupTTL - time.Second))
	check("v1.2.3", 2)
	elapsed.Add(int64(time.Second))
	check("v1.2.3", 3)
	check("v1.2.3", 3)
	elapsed.Add(int64(installerLookupRetry))
	check("v1.2.4", 4)
}

func TestLatestInstallerCoalescesAndAllowsCallerCancellation(t *testing.T) {
	var requests atomic.Int32
	started := make(chan struct{})
	unblock := make(chan struct{})
	releaseResponse := sync.OnceFunc(func() { close(unblock) })
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-unblock
		fmt.Fprint(w, testReleaseBody("v1.2.3", "sha256:"+testInstallerSHA))
	}))
	t.Cleanup(host.Close)
	t.Cleanup(releaseResponse)
	cache := newLatestInstaller()
	cache.endpoint = host.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() {
		_, err := cache.Resolve(ctx)
		first <- err
	}()
	select {
	case <-started:
	case <-time.After(installerLookupTimeout):
		t.Fatal("lookup did not start")
	}
	const waiters = 8
	others := make(chan error, waiters)
	for range waiters {
		go func() {
			got, err := cache.Resolve(context.Background())
			if err == nil && got.SHA256 != testInstallerSHA {
				err = errors.New("waiter received an invalid installer hash")
			}
			others <- err
		}()
	}
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter err = %v", err)
		}
	case <-time.After(installerLookupTimeout):
		t.Fatal("canceled waiter did not return")
	}
	releaseResponse()
	for range waiters {
		if err := <-others; err != nil {
			t.Fatal(err)
		}
	}
	if count := requests.Load(); count != 1 {
		t.Fatalf("overlapping lookups made %d requests; want 1", count)
	}
}
