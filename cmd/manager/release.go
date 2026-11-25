package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"link-observatory/internal/protocol"
)

const (
	installerRepo                  = "ZikQ-Shmily/link-observatory"
	latestInstallerAPI             = "https://api.github.com/repos/" + installerRepo + "/releases/latest"
	officialReleaseDownloadPrefix  = protocol.ReleaseDownloadPrefix
	installerLookupTimeout         = 5 * time.Second
	installerLookupTTL             = 5 * time.Minute
	installerLookupRetry           = 30 * time.Second
	maxInstallerLookupResponseSize = 1 << 20
)

var stableInstallerTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type installerRelease struct {
	URL        string
	SHA256     string
	validUntil time.Time
}

type latestInstaller struct {
	client   *http.Client
	endpoint string
	now      func() time.Time

	mu          sync.Mutex
	nextLookup  time.Time
	refreshDone chan struct{}
	release     installerRelease
	err         error
}

func newLatestInstaller() *latestInstaller {
	return &latestInstaller{
		client: &http.Client{
			Timeout: installerLookupTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoint: latestInstallerAPI,
		now:      time.Now,
	}
}

func (cache *latestInstaller) Resolve(ctx context.Context) (installerRelease, error) {
	for {
		if err := ctx.Err(); err != nil {
			return installerRelease{}, err
		}
		cache.mu.Lock()
		if cache.now().Before(cache.nextLookup) {
			release, err := cache.release, cache.err
			cache.mu.Unlock()
			return release, err
		}
		if cache.refreshDone == nil {
			// A single bounded lookup serves all waiters, regardless of who cancels.
			cache.refreshDone = make(chan struct{})
			go cache.refresh()
		}
		done := cache.refreshDone
		cache.mu.Unlock()

		select {
		case <-done:
		case <-ctx.Done():
			return installerRelease{}, ctx.Err()
		}
	}
}

func (cache *latestInstaller) refresh() {
	release, err := cache.fetch()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if err == nil {
		release.validUntil = cache.now().Add(installerLookupTTL)
		cache.release = release
		cache.err = nil
		cache.nextLookup = release.validUntil
	} else {
		if cache.release.URL == "" {
			cache.err = err
		}
		cache.nextLookup = cache.now().Add(installerLookupRetry)
	}
	close(cache.refreshDone)
	cache.refreshDone = nil
}

func (cache *latestInstaller) fetch() (installerRelease, error) {
	request, err := http.NewRequest(http.MethodGet, cache.endpoint, nil)
	if err != nil {
		return installerRelease{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "link-observatory")
	response, err := cache.client.Do(request)
	if err != nil {
		return installerRelease{}, fmt.Errorf("look up latest GitHub release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return installerRelease{}, fmt.Errorf("look up latest GitHub release: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxInstallerLookupResponseSize+1))
	if err != nil {
		return installerRelease{}, fmt.Errorf("read GitHub release: %w", err)
	}
	if len(body) > maxInstallerLookupResponseSize {
		return installerRelease{}, errors.New("GitHub release response exceeds size limit")
	}
	return decodeInstallerRelease(body)
}

func decodeInstallerRelease(body []byte) (installerRelease, error) {
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      *bool  `json:"draft"`
		Prerelease *bool  `json:"prerelease"`
		Assets     []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return installerRelease{}, fmt.Errorf("decode GitHub release: %w", err)
	}
	if release.Draft == nil || *release.Draft || release.Prerelease == nil || *release.Prerelease ||
		len(release.Tag) > 64 || !stableInstallerTag.MatchString(release.Tag) {
		return installerRelease{}, errors.New("GitHub release has no stable version tag")
	}
	var digest string
	for _, asset := range release.Assets {
		if asset.Name != "install.sh" {
			continue
		}
		if digest != "" {
			return installerRelease{}, errors.New("GitHub release has multiple install.sh assets")
		}
		value, ok := strings.CutPrefix(asset.Digest, "sha256:")
		if _, err := hex.DecodeString(value); !ok || len(value) != 64 || err != nil {
			return installerRelease{}, errors.New("GitHub release has an invalid install.sh SHA-256")
		}
		digest = strings.ToLower(value)
	}
	if digest == "" {
		return installerRelease{}, errors.New("GitHub release is missing install.sh")
	}
	return installerRelease{URL: officialReleaseDownloadPrefix + release.Tag, SHA256: digest}, nil
}
