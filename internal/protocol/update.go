package protocol

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

const (
	UpdatePollPath        = "/api/agent/update"
	ReleaseDownloadPrefix = "https://github.com/ZikQ-Shmily/link-observatory/releases/download/"
)

var updateID = regexp.MustCompile("^[a-f0-9]{32}$")
var stableVersion = regexp.MustCompile("^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$")

type UpdateOffer struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	InstallerSHA256 string `json:"installer_sha256"`
}

type UpdatePoll struct {
	Version  string `json:"version"`
	Ready    bool   `json:"ready"`
	FailedID string `json:"failed_id,omitempty"`
}

func ValidUpdateID(id string) bool {
	return updateID.MatchString(id)
}

func (offer UpdateOffer) Valid() bool {
	_, err := hex.DecodeString(offer.InstallerSHA256)
	return ValidUpdateID(offer.ID) && len(offer.Version) <= 64 && stableVersion.MatchString(offer.Version) &&
		len(offer.InstallerSHA256) == 64 && offer.InstallerSHA256 == strings.ToLower(offer.InstallerSHA256) && err == nil
}

func NewerVersion(next, current string) bool {
	if len(next) > 64 || len(current) > 64 || !stableVersion.MatchString(next) || !stableVersion.MatchString(current) {
		return false
	}
	newParts := strings.Split(next[1:], ".")
	oldParts := strings.Split(current[1:], ".")
	for i, part := range newParts {
		newValue, newErr := strconv.ParseUint(part, 10, 64)
		oldValue, oldErr := strconv.ParseUint(oldParts[i], 10, 64)
		if newErr != nil || oldErr != nil {
			return false
		}
		if newValue != oldValue {
			return newValue > oldValue
		}
	}
	return false
}
