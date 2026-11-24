package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	adminPasswordSaltSize   = 16
	adminPasswordHashSize   = sha256.Size
	adminPasswordIterations = 600_000
	passwordAttemptLimit    = 5
	passwordAttemptWindow   = time.Minute
)

type adminPasswordRecord struct {
	Salt []byte `json:"salt"`
	Hash []byte `json:"hash"`
}

func deriveAdminPassword(password string) (*adminPasswordRecord, error) {
	salt := make([]byte, adminPasswordSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, adminPasswordIterations, adminPasswordHashSize)
	if err != nil {
		return nil, err
	}
	return &adminPasswordRecord{Salt: salt, Hash: hash}, nil
}

func matchesAdminPassword(record *adminPasswordRecord, initialHash, password string) bool {
	if record == nil {
		return matchesDigest(initialHash, password)
	}
	hash, err := pbkdf2.Key(sha256.New, password, record.Salt, adminPasswordIterations, adminPasswordHashSize)
	return err == nil && subtle.ConstantTimeCompare(record.Hash, hash) == 1
}

func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input, 16<<10) {
		return
	}
	if input.CurrentPassword == "" {
		writeError(w, http.StatusBadRequest, "current password is required")
		return
	}
	length := utf8.RuneCountInString(input.NewPassword)
	if length < 12 || length > 128 {
		writeError(w, http.StatusBadRequest, "new password must be 12 to 128 characters")
		return
	}
	if strings.TrimSpace(input.NewPassword) == "" {
		writeError(w, http.StatusBadRequest, "new password must not be all whitespace")
		return
	}
	if strings.ContainsAny(input.NewPassword, "\r\n") {
		writeError(w, http.StatusBadRequest, "new password must not contain line breaks")
		return
	}

	now := time.Now()
	attempts := s.passwordFailures
	if !attempts.until.After(now) {
		attempts = loginFailures{}
	}
	if attempts.count >= passwordAttemptLimit {
		wait := (attempts.until.Sub(now) + time.Second - 1) / time.Second
		w.Header().Set("Retry-After", strconv.FormatInt(int64(wait), 10))
		writeError(w, http.StatusTooManyRequests, "too many password change attempts, try again shortly")
		return
	}

	s.mu.Lock()
	current := s.state.AdminPassword
	s.mu.Unlock()
	if !matchesAdminPassword(current, s.cfg.passwordHash, input.CurrentPassword) {
		if attempts.count == 0 {
			attempts.until = now.Add(passwordAttemptWindow)
		}
		attempts.count++
		s.passwordFailures = attempts
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	if input.NewPassword == input.CurrentPassword {
		writeError(w, http.StatusBadRequest, "new password must differ from the current password")
		return
	}
	newPassword, err := deriveAdminPassword(input.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save new password")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state
	next.AdminPassword = newPassword
	if !s.commit(w, next) {
		return
	}
	clear(s.sessions)
	clear(s.failures)
	s.passwordFailures = loginFailures{}
	http.SetCookie(w, s.cookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}
