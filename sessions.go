package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	sessionTokenBytes = 32
	cleanupInterval   = 15 * time.Minute
	sessionTTL        = 1 * time.Hour
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

type sessionStore struct {
	sessions    map[[sha256.Size]byte]session
	mu          sync.Mutex
	nextCleanup time.Time
}

type session struct {
	user      user
	expiresAt time.Time
}

func NewSessionStore() *sessionStore {
	return &sessionStore{
		sessions:    make(map[[sha256.Size]byte]session),
		nextCleanup: time.Now().Add(cleanupInterval),
	}
}

func (s *sessionStore) Create(ctx context.Context, u user) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	b := make([]byte, sessionTokenBytes)
	rand.Read(b)

	sid := base64.RawURLEncoding.EncodeToString(b)
	tokenHash := sha256.Sum256(b)

	sessionUser := cloneUser(u)
	now := time.Now()

	s.mu.Lock()
	s.sessions[tokenHash] = session{
		user:      sessionUser,
		expiresAt: now.Add(sessionTTL),
	}

	if !now.Before(s.nextCleanup) {
		s.deleteExpiredLocked(now)
	}
	s.mu.Unlock()

	return sid, nil
}

func (s *sessionStore) Get(ctx context.Context, token string) (*session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	tokenHash, err := hashSessionToken(token)
	if err != nil {
		// Do not expose wether the format or lookup was invalid
		return nil, ErrSessionNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, found := s.sessions[tokenHash]
	if !found {
		return nil, ErrSessionNotFound
	}
	if !time.Now().Before(sess.expiresAt) {
		delete(s.sessions, tokenHash)
		return nil, ErrSessionExpired
	}
	return cloneSession(sess), nil
}

func (s *sessionStore) Delete(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	tokenHash, err := hashSessionToken(token)
	if err != nil {
		return nil
	}

	s.mu.Lock()
	delete(s.sessions, tokenHash)
	s.mu.Unlock()

	return nil
}

// Caller must hold mutex lock
func (s *sessionStore) deleteExpiredLocked(now time.Time) {
	nextCleanup := now.Add(cleanupInterval)

	for i, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, i)
		}
	}
	s.nextCleanup = nextCleanup
}

func hashSessionToken(token string) ([sha256.Size]byte, error) {
	randomBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return [sha256.Size]byte{}, errors.New("invalid session token encoding")
	}

	if len(randomBytes) != sessionTokenBytes {
		return [sha256.Size]byte{}, errors.New("invalid session token length")
	}

	return sha256.Sum256(randomBytes), nil
}

func cloneSession(sess session) *session {
	sess.user = cloneUser(sess.user)
	return &sess
}

func cloneUser(u user) user {
	u.roles = append([]string(nil), u.roles...)
	return u
}
