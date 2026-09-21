package main

import (
	"context"
	"testing"
	"time"
)

func TestSessionTokens(t *testing.T) {
	store := NewSessionStore()
	ctx := context.Background()

	users := []struct {
		u               user
		token           string
		returnedSession *session
	}{
		{user{id: "user-1"}, "", nil},
		{user{id: "user-2"}, "", nil},
	}

	for i := range users {
		entry := &users[i]

		token, err := store.Create(ctx, entry.u)
		if err != nil {
			t.Fatal(err)
		}
		entry.token = token

		session, err := store.Get(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		entry.returnedSession = session

		if session.user.id != entry.u.id {
			t.Fatalf("got user ID %q, want %q",
				session.user.id, entry.u.id)
		}
	}

	if users[0].token == users[1].token {
		t.Fatalf("tokens were not unique: %s == %s", users[0].token, users[1].token)
	}
}

func TestTokenExpiry(t *testing.T) {
	store := NewSessionStore()
	ctx := context.Background()

	token, err := store.Create(ctx, user{id: "user1"})
	if err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	for key, session := range store.sessions {
		session.expiresAt = time.Now().Add(-time.Second)
		store.sessions[key] = session
	}
	store.mu.Unlock()

	_, err = store.Get(ctx, token)
	if err != ErrSessionExpired {
		t.Fatalf("got error %v, want %v", err, ErrSessionExpired)
	}
}

func TestRoleIsolation(t *testing.T) {
	t.Run("modifying original user", func(t *testing.T) {
		store := NewSessionStore()
		ctx := context.Background()
		u := user{id: "user-1", roles: []string{"viewer"}}

		token, err := store.Create(ctx, u)
		if err != nil {
			t.Fatal(err)
		}

		u.roles[0] = "admin"

		session, err := store.Get(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		if len(session.user.roles) != 1 ||
			session.user.roles[0] != "viewer" {
			t.Fatalf("got roles %v, want [viewer]", session.user.roles)
		}
	})

	t.Run("modifying returned user", func(t *testing.T) {
		store := NewSessionStore()
		ctx := context.Background()

		token, err := store.Create(ctx, user{
			id:    "user-1",
			roles: []string{"viewer"},
		})
		if err != nil {
			t.Fatal(err)
		}

		session, err := store.Get(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		if len(session.user.roles) != 1 {
			t.Fatalf("got roles %v, want [viewer]", session.user.roles)
		}

		session.user.roles[0] = "admin"

		fetchedAgain, err := store.Get(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		if len(fetchedAgain.user.roles) != 1 ||
			fetchedAgain.user.roles[0] != "viewer" {
			t.Fatalf("got roles %v, want [viewer]", fetchedAgain.user.roles)
		}
	})
}
