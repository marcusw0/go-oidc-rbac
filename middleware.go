package main

import (
	"context"
	"net/http"
)

type contextKey string

type user struct {
	email, id string
	roles     []string
}

const (
	sessionID                 = "session_id"
	userContextKey contextKey = "authenticated-user"
)

func (app *application) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := app.getSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(
			r.Context(),
			userContextKey,
			sess.user,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (app *application) getSession(r *http.Request) (*session, error) {
	cookie, err := r.Cookie(sessionID)
	if err != nil {
		return nil, err
	}

	return app.sessions.Get(r.Context(), cookie.Value)
}
