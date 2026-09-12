package main

import (
	"net/http"
)

const (
	sessionID = "session_id"
)

type user struct {
	email, id, role string
}

func (app *application) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val := r.Context().Value(sessionID); val == nil {
			http.Redirect(w, r, "/login", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
