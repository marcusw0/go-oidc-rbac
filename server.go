package main

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type application struct {
	config
	pendingMu sync.Mutex
	pending map[string]pendingLogin
	sessionsMu sync.Mutex
	sessions map[string]session
	oauth   oauth2.Config
}

type session struct {
	user user
	expiresAt time.Time
}

func (app *application) mount() http.Handler {
	mux := http.NewServeMux()
	protectedMux := http.NewServeMux()

	protectedMux.HandleFunc("/admin", adminHandler)

	mux.HandleFunc("/{$}", homeHandler)
	mux.HandleFunc("/login", app.loginHandler)
	mux.HandleFunc("/auth/callback", app.callbackHandler)
	mux.Handle("/", app.requireAuth(protectedMux))

	return mux
}

func (app *application) run(handler http.Handler) error {
	srv := &http.Server{
		Addr:    app.addr,
		Handler: handler,
		ErrorLog: slog.NewLogLogger(
			app.logger.Handler(),
			slog.LevelError,
		),
	}

	return srv.ListenAndServe()
}
