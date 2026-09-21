package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type pendingLogin struct {
	state        string
	nonce        string
	pkceVerifier string
	expiresAt    time.Time
}

func foo() {
	b := make([]byte, 32)
	rand.Read(b)

}

func (app *application) loginHandler(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	c := make([]byte, 32)
	d := make([]byte, 32)
	rand.Read(b)
	rand.Read(c)
	rand.Read(d)
	state := base64.RawURLEncoding.EncodeToString(b)
	nonce := base64.RawURLEncoding.EncodeToString(c)
	pkce := oauth2.GenerateVerifier()
	transactionID := base64.RawURLEncoding.EncodeToString(d)

	app.pendingMu.Lock()
	app.pending[transactionID] = pendingLogin{
		state:        state,
		nonce:        nonce,
		pkceVerifier: pkce,
		expiresAt:    time.Now().Add(5 * time.Minute),
	}
	app.pendingMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_transaction",
		Value:    transactionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	authURL := app.oauth.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkce),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (app *application) callbackHandler(w http.ResponseWriter, r *http.Request) {
	transactionID, err := r.Cookie("oidc_transaction")
	if err != nil {
		app.logger.Error("callback", "missing_cookie", err,
			"status", http.StatusBadRequest)
		http.Error(w, "missing cookie", http.StatusBadRequest)
		return
	}

	returnedState := r.URL.Query().Get("state")

	app.pendingMu.Lock()
	pending, found := app.pending[transactionID.Value]
	delete(app.pending, transactionID.Value)
	app.pendingMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_transaction",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	valid := found && time.Now().Before(pending.expiresAt) &&
		returnedState != "" &&
		returnedState == pending.state

	if !valid {
		http.Error(w, "Invalid or expired login", http.StatusBadRequest)
		return
	}

	query := r.URL.Query()
	if query.Get("error") != "" {
		http.Error(w, "Login not completed", http.StatusBadRequest)
		return
	}

	code := query.Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := app.oauth.Exchange(
		r.Context(),
		code,
		oauth2.VerifierOption(pending.pkceVerifier),
	)
	if err != nil {
		app.logger.Error("token exchange", "failed token exchange", err,
			"status", http.StatusBadGateway)
		http.Error(w, "Token exchange failed", http.StatusBadGateway)
		return
	}
	idTokenVerifier := app.provider.Verifier(&oidc.Config{ClientID: app.oauth.ClientID})

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "Missing ID token", http.StatusBadGateway)
		return
	}

	idToken, err := idTokenVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Invalid ID token", http.StatusUnauthorized)
		return
	}

	if idToken.Nonce != pending.nonce {
		http.Error(w, "Invalid login nonce", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Invalid user claims", http.StatusUnauthorized)
		return
	}
	if idToken.Subject == "" {
		http.Error(w, "Missing user identity", http.StatusUnauthorized)
		return
	}

	expiresAt := time.Now().Add(sessionTTL)

	u := user{
		id:    idToken.Subject,
		email: claims.Email,
	}

	sid, err := app.sessions.Create(r.Context(), u)
	if err != nil {
		app.logger.Error("session token", "failed creating session", err,
			"status", http.StatusInternalServerError)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionID,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
		Expires:  expiresAt,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
