package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type config struct {
	addr     string
	logger   *slog.Logger
	provider *oidc.Provider
}

func main() {
	logger := newLogger()
	if err := run(logger); err != nil {
		logger.Error("server", "runtime", err)
	}
}

func run(logger *slog.Logger) error {
	provider, err := oidc.NewProvider(context.Background(), os.Getenv("AUTH_ADDR"))
	if err != nil {
		return err
	}
	oauth2Config := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
	}

	cfg := config{
		addr:     os.Getenv("ADDR"),
		logger:   logger,
		provider: provider,
	}

	app := application{
		config:  cfg,
		pending: make(map[string]pendingLogin),
		oauth:   oauth2Config,
	}

	return app.run(app.mount())
}
