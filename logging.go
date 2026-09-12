package main

import (
	"log/slog"
	"os"
)

func newLogger() *slog.Logger {
	handler := slog.NewJSONHandler(
		os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelInfo},
	)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}
