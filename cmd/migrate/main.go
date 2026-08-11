package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Akhilmadineni/clixor-backend/internal/config"
	"github.com/Akhilmadineni/clixor-backend/internal/store/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid_configuration", "error", err)
		os.Exit(1)
	}
	if cfg.Store != "postgres" {
		logger.Error("migration_requires_postgres")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	persistence, err := postgres.Open(ctx, cfg.DatabaseURL, true)
	if err != nil {
		logger.Error("migration_failed", "error", err)
		os.Exit(1)
	}
	persistence.Close()
	logger.Info("migration_complete")
}
