package media

import (
	"context"
	"log/slog"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
)

// RunPendingCleanup continuously converts expired reservations into durable
// media.delete outbox work. Any API replica may run it: PostgreSQL uses
// SKIP LOCKED, and each row transitions out of pending only once.
func RunPendingCleanup(
	ctx context.Context,
	persistence store.Store,
	interval time.Duration,
	batchSize int,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	cleanupPending(ctx, persistence, batchSize, logger)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupPending(ctx, persistence, batchSize, logger)
		}
	}
}

func cleanupPending(ctx context.Context, persistence store.Store, batchSize int, logger *slog.Logger) {
	cleanupPendingAt(ctx, persistence, time.Now().UTC(), batchSize, logger)
}

func cleanupPendingAt(
	ctx context.Context,
	persistence store.Store,
	cutoff time.Time,
	batchSize int,
	logger *slog.Logger,
) int {
	total := 0
	for {
		expired, err := persistence.ExpirePendingMedia(ctx, cutoff, batchSize)
		if err != nil {
			observability.MediaCleanup.WithLabelValues("failed").Inc()
			logger.Error("media_pending_cleanup_failed", "error", err)
			return total
		}
		if expired == 0 {
			return total
		}
		total += expired
		observability.MediaCleanup.WithLabelValues("expired").Add(float64(expired))
		if expired < batchSize {
			return total
		}
	}
}
