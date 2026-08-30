package chores

import (
	"context"
	"log/slog"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
)

// RunRotationCleanup prunes one bounded cohort immediately and on every tick.
// Multiple replicas are safe because PostgreSQL claims rows with SKIP LOCKED.
// Failures leave rows durable and are retried at the next configured interval.
func RunRotationCleanup(ctx context.Context, persistence store.Store, interval time.Duration, batchSize int, logger *slog.Logger) {
	pruneRotationOperations(ctx, persistence, time.Now().UTC(), batchSize, logger)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pruneRotationOperations(ctx, persistence, time.Now().UTC(), batchSize, logger)
		}
	}
}

func pruneRotationOperations(ctx context.Context, persistence store.Store, cutoff time.Time, batchSize int, logger *slog.Logger) int {
	started := time.Now()
	deleted, err := persistence.PruneChoreRotationOperations(ctx, cutoff, batchSize)
	observability.ChoreRotationCleanupDuration.Observe(time.Since(started).Seconds())
	if err != nil {
		observability.ChoreRotationCleanupFailedRuns.Inc()
		logger.Error("chore_rotation_cleanup_failed", "error", err, "duration", time.Since(started))
		return 0
	}
	observability.ChoreRotationCleanupDeletedRows.Add(float64(deleted))
	logger.Info("chore_rotation_cleanup_completed", "deleted_rows", deleted, "duration", time.Since(started))
	return deleted
}
