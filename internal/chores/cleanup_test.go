package chores

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/store/memory"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type cleanupResponse struct {
	deleted int
	err     error
}

type cleanupInvocation struct {
	cutoff    time.Time
	batchSize int
	call      int
}

type cleanupTestStore struct {
	*memory.Store

	mu                sync.Mutex
	responses         []cleanupResponse
	calls             chan cleanupInvocation
	nextCall          int
	blockCall         int
	release           <-chan struct{}
	untilCanceledCall int
}

func newCleanupTestStore(responses ...cleanupResponse) *cleanupTestStore {
	return &cleanupTestStore{
		Store: memory.New(), responses: responses, calls: make(chan cleanupInvocation, 8),
	}
}

func (s *cleanupTestStore) PruneChoreRotationOperations(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	s.mu.Lock()
	s.nextCall++
	call := s.nextCall
	response := cleanupResponse{}
	if call <= len(s.responses) {
		response = s.responses[call-1]
	}
	blockCall, release := s.blockCall, s.release
	untilCanceledCall := s.untilCanceledCall
	s.mu.Unlock()

	s.calls <- cleanupInvocation{cutoff: cutoff, batchSize: batchSize, call: call}
	if call == untilCanceledCall {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if call == blockCall {
		<-release
	}
	return response.deleted, response.err
}

func TestRunRotationCleanupRunsImmediatelyAndStopsOnCancellation(t *testing.T) {
	persistence := newCleanupTestStore(cleanupResponse{deleted: 2})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	deletedBefore := cleanupCounterValue(t, observability.ChoreRotationCleanupDeletedRows)
	failedBefore := cleanupCounterValue(t, observability.ChoreRotationCleanupFailedRuns)
	started := time.Now().UTC()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunRotationCleanup(ctx, persistence, time.Hour, 17, logger)
	}()

	invocation := waitForCleanupInvocation(t, persistence.calls)
	if invocation.call != 1 || invocation.batchSize != 17 {
		t.Fatalf("immediate invocation = %+v", invocation)
	}
	if invocation.cutoff.Before(started) || invocation.cutoff.After(time.Now().UTC()) {
		t.Fatalf("immediate cutoff %s is outside worker run", invocation.cutoff)
	}
	cancel()
	waitForCleanupWorker(t, done)
	assertNoCleanupInvocation(t, persistence.calls)

	if delta := cleanupCounterValue(t, observability.ChoreRotationCleanupDeletedRows) - deletedBefore; delta != 2 {
		t.Fatalf("deleted-row metric delta = %v, want 2", delta)
	}
	if delta := cleanupCounterValue(t, observability.ChoreRotationCleanupFailedRuns) - failedBefore; delta != 0 {
		t.Fatalf("failed-run metric delta = %v, want 0", delta)
	}
	output := logs.String()
	if !strings.Contains(output, "msg=chore_rotation_cleanup_completed") || !strings.Contains(output, "deleted_rows=2") {
		t.Fatalf("completion log lacks stable event/row fields: %s", output)
	}
}

func TestRunRotationCleanupRetriesOnCadenceAndEmitsUnambiguousTelemetry(t *testing.T) {
	release := make(chan struct{})
	persistence := newCleanupTestStore(
		cleanupResponse{err: errors.New("forced cleanup failure")},
		cleanupResponse{deleted: 3},
	)
	persistence.blockCall, persistence.release = 2, release
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	deletedBefore := cleanupCounterValue(t, observability.ChoreRotationCleanupDeletedRows)
	failedBefore := cleanupCounterValue(t, observability.ChoreRotationCleanupFailedRuns)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunRotationCleanup(ctx, persistence, 200*time.Millisecond, 23, logger)
	}()

	first := waitForCleanupInvocation(t, persistence.calls)
	second := waitForCleanupInvocation(t, persistence.calls)
	if first.call != 1 || second.call != 2 || first.batchSize != 23 || second.batchSize != 23 {
		t.Fatalf("retry invocations = first %+v second %+v", first, second)
	}
	// Cancel while the second call is held so no later tick can race worker exit;
	// releasing it then proves the successful retry is observed before shutdown.
	cancel()
	close(release)
	waitForCleanupWorker(t, done)
	assertNoCleanupInvocation(t, persistence.calls)

	if delta := cleanupCounterValue(t, observability.ChoreRotationCleanupDeletedRows) - deletedBefore; delta != 3 {
		t.Fatalf("deleted-row metric delta = %v, want 3", delta)
	}
	if delta := cleanupCounterValue(t, observability.ChoreRotationCleanupFailedRuns) - failedBefore; delta != 1 {
		t.Fatalf("failed-run metric delta = %v, want 1", delta)
	}
	output := logs.String()
	for _, field := range []string{
		"msg=chore_rotation_cleanup_failed", "error=\"forced cleanup failure\"",
		"msg=chore_rotation_cleanup_completed", "deleted_rows=3",
	} {
		if !strings.Contains(output, field) {
			t.Fatalf("cleanup logs lack %q: %s", field, output)
		}
	}
	assertCleanupMetricName(t, observability.ChoreRotationCleanupDeletedRows,
		"clustr_chores_rotation_cleanup_deleted_rows_total")
	assertCleanupMetricName(t, observability.ChoreRotationCleanupFailedRuns,
		"clustr_chores_rotation_cleanup_failed_runs_total")
}

func TestRunRotationCleanupCancellationInterruptsStoreWithoutLeakingWorker(t *testing.T) {
	persistence := newCleanupTestStore()
	persistence.untilCanceledCall = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunRotationCleanup(ctx, persistence, time.Hour, 5, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	}()

	invocation := waitForCleanupInvocation(t, persistence.calls)
	if invocation.call != 1 {
		t.Fatalf("blocking invocation = %+v", invocation)
	}
	cancel()
	waitForCleanupWorker(t, done)
	assertNoCleanupInvocation(t, persistence.calls)
}

func waitForCleanupInvocation(t *testing.T, calls <-chan cleanupInvocation) cleanupInvocation {
	t.Helper()
	select {
	case invocation := <-calls:
		return invocation
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cleanup invocation")
		return cleanupInvocation{}
	}
}

func waitForCleanupWorker(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup worker did not exit after cancellation")
	}
}

func assertNoCleanupInvocation(t *testing.T, calls <-chan cleanupInvocation) {
	t.Helper()
	select {
	case invocation := <-calls:
		t.Fatalf("cleanup worker invoked store after shutdown: %+v", invocation)
	default:
	}
}

func cleanupCounterValue(t *testing.T, metric prometheus.Metric) float64 {
	t.Helper()
	var value dto.Metric
	if err := metric.Write(&value); err != nil {
		t.Fatal(err)
	}
	return value.GetCounter().GetValue()
}

func assertCleanupMetricName(t *testing.T, collector prometheus.Collector, name string) {
	t.Helper()
	descriptions := make(chan *prometheus.Desc, 1)
	collector.Describe(descriptions)
	description := <-descriptions
	if !strings.Contains(description.String(), `fqName: "`+name+`"`) {
		t.Fatalf("metric description %s does not contain %q", description, name)
	}
}
