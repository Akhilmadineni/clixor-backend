package mail

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/textproto"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
)

type DeliveryPolicy struct {
	BatchSize           int
	WorkerConcurrency   int
	MaxAttempts         int
	BaseDelay           time.Duration
	MaxDelay            time.Duration
	DeliveredRetention  time.Duration
	DeadLetterRetention time.Duration
}

type Worker struct {
	store           store.Store
	sender          Service
	cipher          *QueueCipher
	logger          *slog.Logger
	policy          DeliveryPolicy
	now             func() time.Time
	lastPrune       time.Time
	deliveryTimeout time.Duration
}

const mailDeliveryTimeout = 15 * time.Second

var (
	errMailPayloadInvalid = errors.New("mail payload invalid")
	errMailPurposeInvalid = errors.New("mail purpose invalid")
)

func DefaultDeliveryPolicy() DeliveryPolicy {
	return DeliveryPolicy{
		BatchSize: 50, WorkerConcurrency: 4, MaxAttempts: 8,
		BaseDelay: 5 * time.Second, MaxDelay: 30 * time.Minute,
		DeliveredRetention: 24 * time.Hour, DeadLetterRetention: 30 * 24 * time.Hour,
	}
}

func NewWorker(
	persistence store.Store,
	sender Service,
	cipher *QueueCipher,
	logger *slog.Logger,
	policy DeliveryPolicy,
) *Worker {
	now := time.Now
	return &Worker{
		store: persistence, sender: sender, cipher: cipher, logger: logger,
		policy: policy, now: now, lastPrune: now().UTC(), deliveryTimeout: mailDeliveryTimeout,
	}
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.flush(ctx)
			w.pruneRetention(ctx)
		}
	}
}

func (w *Worker) flush(ctx context.Context) {
	limit := min(w.policy.BatchSize, w.policy.WorkerConcurrency)
	if limit < 1 {
		limit = 1
	}
	batch, err := w.store.LockMailDeliveryBatch(ctx, limit)
	if err != nil {
		observability.MailDeliveries.WithLabelValues("lock_failed").Inc()
		w.logger.Error("mail_delivery_lock_failed", "error_class", "storage")
		return
	}
	var workers sync.WaitGroup
	workers.Add(len(batch))
	for _, delivery := range batch {
		delivery := delivery
		go func() {
			defer workers.Done()
			w.deliver(ctx, delivery)
		}()
	}
	workers.Wait()
}

func (w *Worker) deliver(ctx context.Context, delivery domain.MailDelivery) {
	callbackInvoked := false
	err := w.store.WithMailDeliveryLease(
		ctx, delivery.ID, delivery.LeaseToken,
		func(leaseContext context.Context, leased domain.MailDelivery) error {
			callbackInvoked = true
			delivery = leased
			payload, err := w.cipher.open(leased)
			if err != nil {
				return errMailPayloadInvalid
			}
			sendContext, cancel := context.WithTimeout(leaseContext, w.deliveryTimeout)
			defer cancel()
			switch payload.Purpose {
			case domain.MailDeliveryPasswordReset:
				return w.sender.SendPasswordReset(
					sendContext, payload.Recipient, payload.Code,
					time.Duration(payload.TTLSeconds)*time.Second,
				)
			case domain.MailDeliveryPasswordChanged:
				return w.sender.SendPasswordChanged(sendContext, payload.Recipient)
			default:
				return errMailPurposeInvalid
			}
		},
	)
	// A batch claim is only a scheduling hint. Cancellation, challenge
	// consumption, or account erasure may remove the exact row before the
	// delivery barrier is acquired; never decrypt or send that stale payload.
	if !callbackInvoked && (errors.Is(err, domain.ErrNotFound) ||
		errors.Is(err, domain.ErrConflict)) {
		return
	}
	if errors.Is(err, errMailPayloadInvalid) {
		w.finishDeadLetter(ctx, delivery, "payload_invalid")
		return
	}
	if errors.Is(err, errMailPurposeInvalid) {
		w.finishDeadLetter(ctx, delivery, "purpose_invalid")
		return
	}
	if err == nil {
		if finishErr := w.store.FinishMailDelivery(
			ctx, delivery.ID, delivery.LeaseToken, domain.MailDeliveryDelivered,
			time.Time{}, "",
		); finishErr != nil {
			w.logger.Error(
				"mail_delivery_ack_failed", "delivery_id", delivery.ID,
				"error_class", "storage",
			)
			return
		}
		observability.MailDeliveries.WithLabelValues("delivered").Inc()
		observability.MailDeliveryLag.Observe(
			max(0, w.now().UTC().Sub(delivery.CreatedAt).Seconds()),
		)
		return
	}

	if ctx.Err() != nil {
		releaseContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.store.FinishMailDelivery(
			releaseContext, delivery.ID, delivery.LeaseToken,
			domain.MailDeliveryPending, w.now().UTC(), "shutdown",
		)
		return
	}
	errorClass, retryable := classifyDeliveryError(err)
	// Never log err: SMTP responses are untrusted and can contain the recipient;
	// the encrypted payload contains all other sensitive mail inputs. Bounded
	// classes and opaque delivery IDs are sufficient for operations.
	w.logger.Error(
		"mail_send_failed", "delivery_id", delivery.ID,
		"attempt", delivery.Attempts, "error_class", errorClass,
	)
	observability.MailDeliveryFailures.WithLabelValues(errorClass).Inc()
	if !retryable || delivery.Attempts >= w.policy.MaxAttempts {
		w.finishDeadLetter(ctx, delivery, errorClass)
		return
	}
	nextAttempt := w.now().UTC().Add(w.retryDelay(delivery))
	if finishErr := w.store.FinishMailDelivery(
		ctx, delivery.ID, delivery.LeaseToken, domain.MailDeliveryPending,
		nextAttempt, errorClass,
	); finishErr != nil {
		w.logger.Error(
			"mail_retry_schedule_failed", "delivery_id", delivery.ID,
			"error_class", "storage",
		)
		return
	}
	observability.MailDeliveries.WithLabelValues("retry_scheduled").Inc()
}

func (w *Worker) finishDeadLetter(
	ctx context.Context,
	delivery domain.MailDelivery,
	errorClass string,
) {
	if err := w.store.FinishMailDelivery(
		ctx, delivery.ID, delivery.LeaseToken, domain.MailDeliveryDeadLetter,
		time.Time{}, errorClass,
	); err != nil {
		w.logger.Error(
			"mail_dead_letter_failed", "delivery_id", delivery.ID,
			"error_class", "storage",
		)
		return
	}
	observability.MailDeliveries.WithLabelValues("dead_letter").Inc()
}

func (w *Worker) retryDelay(delivery domain.MailDelivery) time.Duration {
	delay := w.policy.BaseDelay
	for attempt := 1; attempt < delivery.Attempts && delay < w.policy.MaxDelay; attempt++ {
		if delay > w.policy.MaxDelay/2 {
			delay = w.policy.MaxDelay
			break
		}
		delay *= 2
	}
	if delay > w.policy.MaxDelay {
		delay = w.policy.MaxDelay
	}
	if delay <= 0 {
		return 0
	}
	seed := binary.BigEndian.Uint64(delivery.ID[:8]) + uint64(delivery.Attempts)*1103515245
	// Stable 50-100% jitter spreads provider recovery without probabilistic tests.
	return delay/2 + time.Duration(seed%501)*delay/1000
}

func (w *Worker) pruneRetention(ctx context.Context) {
	now := w.now().UTC()
	if now.Sub(w.lastPrune) < time.Hour {
		return
	}
	w.lastPrune = now
	deleted, err := w.store.PruneMailDeliveries(
		ctx, now.Add(-w.policy.DeliveredRetention), now.Add(-w.policy.DeadLetterRetention),
		now.Add(-w.policy.DeliveredRetention), store.MaxRetentionPruneBatchSize,
	)
	if err != nil {
		observability.MailDeliveries.WithLabelValues("prune_failed").Inc()
		w.logger.Error("mail_delivery_prune_failed", "error_class", "storage")
		return
	}
	if deleted > 0 {
		observability.MailDeliveries.WithLabelValues("pruned").Add(float64(deleted))
	}
}

func classifyDeliveryError(err error) (string, bool) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout", true
	}
	var certificateInvalid x509.CertificateInvalidError
	var hostnameInvalid x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &certificateInvalid) || errors.As(err, &hostnameInvalid) ||
		errors.As(err, &unknownAuthority) {
		return "tls_identity", false
	}
	var protocolError *textproto.Error
	if errors.As(err, &protocolError) {
		if protocolError.Code >= 400 && protocolError.Code < 500 {
			return "smtp_temporary", true
		}
		return "smtp_rejected", false
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return "network", true
	}
	return "transport", true
}
