package mail

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

type workerStore struct {
	store.Store
	mu           sync.Mutex
	batch        []domain.MailDelivery
	finishes     []workerFinish
	pruneCount   int64
	pruneArgs    []time.Time
	lockErr      error
	leaseErr     error
	finishErr    error
	retentionErr error
	claimed      map[uuid.UUID]domain.MailDelivery
}

type workerFinish struct {
	id, lease uuid.UUID
	result    string
	next      time.Time
	class     string
}

func (s *workerStore) LockMailDeliveryBatch(context.Context, int) ([]domain.MailDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockErr != nil {
		return nil, s.lockErr
	}
	batch := append([]domain.MailDelivery(nil), s.batch...)
	s.batch = nil
	if s.claimed == nil {
		s.claimed = make(map[uuid.UUID]domain.MailDelivery)
	}
	for _, delivery := range batch {
		s.claimed[delivery.ID] = delivery
	}
	return batch, nil
}

func (s *workerStore) WithMailDeliveryLease(
	ctx context.Context,
	id uuid.UUID,
	lease uuid.UUID,
	deliver func(context.Context, domain.MailDelivery) error,
) error {
	s.mu.Lock()
	if s.leaseErr != nil {
		err := s.leaseErr
		s.mu.Unlock()
		return err
	}
	delivery, found := s.claimed[id]
	if !found || delivery.LeaseToken != lease {
		s.mu.Unlock()
		return domain.ErrNotFound
	}
	delivery.Ciphertext = append([]byte(nil), delivery.Ciphertext...)
	s.mu.Unlock()
	return deliver(ctx, delivery)
}

func (s *workerStore) FinishMailDelivery(
	_ context.Context,
	id uuid.UUID,
	lease uuid.UUID,
	result string,
	next time.Time,
	class string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishes = append(s.finishes, workerFinish{id: id, lease: lease, result: result, next: next, class: class})
	return s.finishErr
}

func (s *workerStore) PruneMailDeliveries(
	_ context.Context,
	deliveredBefore, deadLetterBefore, canceledBefore time.Time,
	_ int,
) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneArgs = []time.Time{deliveredBefore, deadLetterBefore, canceledBefore}
	return s.pruneCount, s.retentionErr
}

type workerSender struct {
	mu         sync.Mutex
	to         string
	code       string
	ttl        time.Duration
	resetErr   error
	changedErr error
	resets     int
	changes    int
}

func (s *workerSender) SendPasswordReset(
	_ context.Context,
	to, code string,
	ttl time.Duration,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.to, s.code, s.ttl = to, code, ttl
	s.resets++
	return s.resetErr
}

func (s *workerSender) SendPasswordChanged(_ context.Context, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.to = to
	s.changes++
	return s.changedErr
}

func TestWorkerDecryptsDeliveryAndAcknowledgesSuccess(t *testing.T) {
	cipher := testQueueCipher(t)
	delivery, err := cipher.SealPasswordReset(
		uuid.New(), "person@example.com", "12345678", 10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	delivery.LeaseToken = uuid.New()
	delivery.Attempts = 1
	persistence := &workerStore{batch: []domain.MailDelivery{delivery}}
	sender := &workerSender{}
	worker := NewWorker(persistence, sender, cipher, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), DefaultDeliveryPolicy())
	worker.flush(context.Background())

	if sender.resets != 1 || sender.to != "person@example.com" ||
		sender.code != "12345678" || sender.ttl != 10*time.Minute {
		t.Fatalf("sender received unexpected payload: %+v", sender)
	}
	if len(persistence.finishes) != 1 || persistence.finishes[0].result != domain.MailDeliveryDelivered {
		t.Fatalf("finish=%+v", persistence.finishes)
	}
}

func TestWorkerRetriesWithBoundedJitterThenDeadLetters(t *testing.T) {
	cipher := testQueueCipher(t)
	delivery, err := cipher.SealPasswordReset(
		uuid.New(), "retry@example.com", "87654321", 10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	delivery.LeaseToken = uuid.New()
	delivery.Attempts = 1
	persistence := &workerStore{batch: []domain.MailDelivery{delivery}}
	sender := &workerSender{resetErr: &textproto.Error{Code: 451, Msg: "temporary"}}
	policy := DefaultDeliveryPolicy()
	policy.BaseDelay = 10 * time.Second
	policy.MaxDelay = 40 * time.Second
	fixedNow := time.Now().UTC()
	worker := NewWorker(persistence, sender, cipher, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), policy)
	worker.now = func() time.Time { return fixedNow }
	worker.flush(context.Background())
	if len(persistence.finishes) != 1 || persistence.finishes[0].result != domain.MailDeliveryPending ||
		persistence.finishes[0].class != "smtp_temporary" {
		t.Fatalf("retry finish=%+v", persistence.finishes)
	}
	delay := persistence.finishes[0].next.Sub(fixedNow)
	if delay < 5*time.Second || delay > 10*time.Second {
		t.Fatalf("retry jitter=%s, want 50-100%% of base", delay)
	}

	delivery.Attempts = policy.MaxAttempts
	delivery.LeaseToken = uuid.New()
	persistence.batch = []domain.MailDelivery{delivery}
	worker.flush(context.Background())
	if len(persistence.finishes) != 2 || persistence.finishes[1].result != domain.MailDeliveryDeadLetter {
		t.Fatalf("dead-letter finish=%+v", persistence.finishes)
	}

	delivery.Attempts = 100
	if got := worker.retryDelay(delivery); got < policy.MaxDelay/2 || got > policy.MaxDelay {
		t.Fatalf("capped jitter=%s", got)
	}
}

func TestWorkerDeadLettersInvalidCiphertextWithoutSending(t *testing.T) {
	cipher := testQueueCipher(t)
	delivery, err := cipher.SealPasswordChanged(uuid.New(), "changed@example.com")
	if err != nil {
		t.Fatal(err)
	}
	delivery.Ciphertext[len(delivery.Ciphertext)-1] ^= 0xff
	delivery.LeaseToken = uuid.New()
	delivery.Attempts = 1
	persistence := &workerStore{batch: []domain.MailDelivery{delivery}}
	sender := &workerSender{}
	worker := NewWorker(persistence, sender, cipher, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), DefaultDeliveryPolicy())
	worker.flush(context.Background())
	if sender.resets != 0 || sender.changes != 0 {
		t.Fatal("invalid encrypted payload reached SMTP sender")
	}
	if len(persistence.finishes) != 1 || persistence.finishes[0].result != domain.MailDeliveryDeadLetter ||
		persistence.finishes[0].class != "payload_invalid" {
		t.Fatalf("invalid-payload finish=%+v", persistence.finishes)
	}
}

func TestWorkerDropsInvalidatedLeaseBeforeDecryptingOrSending(t *testing.T) {
	cipher := testQueueCipher(t)
	delivery, err := cipher.SealPasswordReset(
		uuid.New(), "erased@example.com", "12345678", 10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	delivery.Ciphertext[len(delivery.Ciphertext)-1] ^= 0xff
	delivery.LeaseToken = uuid.New()
	delivery.Attempts = 1
	persistence := &workerStore{
		batch: []domain.MailDelivery{delivery}, leaseErr: domain.ErrNotFound,
	}
	sender := &workerSender{}
	worker := NewWorker(
		persistence, sender, cipher,
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), DefaultDeliveryPolicy(),
	)
	worker.flush(context.Background())
	if sender.resets != 0 || sender.changes != 0 {
		t.Fatal("invalidated mail lease reached the SMTP sender")
	}
	if len(persistence.finishes) != 0 {
		t.Fatalf("invalidated mail lease was acknowledged: %+v", persistence.finishes)
	}
}

func TestWorkerLogsNeverExposeMailOrTransportSecrets(t *testing.T) {
	cipher := testQueueCipher(t)
	recipient := "private-recipient@example.com"
	code := "11223344"
	credential := "smtp-password-must-not-leak"
	delivery, err := cipher.SealPasswordReset(uuid.New(), recipient, code, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	delivery.LeaseToken = uuid.New()
	delivery.Attempts = 1
	persistence := &workerStore{batch: []domain.MailDelivery{delivery}}
	sender := &workerSender{resetErr: errors.New(recipient + " " + code + " " + credential)}
	var logs bytes.Buffer
	worker := NewWorker(persistence, sender, cipher, slog.New(slog.NewJSONHandler(&logs, nil)), DefaultDeliveryPolicy())
	worker.flush(context.Background())
	text := logs.String()
	for _, forbidden := range []string{recipient, code, credential, base64.StdEncoding.EncodeToString(delivery.Ciphertext)} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("worker log exposed protected value: %s", text)
		}
	}
	if !strings.Contains(text, "error_class") || !strings.Contains(text, delivery.ID.String()) {
		t.Fatalf("worker log lacks safe correlation fields: %s", text)
	}
}

func TestWorkerRetentionUsesSeparateTerminalCutoffs(t *testing.T) {
	cipher := testQueueCipher(t)
	policy := DefaultDeliveryPolicy()
	policy.DeliveredRetention = 12 * time.Hour
	policy.DeadLetterRetention = 20 * 24 * time.Hour
	persistence := &workerStore{pruneCount: 3}
	worker := NewWorker(persistence, &workerSender{}, cipher, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), policy)
	now := time.Now().UTC()
	worker.now = func() time.Time { return now }
	worker.lastPrune = now.Add(-2 * time.Hour)
	worker.pruneRetention(context.Background())
	if len(persistence.pruneArgs) != 3 ||
		!persistence.pruneArgs[0].Equal(now.Add(-12*time.Hour)) ||
		!persistence.pruneArgs[1].Equal(now.Add(-20*24*time.Hour)) ||
		!persistence.pruneArgs[2].Equal(now.Add(-12*time.Hour)) {
		t.Fatalf("retention cutoffs=%v", persistence.pruneArgs)
	}
}

func TestWorkerClassifiesOnlyBoundedProviderIndependentErrors(t *testing.T) {
	for name, test := range map[string]struct {
		err       error
		class     string
		retryable bool
	}{
		"timeout":   {context.DeadlineExceeded, "timeout", true},
		"temporary": {&textproto.Error{Code: 451, Msg: "private provider text"}, "smtp_temporary", true},
		"rejected":  {&textproto.Error{Code: 550, Msg: "private provider text"}, "smtp_rejected", false},
		"identity":  {x509.HostnameError{Host: "private.example"}, "tls_identity", false},
		"unknown":   {errors.New("private transport text"), "transport", true},
	} {
		t.Run(name, func(t *testing.T) {
			class, retryable := classifyDeliveryError(test.err)
			if class != test.class || retryable != test.retryable || strings.Contains(class, "private") {
				t.Fatalf("classification=(%q,%t), want (%q,%t)", class, retryable, test.class, test.retryable)
			}
		})
	}
}
