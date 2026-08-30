package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/media"
	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/push"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

type Relay struct {
	store     store.Store
	bus       events.Bus
	logger    *slog.Logger
	push      push.Service
	media     media.Service
	policy    PushRetryPolicy
	now       func() time.Time
	lastPrune time.Time
}

type PushRetryPolicy struct {
	BatchSize           int
	WorkerConcurrency   int
	MaxAttempts         int
	BaseDelay           time.Duration
	MaxDelay            time.Duration
	DeliveredRetention  time.Duration
	DeadLetterRetention time.Duration
}

const (
	genericPushTitle = "Clixor"
	genericPushBody  = "You have new activity. Open the app to view it."
	genericPushKind  = "activity"
)

func DefaultPushRetryPolicy() PushRetryPolicy {
	return PushRetryPolicy{
		BatchSize: 100, WorkerConcurrency: 16, MaxAttempts: 8, BaseDelay: 2 * time.Second,
		MaxDelay: 15 * time.Minute, DeliveredRetention: 24 * time.Hour,
		DeadLetterRetention: 30 * 24 * time.Hour,
	}
}

func New(store store.Store, bus events.Bus, pushService push.Service, mediaService media.Service, logger *slog.Logger) *Relay {
	return NewWithPushRetryPolicy(store, bus, pushService, mediaService, logger, DefaultPushRetryPolicy())
}

func NewWithPushRetryPolicy(
	persistence store.Store,
	bus events.Bus,
	pushService push.Service,
	mediaService media.Service,
	logger *slog.Logger,
	policy PushRetryPolicy,
) *Relay {
	now := time.Now
	return &Relay{
		store: persistence, bus: bus, push: pushService, media: mediaService,
		logger: logger, policy: policy, now: now, lastPrune: now().UTC(),
	}
}

func (r *Relay) Run(ctx context.Context) {
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.flush(ctx)
			}
		}
	}()
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.flushPush(ctx)
				r.pruneRetention(ctx)
			}
		}
	}()
	workers.Wait()
}

func (r *Relay) flush(ctx context.Context) {
	batch, err := r.store.LockOutboxBatch(ctx, 100)
	if err != nil {
		observability.OutboxEvents.WithLabelValues("lock_failed").Inc()
		r.logger.Error("outbox_lock_failed", "error", err)
		return
	}
	published := make([]int64, 0, len(batch))
	for _, item := range batch {
		if item.Topic == "media.delete" {
			if err := r.deleteMedia(ctx, item); err != nil {
				observability.OutboxEvents.WithLabelValues("media_delete_failed").Inc()
				r.logger.Error("outbox_media_delete_failed", "error", err, "outbox_id", item.ID)
				continue
			}
			observability.OutboxEvents.WithLabelValues("published").Inc()
			observability.OutboxLag.Observe(time.Since(item.CreatedAt).Seconds())
			published = append(published, item.ID)
			continue
		}
		event, recipients, ok := r.translate(ctx, item)
		if !ok {
			observability.OutboxEvents.WithLabelValues("translate_failed").Inc()
			continue
		}
		if err := r.enqueuePush(ctx, item, recipients); err != nil {
			observability.PushDeliveries.WithLabelValues("queue_failed").Inc()
			r.logger.Error("push_queue_failed", "error", err, "outbox_id", item.ID)
			continue
		}
		if err := r.bus.Publish(ctx, recipients, event); err != nil {
			observability.OutboxEvents.WithLabelValues("publish_failed").Inc()
			r.logger.Error("outbox_publish_failed", "error", err, "outbox_id", item.ID)
			continue
		}
		observability.OutboxEvents.WithLabelValues("published").Inc()
		observability.OutboxLag.Observe(time.Since(item.CreatedAt).Seconds())
		published = append(published, item.ID)
	}
	if len(published) > 0 {
		if err := r.store.MarkOutboxPublished(ctx, published); err != nil {
			r.logger.Error("outbox_ack_failed", "error", err)
		}
	}
}

func (r *Relay) deleteMedia(ctx context.Context, item domain.OutboxEvent) error {
	var payload store.MediaDeletePayload
	if err := json.Unmarshal(item.Payload, &payload); err != nil {
		return fmt.Errorf("decode media deletion: %w", err)
	}
	if len(payload.ObjectKeys) == 0 || len(payload.ObjectKeys) > store.MediaDeleteBatchSize {
		return fmt.Errorf("invalid media deletion object count: %d", len(payload.ObjectKeys))
	}
	for _, objectKey := range payload.ObjectKeys {
		if strings.TrimSpace(objectKey) == "" {
			return fmt.Errorf("invalid empty media object key")
		}
		if err := r.media.Delete(ctx, objectKey); err != nil {
			return fmt.Errorf("delete media object %q: %w", objectKey, err)
		}
	}
	return nil
}

func (r *Relay) enqueuePush(ctx context.Context, item domain.OutboxEvent, recipients []uuid.UUID) error {
	notification, ok, err := r.notificationFor(ctx, item, recipients)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	pushRecipients := make([]uuid.UUID, 0, len(recipients))
	for _, userID := range recipients {
		if userID == notification.actorID {
			continue
		}
		pushRecipients = append(pushRecipients, userID)
	}
	inserted, err := r.store.EnqueuePushDeliveries(ctx, domain.PushDelivery{
		OutboxEventID: item.ID,
		Title:         notification.title, Body: notification.body, Kind: notification.kind,
		ConversationID: notification.conversationID, EntityID: notification.entityID,
		NotificationID: notification.entityID.String(),
	}, pushRecipients)
	if err != nil {
		return err
	}
	if inserted > 0 {
		observability.PushDeliveries.WithLabelValues("queued").Add(float64(inserted))
	}
	return nil
}

func (r *Relay) flushPush(ctx context.Context) {
	if push.IsDisabled(r.push) {
		// Keep queued work pending when APNs credentials are intentionally absent.
		// A later process with a configured provider can claim the same durable
		// rows; treating Disabled.Send's no-op as success would lose them forever.
		return
	}
	limit := min(r.policy.BatchSize, r.policy.WorkerConcurrency)
	if limit < 1 {
		limit = 1
	}
	batch, err := r.store.LockPushDeliveryBatch(ctx, limit)
	if err != nil {
		observability.PushDeliveries.WithLabelValues("lock_failed").Inc()
		r.logger.Error("push_delivery_lock_failed", "error", err)
		return
	}
	var workers sync.WaitGroup
	workers.Add(len(batch))
	for _, delivery := range batch {
		delivery := delivery
		go func() {
			defer workers.Done()
			r.deliverPush(ctx, delivery)
		}()
	}
	workers.Wait()
}

func (r *Relay) deliverPush(ctx context.Context, delivery domain.PushDelivery) {
	if strings.TrimSpace(delivery.PushToken) == "" {
		if err := r.store.FinishPushDelivery(
			ctx, delivery.ID, delivery.LeaseToken, domain.PushDeliveryCanceled,
			time.Time{}, "token_missing",
		); err != nil {
			r.logger.Error("push_delivery_cancel_failed", "error", err, "delivery_id", delivery.ID)
			return
		}
		observability.PushDeliveries.WithLabelValues("canceled").Inc()
		return
	}
	err := r.push.Send(
		ctx, delivery.PushToken, genericPushTitle, genericPushBody,
		map[string]string{"type": genericPushKind},
		delivery.NotificationID,
	)
	if err == nil {
		if finishErr := r.store.FinishPushDelivery(
			ctx, delivery.ID, delivery.LeaseToken, domain.PushDeliveryDelivered,
			time.Time{}, "",
		); finishErr != nil {
			r.logger.Error("push_delivery_ack_failed", "error", finishErr, "delivery_id", delivery.ID)
			return
		}
		observability.PushDeliveries.WithLabelValues("delivered").Inc()
		observability.PushDeliveryLag.Observe(r.now().UTC().Sub(delivery.CreatedAt).Seconds())
		return
	}

	observability.PushFailures.Inc()
	errorClass := push.ErrorClass(err)
	observability.PushDeliveryFailures.WithLabelValues(errorClass).Inc()
	// Never log a token or APNs response body; the bounded error class and
	// identifiers are sufficient to operate the retry queue.
	r.logger.Error(
		"push_send_failed", "error_class", errorClass,
		"delivery_id", delivery.ID, "device_id", delivery.DeviceID,
		"attempt", delivery.Attempts,
	)
	if push.IsInvalidToken(err) {
		if invalidateErr := r.store.InvalidatePushDelivery(
			ctx, delivery.ID, delivery.LeaseToken, delivery.UserID,
			delivery.DeviceID, delivery.PushToken,
		); invalidateErr != nil {
			r.logger.Error(
				"push_token_invalidate_failed", "error", invalidateErr,
				"delivery_id", delivery.ID, "device_id", delivery.DeviceID,
			)
			return
		}
		observability.PushDeliveries.WithLabelValues("invalid_token").Inc()
		return
	}

	if ctx.Err() != nil {
		// A graceful shutdown releases the lease immediately instead of waiting
		// two minutes or incorrectly dead-lettering the delivery.
		releaseContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.store.FinishPushDelivery(
			releaseContext, delivery.ID, delivery.LeaseToken,
			domain.PushDeliveryPending, r.now().UTC(), "shutdown",
		)
		return
	}
	if !push.IsRetryable(err) || delivery.Attempts >= r.policy.MaxAttempts {
		if finishErr := r.store.FinishPushDelivery(
			ctx, delivery.ID, delivery.LeaseToken, domain.PushDeliveryDeadLetter,
			time.Time{}, errorClass,
		); finishErr != nil {
			r.logger.Error("push_dead_letter_failed", "error", finishErr, "delivery_id", delivery.ID)
			return
		}
		observability.PushDeliveries.WithLabelValues("dead_letter").Inc()
		return
	}
	nextAttempt := r.now().UTC().Add(r.retryDelay(delivery))
	if finishErr := r.store.FinishPushDelivery(
		ctx, delivery.ID, delivery.LeaseToken, domain.PushDeliveryPending,
		nextAttempt, errorClass,
	); finishErr != nil {
		r.logger.Error("push_retry_schedule_failed", "error", finishErr, "delivery_id", delivery.ID)
		return
	}
	observability.PushDeliveries.WithLabelValues("retry_scheduled").Inc()
}

func (r *Relay) retryDelay(delivery domain.PushDelivery) time.Duration {
	delay := r.policy.BaseDelay
	for attempt := 1; attempt < delivery.Attempts && delay < r.policy.MaxDelay; attempt++ {
		if delay > r.policy.MaxDelay/2 {
			delay = r.policy.MaxDelay
			break
		}
		delay *= 2
	}
	if delay > r.policy.MaxDelay {
		delay = r.policy.MaxDelay
	}
	if delay <= 0 {
		return 0
	}
	// Stable 50-100% jitter spreads a provider recovery surge without making
	// delivery tests probabilistic.
	seed := uint64(delivery.ID)*1103515245 + uint64(delivery.Attempts)*12345
	return delay/2 + time.Duration(seed%501)*delay/1000
}

func (r *Relay) pruneRetention(ctx context.Context) {
	now := r.now().UTC()
	if now.Sub(r.lastPrune) < time.Hour {
		return
	}
	r.lastPrune = now
	pushDeleted, err := r.store.PrunePushDeliveries(
		ctx, now.Add(-r.policy.DeliveredRetention), now.Add(-r.policy.DeadLetterRetention),
		store.MaxRetentionPruneBatchSize,
	)
	if err != nil {
		observability.PushDeliveries.WithLabelValues("prune_failed").Inc()
		r.logger.Error("push_delivery_prune_failed", "error", err)
	} else if pushDeleted > 0 {
		observability.PushDeliveries.WithLabelValues("pruned").Add(float64(pushDeleted))
	}

	// Source rows outlive both terminal push retention windows. A source with a
	// pending or retained terminal delivery is protected again by the store's
	// no-child predicate and foreign key, including during concurrent pruning.
	outboxRetention := max(r.policy.DeliveredRetention, r.policy.DeadLetterRetention)
	outboxDeleted, err := r.store.PrunePublishedOutbox(
		ctx, now.Add(-outboxRetention), store.MaxRetentionPruneBatchSize,
	)
	if err != nil {
		observability.OutboxEvents.WithLabelValues("prune_failed").Inc()
		r.logger.Error("outbox_prune_failed", "error", err)
	} else if outboxDeleted > 0 {
		observability.OutboxEvents.WithLabelValues("pruned").Add(float64(outboxDeleted))
	}
}

type activityNotification struct {
	actorID        uuid.UUID
	conversationID uuid.UUID
	entityID       uuid.UUID
	kind           string
	title          string
	body           string
}

func (r *Relay) notificationFor(
	ctx context.Context,
	item domain.OutboxEvent,
	recipients []uuid.UUID,
) (activityNotification, bool, error) {
	switch item.Topic {
	case "message.created":
		var message domain.Message
		if json.Unmarshal(item.Payload, &message) != nil {
			return activityNotification{}, false, nil
		}
		conversation, err := r.conversationFor(ctx, message.ConversationID, message.SenderID, recipients)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrForbidden) {
				return activityNotification{}, false, nil
			}
			return activityNotification{}, false, err
		}
		return activityNotification{
			actorID: message.SenderID, conversationID: message.ConversationID,
			entityID: message.ID, kind: "message", title: conversationTitle(conversation),
			// Message ciphertext is end-to-end encrypted, so the server deliberately
			// uses privacy-safe copy instead of attempting to expose a preview.
			body: clip(displayName(r, ctx, message.SenderID)+" sent a message", 180),
		}, true, nil

	case "entity.updated":
		var entity domain.Entity
		if json.Unmarshal(item.Payload, &entity) != nil || entity.Version != 1 {
			return activityNotification{}, false, nil
		}
		if entity.Kind != "expense" && entity.Kind != "task" {
			return activityNotification{}, false, nil
		}
		conversation, err := r.conversationFor(ctx, entity.ConversationID, entity.CreatedBy, recipients)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrForbidden) {
				return activityNotification{}, false, nil
			}
			return activityNotification{}, false, err
		}
		payload := decodedObject(entity.Payload)
		// A subscription-pod create emits its own durable event immediately
		// before its initial charge. Suppress that initial expense to avoid two
		// alerts for one user action; later subscription expenses still notify.
		if entity.Kind == "expense" && isSubscription(conversation) &&
			entity.CreatedAt.Sub(conversation.CreatedAt) >= 0 &&
			entity.CreatedAt.Sub(conversation.CreatedAt) < 10*time.Minute &&
			isInitialSubscriptionCharge(conversation, payload) {
			return activityNotification{}, false, nil
		}
		actor := displayName(r, ctx, entity.CreatedBy)
		body := ""
		if entity.Kind == "expense" {
			description := firstString(payload, "description", "title", "name")
			if description == "" {
				description = "an expense"
			}
			amount := formattedAmount(payload["amount"])
			body = actor + " added " + description
			if amount != "" {
				body += " (" + amount + ")"
			}
		} else {
			title := firstString(payload, "title", "name")
			if title == "" {
				title = "a task"
			}
			body = actor + " created a task: " + title
		}
		return activityNotification{
			actorID: entity.CreatedBy, conversationID: entity.ConversationID,
			entityID: entity.ID, kind: entity.Kind, title: conversationTitle(conversation),
			body: clip(body, 180),
		}, true, nil

	case "conversation.created":
		var conversation domain.Conversation
		if json.Unmarshal(item.Payload, &conversation) != nil || !isSubscription(conversation) {
			return activityNotification{}, false, nil
		}
		return subscriptionNotification(
			conversation, conversation.CreatedBy, conversation.ID,
			displayName(r, ctx, conversation.CreatedBy),
		), true, nil

	case "conversation.member_added":
		var added domain.ConversationMemberAdded
		if json.Unmarshal(item.Payload, &added) != nil {
			return activityNotification{}, false, nil
		}
		conversation, err := r.conversationFor(ctx, added.ConversationID, added.ActorID, recipients)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrForbidden) {
				return activityNotification{}, false, nil
			}
			return activityNotification{}, false, err
		}
		if !isSubscription(conversation) {
			return activityNotification{}, false, nil
		}
		return subscriptionNotification(
			conversation, added.ActorID, conversation.ID,
			displayName(r, ctx, added.ActorID),
		), true, nil
	default:
		return activityNotification{}, false, nil
	}
}

func (r *Relay) conversationFor(
	ctx context.Context,
	conversationID, actorID uuid.UUID,
	recipients []uuid.UUID,
) (domain.Conversation, error) {
	candidates := make([]uuid.UUID, 0, len(recipients)+1)
	candidates = append(candidates, actorID)
	candidates = append(candidates, recipients...)
	seen := make(map[uuid.UUID]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == uuid.Nil {
			continue
		}
		if _, duplicate := seen[candidate]; duplicate {
			continue
		}
		seen[candidate] = struct{}{}
		conversation, err := r.store.Conversation(ctx, conversationID, candidate)
		if err == nil {
			return conversation, nil
		}
		if !errors.Is(err, domain.ErrNotFound) && !errors.Is(err, domain.ErrForbidden) {
			return domain.Conversation{}, fmt.Errorf("load notification conversation %s: %w", conversationID, err)
		}
	}
	return domain.Conversation{}, domain.ErrNotFound
}

func subscriptionNotification(
	conversation domain.Conversation,
	actorID, entityID uuid.UUID,
	actor string,
) activityNotification {
	groupName := strings.TrimSpace(conversation.Title)
	if groupName == "" {
		groupName = "a subscription"
	}
	return activityNotification{
		actorID: actorID, conversationID: conversation.ID, entityID: entityID,
		kind: "subscription", title: "Subscription",
		body: clip(actor+" added "+groupName, 180),
	}
}

func displayName(r *Relay, ctx context.Context, userID uuid.UUID) string {
	user, err := r.store.UserByID(ctx, userID)
	if err != nil || strings.TrimSpace(user.DisplayName) == "" {
		return "Someone"
	}
	return clip(strings.TrimSpace(user.DisplayName), 80)
}

func conversationTitle(conversation domain.Conversation) string {
	if title := strings.TrimSpace(conversation.Title); title != "" {
		return clip(title, 100)
	}
	return "Clixor"
}

func isSubscription(conversation domain.Conversation) bool {
	metadata := decodedObject(conversation.Metadata)
	return strings.EqualFold(firstString(metadata, "type"), "subscriptions")
}

func isInitialSubscriptionCharge(conversation domain.Conversation, payload map[string]any) bool {
	description := strings.ToLower(firstString(payload, "description"))
	if description == "" {
		return false
	}
	groupName := strings.ToLower(strings.TrimSpace(conversation.Title))
	if groupName != "" && !strings.HasPrefix(description, groupName) {
		return false
	}
	return strings.Contains(description, "subscription") || strings.Contains(description, "membership")
}

func decodedObject(raw json.RawMessage) map[string]any {
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	return object
}

func firstString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := object[key].(string); ok && strings.TrimSpace(value) != "" {
			return clip(strings.TrimSpace(value), 100)
		}
	}
	return ""
}

func formattedAmount(value any) string {
	var amount float64
	switch typed := value.(type) {
	case float64:
		amount = typed
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return ""
		}
		amount = parsed
	default:
		return ""
	}
	return fmt.Sprintf("$%.2f", amount)
}

func clip(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit-1]) + "…"
}

func (r *Relay) translate(ctx context.Context, item domain.OutboxEvent) (domain.RealtimeEvent, []uuid.UUID, bool) {
	var event domain.RealtimeEvent
	switch item.Topic {
	case "message.created":
		var message domain.Message
		if err := json.Unmarshal(item.Payload, &message); err != nil {
			r.logger.Error("outbox_payload_invalid", "error", err, "outbox_id", item.ID)
			return domain.RealtimeEvent{}, nil, false
		}
		event = domain.RealtimeEvent{
			ID: message.ID.String(), Type: item.Topic, ConversationID: &message.ConversationID,
			Seq: message.Seq, Payload: item.Payload, OccurredAt: item.CreatedAt,
		}
	case "receipt.updated":
		var receipt domain.Receipt
		if err := json.Unmarshal(item.Payload, &receipt); err != nil {
			r.logger.Error("outbox_payload_invalid", "error", err, "outbox_id", item.ID)
			return domain.RealtimeEvent{}, nil, false
		}
		event = domain.RealtimeEvent{
			ID: fmt.Sprintf("receipt:%s:%s:%d:%d", receipt.ConversationID, receipt.UserID,
				receipt.DeliveredSeq, receipt.ReadSeq),
			Type: item.Topic, ConversationID: &receipt.ConversationID,
			Seq: max(receipt.DeliveredSeq, receipt.ReadSeq), Payload: item.Payload,
			OccurredAt: item.CreatedAt,
		}
	case "entity.updated", "entity.deleted":
		var entity domain.Entity
		if err := json.Unmarshal(item.Payload, &entity); err != nil {
			r.logger.Error("outbox_payload_invalid", "error", err, "outbox_id", item.ID)
			return domain.RealtimeEvent{}, nil, false
		}
		event = domain.RealtimeEvent{
			ID:   fmt.Sprintf("%s:%s:%d", item.Topic, entity.ID, entity.Version),
			Type: item.Topic, ConversationID: &entity.ConversationID, Seq: entity.Version,
			Payload: item.Payload, OccurredAt: item.CreatedAt,
		}
	case "conversation.created":
		var conversation domain.Conversation
		if err := json.Unmarshal(item.Payload, &conversation); err != nil {
			r.logger.Error("outbox_payload_invalid", "error", err, "outbox_id", item.ID)
			return domain.RealtimeEvent{}, nil, false
		}
		event = domain.RealtimeEvent{
			ID: conversation.ID.String(), Type: item.Topic, ConversationID: &conversation.ID,
			Payload: item.Payload, OccurredAt: item.CreatedAt,
		}
	case "conversation.member_added":
		var added domain.ConversationMemberAdded
		if err := json.Unmarshal(item.Payload, &added); err != nil {
			r.logger.Error("outbox_payload_invalid", "error", err, "outbox_id", item.ID)
			return domain.RealtimeEvent{}, nil, false
		}
		event = domain.RealtimeEvent{
			ID:   fmt.Sprintf("member-added:%s:%s", added.ConversationID, added.UserID),
			Type: item.Topic, ConversationID: &added.ConversationID,
			Payload: item.Payload, OccurredAt: item.CreatedAt,
		}
	default:
		r.logger.Warn("outbox_topic_unknown", "topic", item.Topic, "outbox_id", item.ID)
		return domain.RealtimeEvent{}, nil, false
	}
	recipients, err := r.store.ConversationMemberIDs(ctx, item.AggregateID)
	if err != nil {
		r.logger.Error("outbox_members_failed", "error", err, "outbox_id", item.ID)
		return domain.RealtimeEvent{}, nil, false
	}
	return event, recipients, true
}
