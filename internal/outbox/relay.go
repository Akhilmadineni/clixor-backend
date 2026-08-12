package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/events"
	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/push"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

type Relay struct {
	store  store.Store
	bus    events.Bus
	logger *slog.Logger
	push   push.Service
}

func New(store store.Store, bus events.Bus, pushService push.Service, logger *slog.Logger) *Relay {
	return &Relay{store: store, bus: bus, push: pushService, logger: logger}
}

func (r *Relay) Run(ctx context.Context) {
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
		event, recipients, ok := r.translate(ctx, item)
		if !ok {
			observability.OutboxEvents.WithLabelValues("translate_failed").Inc()
			continue
		}
		if err := r.bus.Publish(ctx, recipients, event); err != nil {
			observability.OutboxEvents.WithLabelValues("publish_failed").Inc()
			r.logger.Error("outbox_publish_failed", "error", err, "outbox_id", item.ID)
			continue
		}
		r.sendPush(ctx, item, recipients)
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

func (r *Relay) sendPush(ctx context.Context, item domain.OutboxEvent, recipients []uuid.UUID) {
	notification, ok := r.notificationFor(ctx, item, recipients)
	if !ok {
		return
	}
	for _, userID := range recipients {
		if userID == notification.actorID {
			continue
		}
		devices, err := r.store.ListDevices(ctx, userID)
		if err != nil {
			r.logger.Error("push_devices_failed", "error", err, "user_id", userID)
			continue
		}
		for _, device := range devices {
			if strings.TrimSpace(device.PushToken) == "" || device.Platform != "ios" {
				continue
			}
			err := r.push.Send(
				ctx, device.PushToken, notification.title, notification.body,
				map[string]string{
					"type":     notification.kind,
					"groupId":  notification.conversationID.String(),
					"entityId": notification.entityID.String(),
				},
				notification.entityID.String(),
			)
			if err != nil {
				observability.PushFailures.Inc()
				r.logger.Error("push_send_failed", "error", err, "device_id", device.ID)
				if push.IsInvalidToken(err) {
					if clearErr := r.store.ClearDevicePushToken(ctx, userID, device.ID); clearErr != nil {
						r.logger.Error("push_token_clear_failed", "error", clearErr, "device_id", device.ID)
					}
				}
			}
		}
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
) (activityNotification, bool) {
	switch item.Topic {
	case "message.created":
		var message domain.Message
		if json.Unmarshal(item.Payload, &message) != nil {
			return activityNotification{}, false
		}
		conversation, ok := r.conversationFor(ctx, message.ConversationID, message.SenderID, recipients)
		if !ok {
			return activityNotification{}, false
		}
		return activityNotification{
			actorID: message.SenderID, conversationID: message.ConversationID,
			entityID: message.ID, kind: "message", title: conversationTitle(conversation),
			// Message ciphertext is end-to-end encrypted, so the server deliberately
			// uses privacy-safe copy instead of attempting to expose a preview.
			body: clip(displayName(r, ctx, message.SenderID)+" sent a message", 180),
		}, true

	case "entity.updated":
		var entity domain.Entity
		if json.Unmarshal(item.Payload, &entity) != nil || entity.Version != 1 {
			return activityNotification{}, false
		}
		if entity.Kind != "expense" && entity.Kind != "task" {
			return activityNotification{}, false
		}
		conversation, ok := r.conversationFor(ctx, entity.ConversationID, entity.CreatedBy, recipients)
		if !ok {
			return activityNotification{}, false
		}
		payload := decodedObject(entity.Payload)
		// A subscription-pod create emits its own durable event immediately
		// before its initial charge. Suppress that initial expense to avoid two
		// alerts for one user action; later subscription expenses still notify.
		if entity.Kind == "expense" && isSubscription(conversation) &&
			entity.CreatedAt.Sub(conversation.CreatedAt) >= 0 &&
			entity.CreatedAt.Sub(conversation.CreatedAt) < 10*time.Minute &&
			isInitialSubscriptionCharge(conversation, payload) {
			return activityNotification{}, false
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
		}, true

	case "conversation.created":
		var conversation domain.Conversation
		if json.Unmarshal(item.Payload, &conversation) != nil || !isSubscription(conversation) {
			return activityNotification{}, false
		}
		return subscriptionNotification(
			conversation, conversation.CreatedBy, conversation.ID,
			displayName(r, ctx, conversation.CreatedBy),
		), true

	case "conversation.member_added":
		var added domain.ConversationMemberAdded
		if json.Unmarshal(item.Payload, &added) != nil {
			return activityNotification{}, false
		}
		conversation, ok := r.conversationFor(ctx, added.ConversationID, added.ActorID, recipients)
		if !ok || !isSubscription(conversation) {
			return activityNotification{}, false
		}
		return subscriptionNotification(
			conversation, added.ActorID, conversation.ID,
			displayName(r, ctx, added.ActorID),
		), true
	default:
		return activityNotification{}, false
	}
}

func (r *Relay) conversationFor(
	ctx context.Context,
	conversationID, actorID uuid.UUID,
	recipients []uuid.UUID,
) (domain.Conversation, bool) {
	conversation, err := r.store.Conversation(ctx, conversationID, actorID)
	if err == nil {
		return conversation, true
	}
	for _, recipient := range recipients {
		conversation, err = r.store.Conversation(ctx, conversationID, recipient)
		if err == nil {
			return conversation, true
		}
	}
	return domain.Conversation{}, false
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
