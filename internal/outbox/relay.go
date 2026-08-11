package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	if item.Topic != "message.created" {
		return
	}
	var message domain.Message
	if json.Unmarshal(item.Payload, &message) != nil {
		return
	}
	for _, userID := range recipients {
		devices, err := r.store.ListDevices(ctx, userID)
		if err != nil {
			continue
		}
		for _, device := range devices {
			if device.ID == message.SenderDeviceID || device.PushToken == "" {
				continue
			}
			err := r.push.Send(ctx, device.PushToken, "New message", "Open Clustr to view it.", map[string]string{
				"conversation_id": message.ConversationID.String(),
				"message_id":      message.ID.String(),
				"seq":             fmt.Sprintf("%d", message.Seq),
			}, message.ID.String())
			if err != nil {
				observability.PushFailures.Inc()
				r.logger.Error("push_send_failed", "error", err, "device_id", device.ID)
			}
		}
	}
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
