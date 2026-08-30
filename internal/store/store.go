package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

type CreateUserParams struct {
	Email        string
	Phone        string
	DisplayName  string
	PasswordHash string
}

type CreateConversationParams struct {
	ID           uuid.UUID
	Kind         string
	Title        string
	Metadata     json.RawMessage
	CreatedBy    uuid.UUID
	MemberIDs    []uuid.UUID
	InvitePhones []string
}

type UpdateConversationParams struct {
	Title     *string
	AvatarURL *string
	Metadata  *json.RawMessage
}

type CreateMessageParams struct {
	ID              uuid.UUID
	ClientMessageID string
	ConversationID  uuid.UUID
	SenderID        uuid.UUID
	SenderDeviceID  uuid.UUID
	ContentType     string
	Ciphertext      string
	Envelope        json.RawMessage
	ReplyToID       *uuid.UUID
}

const MaxMessagePageSize = 500

// MaxRetentionPruneBatchSize caps each retention transaction. Multiple relay
// replicas may prune concurrently, so the stores must also lock candidate rows
// with SKIP LOCKED rather than relying on this process-level bound alone.
const MaxRetentionPruneBatchSize = 1000

type ListMessagesParams struct {
	ConversationID uuid.UUID
	UserID         uuid.UUID
	BeforeSeq      *int64
	AfterSeq       *int64
	Limit          int
}

func (p ListMessagesParams) Validate() error {
	if p.ConversationID == uuid.Nil || p.UserID == uuid.Nil || p.Limit < 1 ||
		p.Limit > MaxMessagePageSize || (p.BeforeSeq != nil && p.AfterSeq != nil) ||
		(p.BeforeSeq != nil && *p.BeforeSeq < 1) || (p.AfterSeq != nil && *p.AfterSeq < 0) {
		return domain.ErrInvalid
	}
	return nil
}

type CreateConversationInviteParams struct {
	ID             uuid.UUID
	ConversationID uuid.UUID
	ActorID        uuid.UUID
	TokenHash      []byte
	ExpiresAt      time.Time
	MaxUses        int
}

// MediaReservationLimits are enforced atomically by the persistence layer.
// User totals include profile and conversation media. Stored totals include
// pending reservations as well as ready objects, so completing uploads cannot
// bypass storage limits and different API replicas cannot race around them.
type MediaReservationLimits struct {
	PendingTTL                  time.Duration
	MaxPendingCountPerUser      int
	MaxPendingBytesPerUser      int64
	MaxPendingCountConversation int
	MaxPendingBytesConversation int64
	MaxStoredCountPerUser       int
	MaxStoredBytesPerUser       int64
	MaxStoredCountConversation  int
	MaxStoredBytesConversation  int64
}

func DefaultMediaReservationLimits() MediaReservationLimits {
	return MediaReservationLimits{
		PendingTTL:                  5 * time.Minute,
		MaxPendingCountPerUser:      8,
		MaxPendingBytesPerUser:      2 << 30,
		MaxPendingCountConversation: 32,
		MaxPendingBytesConversation: 8 << 30,
		MaxStoredCountPerUser:       2_000,
		MaxStoredBytesPerUser:       2 << 30,
		MaxStoredCountConversation:  10_000,
		MaxStoredBytesConversation:  10 << 30,
	}
}

func (l MediaReservationLimits) Validate() error {
	if l.PendingTTL < time.Minute || l.PendingTTL > 15*time.Minute ||
		l.MaxPendingCountPerUser < 1 || l.MaxPendingBytesPerUser < 1 ||
		l.MaxPendingCountConversation < 1 || l.MaxPendingBytesConversation < 1 ||
		l.MaxStoredCountPerUser < l.MaxPendingCountPerUser ||
		l.MaxStoredBytesPerUser < l.MaxPendingBytesPerUser ||
		l.MaxStoredCountConversation < l.MaxPendingCountConversation ||
		l.MaxStoredBytesConversation < l.MaxPendingBytesConversation {
		return domain.ErrInvalid
	}
	return nil
}

type Store interface {
	Close()
	Ping(context.Context) error

	CreateUser(context.Context, CreateUserParams) (domain.User, error)
	UserByID(context.Context, uuid.UUID) (domain.User, error)
	UserByEmail(context.Context, string) (domain.User, error)
	UserByPhone(context.Context, string) (domain.User, error)
	UsersByPhones(context.Context, []string) ([]domain.User, error)
	UsersByUsernames(context.Context, []string) ([]domain.User, error)
	SearchUsersByUsername(context.Context, string, int) ([]domain.User, error)
	UpdateUserProfile(context.Context, uuid.UUID, json.RawMessage) (domain.User, error)
	UpdateUserPhone(context.Context, uuid.UUID, string) (domain.User, error)
	UserByExternalIdentity(context.Context, string, string) (domain.User, error)
	LinkExternalIdentity(context.Context, string, string, uuid.UUID, string) error
	AgeAssurance(context.Context, uuid.UUID) (domain.AgeAssurance, error)
	UpsertAgeAssurance(context.Context, domain.AgeAssurance) (domain.AgeAssurance, error)
	DeleteAccount(context.Context, uuid.UUID) error
	CreatePasswordResetChallenge(context.Context, domain.PasswordResetChallenge) error
	CancelPasswordResetChallenge(context.Context, uuid.UUID) error
	ConsumePasswordResetChallenge(context.Context, uuid.UUID, []byte, string, int) (string, error)

	UpsertDevice(context.Context, domain.Device) (domain.Device, error)
	Device(context.Context, uuid.UUID, uuid.UUID) (domain.Device, error)
	ListDevices(context.Context, uuid.UUID) ([]domain.Device, error)
	ClearDevicePushToken(context.Context, uuid.UUID, uuid.UUID) error
	PutOneTimePreKeys(context.Context, uuid.UUID, []domain.OneTimePreKey) error
	ClaimPreKeys(context.Context, uuid.UUID) ([]domain.PreKeyBundle, error)

	CreateSession(context.Context, domain.Session) error
	RotateSession(context.Context, uuid.UUID, []byte, []byte, time.Time) (domain.Session, error)
	RevokeSession(context.Context, uuid.UUID, uuid.UUID) error
	SessionActive(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error)

	CreateConversation(context.Context, CreateConversationParams) (domain.Conversation, error)
	Conversation(context.Context, uuid.UUID, uuid.UUID) (domain.Conversation, error)
	ListConversations(context.Context, uuid.UUID, time.Time, int) ([]domain.Conversation, error)
	UpdateConversation(context.Context, uuid.UUID, uuid.UUID, UpdateConversationParams) (domain.Conversation, error)
	DeleteConversation(context.Context, uuid.UUID, uuid.UUID) error
	ListConversationMembers(context.Context, uuid.UUID, uuid.UUID) ([]domain.ConversationMember, error)
	ConversationMemberIDs(context.Context, uuid.UUID) ([]uuid.UUID, error)
	UsersShareConversation(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	AddConversationMember(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) error
	RemoveConversationMember(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
	TransferConversationOwnership(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
	CreateConversationInvites(context.Context, uuid.UUID, uuid.UUID, []string) error
	ClaimConversationInvites(context.Context, uuid.UUID, string) ([]uuid.UUID, error)
	CreateConversationInvite(context.Context, CreateConversationInviteParams) (domain.ConversationInvite, error)
	ConversationInvitePreview(context.Context, []byte, uuid.UUID) (domain.ConversationInvitePreview, error)
	AcceptConversationInvite(context.Context, []byte, uuid.UUID) (domain.ConversationInviteAcceptance, error)
	RevokeConversationInvite(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error

	CreateMessage(context.Context, CreateMessageParams) (domain.Message, []uuid.UUID, error)
	ListMessages(context.Context, ListMessagesParams) ([]domain.Message, error)
	UpsertReceipt(context.Context, domain.Receipt) (domain.Receipt, error)
	ListReceipts(context.Context, uuid.UUID, uuid.UUID) ([]domain.Receipt, error)

	PutEntity(context.Context, domain.Entity, *int64) (domain.Entity, error)
	ListEntities(context.Context, uuid.UUID, uuid.UUID, string, time.Time, int) ([]domain.Entity, error)
	DeleteEntity(context.Context, uuid.UUID, uuid.UUID, string, uuid.UUID, *int64) (domain.Entity, error)

	CreateMedia(context.Context, domain.MediaObject, MediaReservationLimits) (domain.MediaObject, error)
	CreateProfileMedia(context.Context, domain.MediaObject, MediaReservationLimits) (domain.MediaObject, error)
	Media(context.Context, uuid.UUID, uuid.UUID) (domain.MediaObject, error)
	ClaimMediaVerification(context.Context, uuid.UUID, uuid.UUID, time.Duration) (domain.MediaObject, error)
	MarkMediaReady(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (domain.MediaObject, error)
	ReleaseMediaVerification(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
	RejectMediaVerification(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (domain.MediaObject, error)
	RejectPendingMedia(context.Context, uuid.UUID, uuid.UUID) (domain.MediaObject, error)
	DeleteMedia(context.Context, uuid.UUID, uuid.UUID) (domain.MediaObject, error)
	ExpirePendingMedia(context.Context, time.Time, int) (int, error)

	LockOutboxBatch(context.Context, int) ([]domain.OutboxEvent, error)
	LockRealtimeOutboxBatch(context.Context, int) ([]domain.OutboxEvent, error)
	LockMediaDeleteOutboxBatch(context.Context, int) ([]domain.OutboxEvent, error)
	ReleaseOutboxEvent(context.Context, int64, time.Time) error
	MarkOutboxPublished(context.Context, []int64) error
	EnqueuePushDeliveries(context.Context, domain.PushDelivery, []uuid.UUID) (int, error)
	LockPushDeliveryBatch(context.Context, int) ([]domain.PushDelivery, error)
	FinishPushDelivery(context.Context, int64, uuid.UUID, string, time.Time, string) error
	InvalidatePushDelivery(context.Context, int64, uuid.UUID, uuid.UUID, uuid.UUID, string) error
	PrunePushDeliveries(context.Context, time.Time, time.Time, int) (int64, error)
	PrunePublishedOutbox(context.Context, time.Time, int) (int64, error)
}
