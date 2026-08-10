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

type Store interface {
	Close()
	Ping(context.Context) error

	CreateUser(context.Context, CreateUserParams) (domain.User, error)
	UserByID(context.Context, uuid.UUID) (domain.User, error)
	UserByEmail(context.Context, string) (domain.User, error)
	UserByPhone(context.Context, string) (domain.User, error)
	UsersByPhones(context.Context, []string) ([]domain.User, error)
	UpdateUserProfile(context.Context, uuid.UUID, json.RawMessage) (domain.User, error)
	UserByExternalIdentity(context.Context, string, string) (domain.User, error)
	LinkExternalIdentity(context.Context, string, string, uuid.UUID, string) error

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

	CreateMessage(context.Context, CreateMessageParams) (domain.Message, []uuid.UUID, error)
	ListMessages(context.Context, uuid.UUID, uuid.UUID, int64, int) ([]domain.Message, error)
	UpsertReceipt(context.Context, domain.Receipt) (domain.Receipt, error)
	ListReceipts(context.Context, uuid.UUID, uuid.UUID) ([]domain.Receipt, error)

	PutEntity(context.Context, domain.Entity, *int64) (domain.Entity, error)
	ListEntities(context.Context, uuid.UUID, uuid.UUID, string, time.Time, int) ([]domain.Entity, error)
	DeleteEntity(context.Context, uuid.UUID, uuid.UUID, string, uuid.UUID, *int64) (domain.Entity, error)

	CreateMedia(context.Context, domain.MediaObject) (domain.MediaObject, error)
	Media(context.Context, uuid.UUID, uuid.UUID) (domain.MediaObject, error)
	MarkMediaReady(context.Context, uuid.UUID, uuid.UUID) (domain.MediaObject, error)

	LockOutboxBatch(context.Context, int) ([]domain.OutboxEvent, error)
	MarkOutboxPublished(context.Context, []int64) error
}
