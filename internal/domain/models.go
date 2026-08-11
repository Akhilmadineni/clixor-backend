package domain

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("conflict")
	ErrForbidden       = errors.New("forbidden")
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrInvalid         = errors.New("invalid input")
)

type User struct {
	ID           uuid.UUID       `json:"id"`
	Email        string          `json:"email,omitempty"`
	Phone        string          `json:"phone,omitempty"`
	DisplayName  string          `json:"display_name,omitempty"`
	AvatarURL    string          `json:"avatar_url,omitempty"`
	Profile      json.RawMessage `json:"profile,omitempty"`
	PasswordHash string          `json:"-"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type Device struct {
	ID           uuid.UUID       `json:"id"`
	UserID       uuid.UUID       `json:"user_id"`
	Name         string          `json:"name"`
	Platform     string          `json:"platform"`
	PushToken    string          `json:"-"`
	IdentityKey  string          `json:"identity_key,omitempty"`
	SignedPreKey json.RawMessage `json:"signed_prekey,omitempty"`
	LastSeenAt   time.Time       `json:"last_seen_at"`
	CreatedAt    time.Time       `json:"created_at"`
}

type Session struct {
	ID                       uuid.UUID
	UserID                   uuid.UUID
	DeviceID                 uuid.UUID
	RefreshTokenHash         []byte
	PreviousRefreshTokenHash []byte
	ExpiresAt                time.Time
	RevokedAt                *time.Time
	CreatedAt                time.Time
}

type OneTimePreKey struct {
	ID        int64      `json:"-"`
	DeviceID  uuid.UUID  `json:"-"`
	KeyID     uint32     `json:"key_id"`
	PublicKey string     `json:"public_key"`
	ClaimedAt *time.Time `json:"-"`
}

type PreKeyBundle struct {
	DeviceID      uuid.UUID       `json:"device_id"`
	IdentityKey   string          `json:"identity_key"`
	SignedPreKey  json.RawMessage `json:"signed_prekey"`
	OneTimePreKey *OneTimePreKey  `json:"one_time_prekey,omitempty"`
}

type Conversation struct {
	ID        uuid.UUID       `json:"id"`
	Kind      string          `json:"kind"`
	Title     string          `json:"title,omitempty"`
	AvatarURL string          `json:"avatar_url,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedBy uuid.UUID       `json:"created_by"`
	LastSeq   int64           `json:"last_seq"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type ConversationMember struct {
	ConversationID uuid.UUID  `json:"conversation_id"`
	UserID         uuid.UUID  `json:"user_id"`
	Role           string     `json:"role"`
	JoinedAt       time.Time  `json:"joined_at"`
	MutedUntil     *time.Time `json:"muted_until,omitempty"`
}

type Message struct {
	ID               uuid.UUID       `json:"id"`
	ClientMessageID  string          `json:"client_message_id"`
	ConversationID   uuid.UUID       `json:"conversation_id"`
	SenderID         uuid.UUID       `json:"sender_id"`
	SenderDeviceID   uuid.UUID       `json:"sender_device_id"`
	Seq              int64           `json:"seq"`
	ContentType      string          `json:"content_type"`
	Ciphertext       string          `json:"ciphertext"`
	Envelope         json.RawMessage `json:"envelope,omitempty"`
	ReplyToID        *uuid.UUID      `json:"reply_to_id,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	ServerReceivedAt time.Time       `json:"server_received_at"`
}

type Receipt struct {
	ConversationID uuid.UUID `json:"conversation_id"`
	UserID         uuid.UUID `json:"user_id"`
	DeliveredSeq   int64     `json:"delivered_seq"`
	ReadSeq        int64     `json:"read_seq"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Entity struct {
	ConversationID uuid.UUID       `json:"conversation_id"`
	Kind           string          `json:"kind"`
	ID             uuid.UUID       `json:"id"`
	Version        int64           `json:"version"`
	Payload        json.RawMessage `json:"payload"`
	CreatedBy      uuid.UUID       `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	DeletedAt      *time.Time      `json:"deleted_at,omitempty"`
}

type MediaObject struct {
	ID               uuid.UUID `json:"id"`
	OwnerID          uuid.UUID `json:"owner_id"`
	ConversationID   uuid.UUID `json:"conversation_id"`
	ObjectKey        string    `json:"-"`
	ContentType      string    `json:"content_type"`
	ByteSize         int64     `json:"byte_size"`
	CiphertextSHA256 string    `json:"ciphertext_sha256"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type OutboxEvent struct {
	ID          int64
	Topic       string
	AggregateID uuid.UUID
	Payload     json.RawMessage
	CreatedAt   time.Time
}

type RealtimeEvent struct {
	ID             string          `json:"id"`
	Type           string          `json:"type"`
	ConversationID *uuid.UUID      `json:"conversation_id,omitempty"`
	Seq            int64           `json:"seq,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	OccurredAt     time.Time       `json:"occurred_at"`
}

type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// MarshalJSON keeps the public page contract stable: empty collections are []
// rather than null. Mobile clients decode items as an array and should not need
// to special-case the backing store's nil slice representation.
func (p Page[T]) MarshalJSON() ([]byte, error) {
	type pageAlias Page[T]
	if p.Items == nil {
		p.Items = []T{}
	}
	return json.Marshal(pageAlias(p))
}
