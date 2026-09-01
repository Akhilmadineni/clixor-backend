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
	ErrInviteRevoked   = errors.New("invite revoked")
	ErrInviteExpired   = errors.New("invite expired")
	ErrInviteExhausted = errors.New("invite exhausted")
	ErrQuotaExceeded   = errors.New("quota exceeded")
	ErrMediaExpired    = errors.New("media upload expired")
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

// AgeAssurance records only the minimum information needed to enforce the
// adults-only policy. Exact dates of birth and identity documents are never
// persisted by the backend.
type AgeAssurance struct {
	UserID        uuid.UUID  `json:"-"`
	Status        string     `json:"status"`
	MinimumAge    int        `json:"minimum_age"`
	Source        string     `json:"source"`
	Declaration   string     `json:"declaration"`
	PolicyVersion string     `json:"policy_version"`
	CheckedAt     time.Time  `json:"checked_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
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

// PasswordResetChallenge contains only a one-way verifier for the emailed
// code. The raw code is never stored in PostgreSQL, Redis, logs, or events.
type PasswordResetChallenge struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	CodeHash   []byte
	Attempts   int
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

const (
	AccountDeletionPending   = "pending"
	AccountDeletionCompleted = "completed"
)

// AccountDeletionIntent stores only a capability verifier and lifecycle state;
// it deliberately carries no email, phone, display name, or raw token.
type AccountDeletionIntent struct {
	RequestID   uuid.UUID
	UserID      uuid.UUID
	TokenHash   []byte
	State       string
	CreatedAt   time.Time
	CompletedAt *time.Time
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
	DisplayName    string     `json:"display_name,omitempty"`
	Username       string     `json:"username,omitempty"`
	AvatarURL      string     `json:"avatar_url,omitempty"`
	AvatarColor    string     `json:"avatar_color,omitempty"`
	Bio            string     `json:"bio,omitempty"`
}

// PublicUser is the deliberately narrow directory representation returned by
// contact and username discovery. It never contains an email address, password
// data, or private profile fields. MatchedPhone is populated only by exact
// phone lookup so legacy clients can correlate a response with a number they
// already submitted; username lookup and search always omit it.
type PublicUser struct {
	ID           uuid.UUID       `json:"id"`
	MatchedPhone string          `json:"phone,omitempty"`
	DisplayName  string          `json:"display_name,omitempty"`
	AvatarURL    string          `json:"avatar_url,omitempty"`
	Profile      json.RawMessage `json:"profile,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type ConversationMemberAdded struct {
	ConversationID uuid.UUID `json:"conversation_id"`
	ActorID        uuid.UUID `json:"actor_id"`
	UserID         uuid.UUID `json:"user_id"`
}

// ConversationInvite contains only persisted invite metadata. The raw invite
// token is deliberately absent: it is returned once by the create endpoint and
// only its SHA-256 digest crosses the store boundary.
type ConversationInvite struct {
	ID             uuid.UUID  `json:"id"`
	ConversationID uuid.UUID  `json:"conversation_id"`
	CreatedBy      uuid.UUID  `json:"created_by"`
	MaxUses        int        `json:"max_uses"`
	Uses           int        `json:"uses"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ConversationInvitePreview intentionally excludes the conversation ID,
// metadata, creator identity, membership list, and usage counters.
type ConversationInvitePreview struct {
	InviteID      uuid.UUID `json:"invite_id"`
	Kind          string    `json:"kind"`
	Title         string    `json:"title,omitempty"`
	AvatarURL     string    `json:"avatar_url,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	AlreadyMember bool      `json:"already_member"`
}

type ConversationInviteAcceptance struct {
	Conversation Conversation `json:"conversation"`
	Joined       bool         `json:"joined"`
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
	ID               uuid.UUID  `json:"id"`
	OwnerID          uuid.UUID  `json:"owner_id"`
	ConversationID   uuid.UUID  `json:"conversation_id"`
	Scope            string     `json:"scope"`
	ObjectKey        string     `json:"-"`
	ContentType      string     `json:"content_type"`
	ByteSize         int64      `json:"byte_size"`
	CiphertextSHA256 string     `json:"ciphertext_sha256"`
	Status           string     `json:"status"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	// UploadValidUntil is the immutable expiry of the presigned PUT. It remains
	// available internally after the pending reservation becomes ready so every
	// later deletion can wait until the upload capability is no longer usable.
	UploadValidUntil        time.Time  `json:"-"`
	VerificationLeaseToken  *uuid.UUID `json:"-"`
	VerificationLockedUntil *time.Time `json:"-"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

const (
	MediaScopeConversation = "conversation"
	MediaScopeProfile      = "profile"
)

type OutboxEvent struct {
	ID          int64
	Topic       string
	AggregateID uuid.UUID
	Payload     json.RawMessage
	CreatedAt   time.Time
	PublishedAt *time.Time
	AvailableAt time.Time
	LockedUntil *time.Time
	Attempts    int
}

const (
	PushDeliveryPending      = "pending"
	PushDeliveryDelivered    = "delivered"
	PushDeliveryInvalidToken = "invalid_token"
	PushDeliveryDeadLetter   = "dead_letter"
	PushDeliveryCanceled     = "canceled"
)

// PushDelivery is a durable, per-device APNs delivery derived idempotently
// from a transactional outbox event. PushToken is resolved from the device at
// claim time instead of persisted with the notification so a token reassigned
// to another account cannot be used by an old delivery.
type PushDelivery struct {
	ID             int64
	OutboxEventID  int64
	DeviceID       uuid.UUID
	UserID         uuid.UUID
	PushToken      string
	Title          string
	Body           string
	Kind           string
	ConversationID uuid.UUID
	EntityID       uuid.UUID
	NotificationID string
	Status         string
	Attempts       int
	NextAttemptAt  time.Time
	LeaseToken     uuid.UUID
	LockedUntil    time.Time
	CreatedAt      time.Time
	DeliveredAt    *time.Time
	DeadLetteredAt *time.Time
	LastErrorClass string
}

const (
	MailDeliveryPasswordReset   = "password_reset"
	MailDeliveryPasswordChanged = "password_changed"

	MailDeliveryPending    = "pending"
	MailDeliveryDelivered  = "delivered"
	MailDeliveryDeadLetter = "dead_letter"
	MailDeliveryCanceled   = "canceled"
)

// MailDelivery contains only encrypted application payload. Purpose is a
// bounded operational label; recipient addresses, reset codes, subjects, and
// bodies are sealed before this value reaches persistent storage.
type MailDelivery struct {
	ID             uuid.UUID
	ChallengeID    uuid.UUID
	Purpose        string
	Ciphertext     []byte
	Status         string
	Attempts       int
	NextAttemptAt  time.Time
	LeaseToken     uuid.UUID
	LockedUntil    time.Time
	CreatedAt      time.Time
	DeliveredAt    *time.Time
	DeadLetteredAt *time.Time
	CanceledAt     *time.Time
	LastErrorClass string
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
