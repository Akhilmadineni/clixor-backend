package mail

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

const (
	mailQueuePayloadVersion = 1
	mailQueueAADPrefix      = "clixor:mail-queue:v1"
)

// QueueSealer converts transactional mail inputs into an authenticated,
// encrypted queue payload. Implementations must not perform network I/O.
type QueueSealer interface {
	SealPasswordReset(uuid.UUID, string, string, time.Duration) (domain.MailDelivery, error)
	SealPasswordChanged(uuid.UUID, string) (domain.MailDelivery, error)
}

type QueueCipher struct {
	aead cipher.AEAD
	now  func() time.Time
}

type queuePayload struct {
	Version    int    `json:"version"`
	Purpose    string `json:"purpose"`
	Recipient  string `json:"recipient"`
	Code       string `json:"code,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

type unavailableQueue struct{}

func (unavailableQueue) SealPasswordReset(
	uuid.UUID,
	string,
	string,
	time.Duration,
) (domain.MailDelivery, error) {
	return domain.MailDelivery{}, ErrUnavailable
}

func (unavailableQueue) SealPasswordChanged(
	uuid.UUID,
	string,
) (domain.MailDelivery, error) {
	return domain.MailDelivery{}, ErrUnavailable
}

func UnavailableQueue() QueueSealer { return unavailableQueue{} }

// NewQueueCipher accepts one standard padded base64 value that decodes to an
// independent 256-bit key. The ciphertext is bound to immutable queue metadata
// with AES-GCM additional authenticated data.
func NewQueueCipher(encodedKey string) (*QueueCipher, error) {
	encodedKey = strings.TrimSpace(encodedKey)
	key, err := base64.StdEncoding.Strict().DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("mail queue encryption key must be base64-encoded 32 bytes")
	}
	block, err := aes.NewCipher(key)
	for index := range key {
		key[index] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("initialize mail queue cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize mail queue AEAD: %w", err)
	}
	return &QueueCipher{aead: aead, now: time.Now}, nil
}

func (c *QueueCipher) SealPasswordReset(
	challengeID uuid.UUID,
	recipient string,
	code string,
	ttl time.Duration,
) (domain.MailDelivery, error) {
	if challengeID == uuid.Nil || !validResetCode(code) || ttl < time.Minute || ttl > time.Hour {
		return domain.MailDelivery{}, errors.New("invalid password reset mail payload")
	}
	return c.seal(challengeID, queuePayload{
		Version: mailQueuePayloadVersion, Purpose: domain.MailDeliveryPasswordReset,
		Recipient: recipient, Code: code, TTLSeconds: int64(ttl / time.Second),
	})
}

func (c *QueueCipher) SealPasswordChanged(
	challengeID uuid.UUID,
	recipient string,
) (domain.MailDelivery, error) {
	if challengeID == uuid.Nil {
		return domain.MailDelivery{}, errors.New("invalid password changed mail payload")
	}
	return c.seal(challengeID, queuePayload{
		Version: mailQueuePayloadVersion, Purpose: domain.MailDeliveryPasswordChanged,
		Recipient: recipient,
	})
}

func (c *QueueCipher) seal(
	challengeID uuid.UUID,
	payload queuePayload,
) (domain.MailDelivery, error) {
	recipient, err := mail.ParseAddress(strings.TrimSpace(payload.Recipient))
	if err != nil || !validMailbox(recipient.Address) {
		return domain.MailDelivery{}, errors.New("invalid mail queue recipient")
	}
	payload.Recipient = recipient.Address
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return domain.MailDelivery{}, errors.New("encode mail queue payload")
	}
	deliveryID := uuid.New()
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return domain.MailDelivery{}, errors.New("generate mail queue nonce")
	}
	ciphertext := make([]byte, len(nonce))
	copy(ciphertext, nonce)
	ciphertext = c.aead.Seal(
		ciphertext, nonce, plaintext,
		mailQueueAAD(deliveryID, challengeID, payload.Purpose),
	)
	for index := range plaintext {
		plaintext[index] = 0
	}
	now := c.now().UTC()
	return domain.MailDelivery{
		ID: deliveryID, ChallengeID: challengeID, Purpose: payload.Purpose,
		Ciphertext: ciphertext, Status: domain.MailDeliveryPending,
		NextAttemptAt: now, CreatedAt: now,
	}, nil
}

func (c *QueueCipher) open(delivery domain.MailDelivery) (queuePayload, error) {
	if delivery.ID == uuid.Nil || delivery.ChallengeID == uuid.Nil ||
		!validMailPurpose(delivery.Purpose) || len(delivery.Ciphertext) <= c.aead.NonceSize() {
		return queuePayload{}, errors.New("invalid encrypted mail delivery")
	}
	nonce := delivery.Ciphertext[:c.aead.NonceSize()]
	plaintext, err := c.aead.Open(
		nil, nonce, delivery.Ciphertext[c.aead.NonceSize():],
		mailQueueAAD(delivery.ID, delivery.ChallengeID, delivery.Purpose),
	)
	if err != nil {
		return queuePayload{}, errors.New("authenticate encrypted mail delivery")
	}
	defer func() {
		for index := range plaintext {
			plaintext[index] = 0
		}
	}()
	var payload queuePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return queuePayload{}, errors.New("decode encrypted mail delivery")
	}
	recipient, err := mail.ParseAddress(strings.TrimSpace(payload.Recipient))
	if err != nil || !validMailbox(recipient.Address) || payload.Version != mailQueuePayloadVersion ||
		payload.Purpose != delivery.Purpose {
		return queuePayload{}, errors.New("invalid encrypted mail payload")
	}
	payload.Recipient = recipient.Address
	switch payload.Purpose {
	case domain.MailDeliveryPasswordReset:
		if !validResetCode(payload.Code) || payload.TTLSeconds < 60 || payload.TTLSeconds > 3600 {
			return queuePayload{}, errors.New("invalid encrypted password reset payload")
		}
	case domain.MailDeliveryPasswordChanged:
		if payload.Code != "" || payload.TTLSeconds != 0 {
			return queuePayload{}, errors.New("invalid encrypted password changed payload")
		}
	default:
		return queuePayload{}, errors.New("unknown encrypted mail purpose")
	}
	return payload, nil
}

func mailQueueAAD(deliveryID, challengeID uuid.UUID, purpose string) []byte {
	aad := make([]byte, 0, len(mailQueueAADPrefix)+1+16+16+len(purpose))
	aad = append(aad, mailQueueAADPrefix...)
	aad = append(aad, 0)
	aad = append(aad, deliveryID[:]...)
	aad = append(aad, challengeID[:]...)
	aad = append(aad, purpose...)
	return aad
}

func validMailPurpose(purpose string) bool {
	return purpose == domain.MailDeliveryPasswordReset ||
		purpose == domain.MailDeliveryPasswordChanged
}

func validResetCode(code string) bool {
	if len(code) < 6 || len(code) > 16 {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
