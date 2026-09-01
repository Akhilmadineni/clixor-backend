package mail

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

func testQueueCipher(t *testing.T) *QueueCipher {
	t.Helper()
	key := bytes.Repeat([]byte{0x5a}, 32)
	cipher, err := NewQueueCipher(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestQueueCipherRoundTripsWithoutPlaintextAtRest(t *testing.T) {
	cipher := testQueueCipher(t)
	challengeID := uuid.New()
	delivery, err := cipher.SealPasswordReset(
		challengeID, "private-recipient@example.com", "87654321", 10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-recipient@example.com", "87654321", "Your Clixor"} {
		if bytes.Contains(delivery.Ciphertext, []byte(secret)) {
			t.Fatalf("encrypted queue payload contains plaintext %q", secret)
		}
	}
	payload, err := cipher.open(delivery)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Purpose != domain.MailDeliveryPasswordReset ||
		payload.Recipient != "private-recipient@example.com" || payload.Code != "87654321" ||
		payload.TTLSeconds != 600 {
		t.Fatalf("unexpected decrypted payload metadata")
	}

	second, err := cipher.SealPasswordReset(
		challengeID, "private-recipient@example.com", "87654321", 10*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(delivery.Ciphertext, second.Ciphertext) {
		t.Fatal("AES-GCM nonce reuse produced identical ciphertext")
	}
}

func TestQueueCipherAuthenticatesImmutableMetadata(t *testing.T) {
	cipher := testQueueCipher(t)
	delivery, err := cipher.SealPasswordChanged(uuid.New(), "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*domain.MailDelivery){
		func(value *domain.MailDelivery) { value.ID = uuid.New() },
		func(value *domain.MailDelivery) { value.ChallengeID = uuid.New() },
		func(value *domain.MailDelivery) { value.Purpose = domain.MailDeliveryPasswordReset },
		func(value *domain.MailDelivery) { value.Ciphertext[len(value.Ciphertext)-1] ^= 0x01 },
	}
	for index, mutate := range mutations {
		copyDelivery := delivery
		copyDelivery.Ciphertext = append([]byte(nil), delivery.Ciphertext...)
		mutate(&copyDelivery)
		if _, err := cipher.open(copyDelivery); err == nil {
			t.Fatalf("metadata/ciphertext mutation %d authenticated", index)
		}
	}
}

func TestQueueCipherRequiresExactIndependentKeyAndSanitizesErrors(t *testing.T) {
	secretKey := "not-a-valid-and-highly-sensitive-key"
	if _, err := NewQueueCipher(secretKey); err == nil {
		t.Fatal("invalid queue encryption key was accepted")
	} else if strings.Contains(err.Error(), secretKey) {
		t.Fatal("queue cipher error exposed key material")
	}
	cipher := testQueueCipher(t)
	secretRecipient := "secret-recipient@example.com"
	if _, err := cipher.SealPasswordReset(
		uuid.New(), secretRecipient, "not-numeric", 10*time.Minute,
	); err == nil {
		t.Fatal("invalid reset code was accepted")
	} else if strings.Contains(err.Error(), secretRecipient) || strings.Contains(err.Error(), "not-numeric") {
		t.Fatal("queue cipher error exposed payload material")
	}
}
