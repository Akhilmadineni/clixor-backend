package appleauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAppleIdentityTokenVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &Apple{
		audience: "com.example.Clustr",
		keys:     map[string]*rsa.PublicKey{"test-key": &privateKey.PublicKey},
		fetched:  time.Now(),
	}
	rawNonce := "a-production-quality-random-nonce"
	nonceHash := sha256.Sum256([]byte(rawNonce))
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims{
		Email: "PERSON@example.com",
		Nonce: hex.EncodeToString(nonceHash[:]),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://appleid.apple.com",
			Subject:   "apple-subject",
			Audience:  jwt.ClaimStrings{"com.example.Clustr"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verifier.Verify(context.Background(), signed, rawNonce)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "apple-subject" || identity.Email != "person@example.com" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if _, err := verifier.Verify(context.Background(), signed, "wrong-nonce-value"); err != ErrInvalid {
		t.Fatalf("expected nonce mismatch to fail, received %v", err)
	}
}
