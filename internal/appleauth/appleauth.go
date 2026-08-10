package appleauth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalid     = errors.New("invalid Apple identity token")
	ErrUnavailable = errors.New("Apple identity verification unavailable")
)

type Identity struct {
	Subject string
	Email   string
}

type Verifier interface {
	Verify(context.Context, string, string) (Identity, error)
}

type Apple struct {
	audience string
	client   *http.Client
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	fetched  time.Time
}

type Unavailable struct{}

func (Unavailable) Verify(context.Context, string, string) (Identity, error) {
	return Identity{}, ErrUnavailable
}

func New(audience string) (Verifier, error) {
	if strings.TrimSpace(audience) == "" {
		return Unavailable{}, nil
	}
	return &Apple{
		audience: audience,
		client:   &http.Client{Timeout: 5 * time.Second},
		keys:     make(map[string]*rsa.PublicKey),
	}, nil
}

type claims struct {
	Email string `json:"email,omitempty"`
	Nonce string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

func (a *Apple) Verify(ctx context.Context, identityToken, rawNonce string) (Identity, error) {
	if identityToken == "" || rawNonce == "" {
		return Identity{}, ErrInvalid
	}
	parsedClaims := new(claims)
	token, err := jwt.ParseWithClaims(identityToken, parsedClaims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, ErrInvalid
		}
		keyID, _ := token.Header["kid"].(string)
		if keyID == "" {
			return nil, ErrInvalid
		}
		return a.key(ctx, keyID)
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer("https://appleid.apple.com"),
		jwt.WithAudience(a.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil || !token.Valid || parsedClaims.Subject == "" {
		if errors.Is(err, ErrUnavailable) {
			return Identity{}, ErrUnavailable
		}
		return Identity{}, ErrInvalid
	}
	expectedNonce := sha256.Sum256([]byte(rawNonce))
	expectedHex := hex.EncodeToString(expectedNonce[:])
	if len(parsedClaims.Nonce) != len(expectedHex) ||
		subtle.ConstantTimeCompare([]byte(parsedClaims.Nonce), []byte(expectedHex)) != 1 {
		return Identity{}, ErrInvalid
	}
	return Identity{
		Subject: parsedClaims.Subject,
		Email:   strings.ToLower(strings.TrimSpace(parsedClaims.Email)),
	}, nil
}

func (a *Apple) key(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	a.mu.RLock()
	key := a.keys[keyID]
	fresh := time.Since(a.fetched) < 24*time.Hour
	a.mu.RUnlock()
	if key != nil && fresh {
		return key, nil
	}
	if err := a.refresh(ctx); err != nil {
		if key != nil {
			return key, nil
		}
		return nil, ErrUnavailable
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	key = a.keys[keyID]
	if key == nil {
		return nil, ErrInvalid
	}
	return key, nil
}

func (a *Apple) refresh(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://appleid.apple.com/auth/keys", nil)
	if err != nil {
		return err
	}
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Apple JWKS returned %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	var jwks struct {
		Keys []struct {
			KeyType string `json:"kty"`
			KeyID   string `json:"kid"`
			Use     string `json:"use"`
			Alg     string `json:"alg"`
			N       string `json:"n"`
			E       string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.KeyType != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" || jwk.KeyID == "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			continue
		}
		exponent := new(big.Int).SetBytes(exponentBytes)
		if !exponent.IsInt64() || exponent.Sign() <= 0 {
			continue
		}
		keys[jwk.KeyID] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(exponent.Int64()),
		}
	}
	if len(keys) == 0 {
		return errors.New("Apple JWKS did not contain usable keys")
	}
	a.mu.Lock()
	a.keys = keys
	a.fetched = time.Now()
	a.mu.Unlock()
	return nil
}
