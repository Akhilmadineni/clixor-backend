package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type TokenManager struct {
	issuer     string
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	store      store.Store
	now        func() time.Time
}

func NewTokenManager(issuer, secret string, accessTTL, refreshTTL time.Duration, store store.Store) *TokenManager {
	return &TokenManager{
		issuer: issuer, secret: []byte(secret), accessTTL: accessTTL,
		refreshTTL: refreshTTL, store: store, now: func() time.Time { return time.Now().UTC() },
	}
}

func (m *TokenManager) Issue(ctx context.Context, userID, deviceID uuid.UUID) (TokenPair, error) {
	sessionID := uuid.New()
	refreshSecret, err := randomToken(48)
	if err != nil {
		return TokenPair{}, err
	}
	now := m.now()
	session := domain.Session{
		ID: sessionID, UserID: userID, DeviceID: deviceID,
		RefreshTokenHash: refreshHash(refreshSecret), CreatedAt: now,
		ExpiresAt: now.Add(m.refreshTTL),
	}
	if err := m.store.CreateSession(ctx, session); err != nil {
		return TokenPair{}, err
	}
	return m.pair(userID, deviceID, sessionID, refreshSecret, now)
}

func (m *TokenManager) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	sessionID, oldSecret, err := parseRefreshToken(refreshToken)
	if err != nil {
		return TokenPair{}, domain.ErrUnauthenticated
	}
	newSecret, err := randomToken(48)
	if err != nil {
		return TokenPair{}, err
	}
	now := m.now()
	session, err := m.store.RotateSession(
		ctx, sessionID, refreshHash(oldSecret), refreshHash(newSecret), now.Add(m.refreshTTL),
	)
	if err != nil {
		return TokenPair{}, domain.ErrUnauthenticated
	}
	return m.pair(session.UserID, session.DeviceID, session.ID, newSecret, now)
}

func (m *TokenManager) ParseAccess(tokenString string) (Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing algorithm")
		}
		return m.secret, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithAudience("clustr-ios"), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		return Claims{}, domain.ErrUnauthenticated
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return Claims{}, domain.ErrUnauthenticated
	}
	return *claims, nil
}

func (m *TokenManager) pair(userID, deviceID, sessionID uuid.UUID, refreshSecret string, now time.Time) (TokenPair, error) {
	expiresAt := now.Add(m.accessTTL)
	claims := Claims{
		DeviceID:  deviceID.String(),
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: m.issuer, Subject: userID.String(), Audience: jwt.ClaimStrings{"clustr-ios"},
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(expiresAt), ID: uuid.NewString(),
		},
	}
	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign access token: %w", err)
	}
	return TokenPair{
		AccessToken: access, RefreshToken: sessionID.String() + "." + refreshSecret,
		TokenType: "Bearer", ExpiresAt: expiresAt,
	}, nil
}

func parseRefreshToken(value string) (uuid.UUID, string, error) {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 || len(parts[1]) < 40 {
		return uuid.Nil, "", domain.ErrUnauthenticated
	}
	id, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, "", domain.ErrUnauthenticated
	}
	return id, parts[1], nil
}

func refreshHash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
