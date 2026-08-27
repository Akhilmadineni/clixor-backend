package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	conversationInviteTokenPrefix    = "cinv_"
	conversationInviteTokenBytes     = 32
	defaultInviteExpiration          = 7 * 24 * time.Hour
	minimumInviteExpiration          = 5 * time.Minute
	maximumInviteExpiration          = 30 * 24 * time.Hour
	defaultConversationInviteMaxUses = 25
	maximumConversationInviteMaxUses = 1000
)

type conversationInviteTokenRequest struct {
	Token string `json:"token"`
}

func (s *Server) createConversationInvite(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	var request struct {
		ExpiresInSeconds *int64 `json:"expires_in_seconds"`
		MaxUses          *int   `json:"max_uses"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &request) {
		return
	}
	expiresIn := defaultInviteExpiration
	if request.ExpiresInSeconds != nil {
		if *request.ExpiresInSeconds < int64(minimumInviteExpiration/time.Second) ||
			*request.ExpiresInSeconds > int64(maximumInviteExpiration/time.Second) {
			writeDomainError(w, domain.ErrInvalid)
			return
		}
		expiresIn = time.Duration(*request.ExpiresInSeconds) * time.Second
	}
	maxUses := defaultConversationInviteMaxUses
	if request.MaxUses != nil {
		maxUses = *request.MaxUses
	}
	if maxUses < 1 || maxUses > maximumConversationInviteMaxUses {
		writeDomainError(w, domain.ErrInvalid)
		return
	}

	var rawToken string
	var invite domain.ConversationInvite
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		rawToken, err = generateConversationInviteToken()
		if err != nil {
			s.logger.Error("conversation_invite_token_generation_failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "An internal error occurred.")
			return
		}
		tokenHash, _ := conversationInviteTokenHash(rawToken)
		invite, err = s.store.CreateConversationInvite(r.Context(), store.CreateConversationInviteParams{
			ConversationID: conversationID, ActorID: id.UserID, TokenHash: tokenHash,
			ExpiresAt: time.Now().UTC().Add(expiresIn), MaxUses: maxUses,
		})
		if !errors.Is(err, domain.ErrConflict) {
			break
		}
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.logger.Info("conversation_invite_created",
		"conversation_id", conversationID, "invite_id", invite.ID, "actor_id", id.UserID,
		"expires_at", invite.ExpiresAt, "max_uses", invite.MaxUses,
	)
	writeJSON(w, http.StatusCreated, struct {
		Token  string                    `json:"token"`
		Invite domain.ConversationInvite `json:"invite"`
	}{Token: rawToken, Invite: invite})
}

func (s *Server) getConversationInvite(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	tokenHash, ok := conversationInviteTokenFromBody(w, r)
	if !ok {
		return
	}
	preview, err := s.store.ConversationInvitePreview(r.Context(), tokenHash, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) acceptConversationInvite(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	tokenHash, ok := conversationInviteTokenFromBody(w, r)
	if !ok {
		return
	}
	accepted, err := s.store.AcceptConversationInvite(r.Context(), tokenHash, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if accepted.Joined {
		recipients, _ := s.store.ConversationMemberIDs(r.Context(), accepted.Conversation.ID)
		s.publishMembershipEvent(
			r, accepted.Conversation.ID, recipients, "member.added", id.UserID,
		)
	}
	s.logger.Info("conversation_invite_accepted",
		"conversation_id", accepted.Conversation.ID, "actor_id", id.UserID,
		"joined", accepted.Joined,
	)
	writeJSON(w, http.StatusOK, accepted)
}

// conversationInviteTokenFromBody keeps the high-entropy bearer out of URLs.
// Cloudflare, reverse proxies, access logs, browser history, and network
// diagnostics commonly retain request paths, while request bodies remain inside
// the authenticated TLS request and are never logged by this service.
func conversationInviteTokenFromBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var request conversationInviteTokenRequest
	if !decodeJSON(w, r, &request) {
		return nil, false
	}
	tokenHash, ok := conversationInviteTokenHash(request.Token)
	if !ok {
		writeDomainError(w, domain.ErrNotFound)
		return nil, false
	}
	return tokenHash, true
}

func (s *Server) revokeConversationInvite(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	inviteID, err := uuid.Parse(chi.URLParam(r, "inviteID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if err := s.store.RevokeConversationInvite(r.Context(), conversationID, id.UserID, inviteID); err != nil {
		writeDomainError(w, err)
		return
	}
	s.logger.Info("conversation_invite_revoked",
		"conversation_id", conversationID, "invite_id", inviteID, "actor_id", id.UserID,
	)
	w.WriteHeader(http.StatusNoContent)
}

func generateConversationInviteToken() (string, error) {
	random := make([]byte, conversationInviteTokenBytes)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return conversationInviteTokenPrefix + base64.RawURLEncoding.EncodeToString(random), nil
}

func conversationInviteTokenHash(rawToken string) ([]byte, bool) {
	if !strings.HasPrefix(rawToken, conversationInviteTokenPrefix) {
		return nil, false
	}
	encoded := strings.TrimPrefix(rawToken, conversationInviteTokenPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != conversationInviteTokenBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, false
	}
	digest := sha256.Sum256([]byte(rawToken))
	return digest[:], true
}
