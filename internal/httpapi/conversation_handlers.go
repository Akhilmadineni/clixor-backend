package httpapi

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) createConversation(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	var request struct {
		ID           uuid.UUID       `json:"id,omitempty"`
		Kind         string          `json:"kind"`
		Title        string          `json:"title,omitempty"`
		Metadata     json.RawMessage `json:"metadata,omitempty"`
		MemberIDs    []uuid.UUID     `json:"member_ids"`
		MemberPhones []string        `json:"member_phones,omitempty"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Kind != "direct" && request.Kind != "group" {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	phones, ok := normalizePhones(request.MemberPhones)
	if !ok || len(request.MemberIDs)+len(phones) > 1023 || len(request.Title) > 200 ||
		len(request.Metadata) > 256<<10 {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	users, err := s.store.UsersByPhones(r.Context(), phones)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	registeredPhones := make(map[string]struct{}, len(users))
	for _, user := range users {
		registeredPhones[user.Phone] = struct{}{}
		request.MemberIDs = append(request.MemberIDs, user.ID)
	}
	var invitePhones []string
	for _, phone := range phones {
		if _, registered := registeredPhones[phone]; !registered {
			invitePhones = append(invitePhones, phone)
		}
	}
	request.MemberIDs = uniqueIDs(request.MemberIDs)
	if request.Kind == "direct" && (len(request.MemberIDs) != 1 || len(invitePhones) != 0) {
		writeError(w, http.StatusUnprocessableEntity, "direct_recipient_unavailable", "A direct conversation requires one registered recipient.")
		return
	}
	if request.Kind == "direct" && request.MemberIDs[0] == id.UserID {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	for _, memberID := range request.MemberIDs {
		if memberID == id.UserID {
			continue
		}
		if _, err := s.store.UserByID(r.Context(), memberID); err != nil {
			writeDomainError(w, err)
			return
		}
	}
	conversation, err := s.store.CreateConversation(r.Context(), store.CreateConversationParams{
		ID: request.ID, Kind: request.Kind, Title: strings.TrimSpace(request.Title), Metadata: request.Metadata,
		CreatedBy: id.UserID, MemberIDs: request.MemberIDs, InvitePhones: invitePhones,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, conversation)
}

func (s *Server) updateConversation(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	var request struct {
		Title     *string          `json:"title"`
		AvatarURL *string          `json:"avatar_url"`
		Metadata  *json.RawMessage `json:"metadata"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Title == nil && request.AvatarURL == nil && request.Metadata == nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if request.Title != nil {
		trimmed := strings.TrimSpace(*request.Title)
		request.Title = &trimmed
	}
	if (request.Title != nil && len(*request.Title) > 200) ||
		(request.AvatarURL != nil && len(*request.AvatarURL) > 2048) ||
		(request.Metadata != nil && len(*request.Metadata) > 256<<10) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	conversation, err := s.store.UpdateConversation(r.Context(), conversationID, id.UserID, store.UpdateConversationParams{
		Title: request.Title, AvatarURL: request.AvatarURL, Metadata: request.Metadata,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, conversation)
}

func (s *Server) deleteConversation(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	recipients, _ := s.store.ConversationMemberIDs(r.Context(), conversationID)
	if err := s.store.DeleteConversation(r.Context(), conversationID, id.UserID); err != nil {
		writeDomainError(w, err)
		return
	}
	payload, _ := json.Marshal(map[string]uuid.UUID{"conversation_id": conversationID})
	_ = s.bus.Publish(r.Context(), recipients, domain.RealtimeEvent{
		ID: uuid.NewString(), Type: "conversation.deleted", ConversationID: &conversationID,
		Payload: payload, OccurredAt: time.Now().UTC(),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) lookupUsers(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Phones    []string `json:"phones"`
		Usernames []string `json:"usernames"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.Phones) == 0 && len(request.Usernames) == 0 {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	users := make([]domain.PublicUser, 0)
	seen := make(map[uuid.UUID]int)
	appendUser := func(user domain.User, includePhone bool) {
		public := store.PublicUserFromUser(user, includePhone)
		if index, duplicate := seen[user.ID]; duplicate {
			// If one request matched both a submitted phone and a username,
			// preserve the exact-phone correlation without exposing any other
			// account identifier.
			if includePhone {
				users[index].MatchedPhone = public.MatchedPhone
			}
			return
		}
		seen[user.ID] = len(users)
		users = append(users, public)
	}
	if len(request.Phones) > 0 {
		phones, ok := normalizePhones(request.Phones)
		if !ok || len(phones) > 1024 {
			writeDomainError(w, domain.ErrInvalid)
			return
		}
		phoneUsers, err := s.store.UsersByPhones(r.Context(), phones)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		for _, user := range phoneUsers {
			appendUser(user, true)
		}
	}
	if len(request.Usernames) > 0 {
		if len(request.Usernames) > 1024 {
			writeDomainError(w, domain.ErrInvalid)
			return
		}
		usernameUsers, err := s.store.UsersByUsernames(r.Context(), request.Usernames)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		for _, user := range usernameUsers {
			appendUser(user, false)
		}
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.PublicUser]{Items: users})
}

func (s *Server) searchUsers(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	users, err := s.store.SearchUsersByUsername(r.Context(), query, limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	public := make([]domain.PublicUser, 0, len(users))
	for _, user := range users {
		public = append(public, store.PublicUserFromUser(user, false))
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.PublicUser]{Items: public})
}

func (s *Server) getConversation(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	conversation, err := s.store.Conversation(r.Context(), conversationID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, conversation)
}

func (s *Server) listConversations(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r.Context())
	before := parseTime(r.URL.Query().Get("before"))
	limit := parseLimit(r.URL.Query().Get("limit"), 50, 100)
	items, err := s.store.ListConversations(r.Context(), id.UserID, before, limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].UpdatedAt.Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.Conversation]{Items: items, NextCursor: next})
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	items, err := s.store.ListConversationMembers(r.Context(), conversationID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.ConversationMember]{Items: items})
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	var request struct {
		UserID uuid.UUID `json:"user_id"`
		Role   string    `json:"role"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Role == "" {
		request.Role = "member"
	}
	if request.Role != "member" && request.Role != "admin" {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if _, err := s.store.UserByID(r.Context(), request.UserID); err != nil {
		writeDomainError(w, err)
		return
	}
	if err := s.store.AddConversationMember(r.Context(), conversationID, id.UserID, request.UserID, request.Role); err != nil {
		writeDomainError(w, err)
		return
	}
	recipients, _ := s.store.ConversationMemberIDs(r.Context(), conversationID)
	s.publishMembershipEvent(r, conversationID, recipients, "member.added", request.UserID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	s.removeConversationMember(w, r, conversationID, id.UserID, userID)
}

func (s *Server) removeSelfMember(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	s.removeConversationMember(w, r, conversationID, id.UserID, id.UserID)
}

func (s *Server) removeConversationMember(w http.ResponseWriter, r *http.Request, conversationID, actorID, userID uuid.UUID) {
	recipients, _ := s.store.ConversationMemberIDs(r.Context(), conversationID)
	if err := s.store.RemoveConversationMember(r.Context(), conversationID, actorID, userID); err != nil {
		writeDomainError(w, err)
		return
	}
	s.publishMembershipEvent(r, conversationID, recipients, "member.removed", userID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) transferOwner(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	var request struct {
		UserID uuid.UUID `json:"user_id"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.UserID == uuid.Nil {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if err := s.store.TransferConversationOwnership(r.Context(), conversationID, id.UserID, request.UserID); err != nil {
		writeDomainError(w, err)
		return
	}
	recipients, _ := s.store.ConversationMemberIDs(r.Context(), conversationID)
	s.publishMembershipEvent(r, conversationID, recipients, "owner.transferred", request.UserID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publishMembershipEvent(r *http.Request, conversationID uuid.UUID, recipients []uuid.UUID, eventType string, subjectID uuid.UUID) {
	id, _ := identityFrom(r.Context())
	payload, _ := json.Marshal(map[string]any{
		"actor_id": id.UserID, "user_id": subjectID,
	})
	_ = s.bus.Publish(r.Context(), recipients, domain.RealtimeEvent{
		ID: uuid.NewString(), Type: eventType, ConversationID: &conversationID,
		Payload: payload, OccurredAt: time.Now().UTC(),
	})
}

func (s *Server) createMessage(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	var request struct {
		ID              uuid.UUID       `json:"id,omitempty"`
		ClientMessageID string          `json:"client_message_id"`
		ContentType     string          `json:"content_type"`
		Ciphertext      string          `json:"ciphertext"`
		Envelope        json.RawMessage `json:"envelope,omitempty"`
		ReplyToID       *uuid.UUID      `json:"reply_to_id,omitempty"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.ID == uuid.Nil {
		request.ID = uuid.New()
	}
	envelope, validE2EEEnvelope := parseE2EEEnvelope(request.Envelope)
	production05bTransition := validProduction05bTransitionEnvelope(request.Envelope)
	if len(request.ClientMessageID) < 8 || len(request.ClientMessageID) > 128 ||
		len(request.Ciphertext) == 0 || len(request.Ciphertext) > 2<<20 ||
		len(request.Envelope) == 0 || len(request.Envelope) > 1<<20 ||
		!allowedContentType(request.ContentType) || (!validE2EEEnvelope && !production05bTransition) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if _, err := base64.StdEncoding.DecodeString(request.Ciphertext); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_ciphertext", "Ciphertext must be base64 encoded.")
		return
	}
	if validE2EEEnvelope {
		device, err := s.store.Device(r.Context(), id.UserID, id.DeviceID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		registeredIdentity, registered := decodeEncodedBytes(device.IdentityKey, 32)
		senderIdentity, validSender := decodeEncodedBytes(envelope.SenderIdentityKey, 32)
		if !registered {
			writeError(w, http.StatusConflict, "e2ee_device_not_ready", "Publish this device's encryption identity before sending messages.")
			return
		}
		if !validSender || subtle.ConstantTimeCompare(registeredIdentity, senderIdentity) != 1 {
			writeError(w, http.StatusUnprocessableEntity, "e2ee_identity_mismatch", "The message identity does not match the authenticated device.")
			return
		}
		if !envelope.hasRecipient(id.DeviceID) {
			writeError(w, http.StatusUnprocessableEntity, "e2ee_sender_not_recipient", "The sending device must be able to decrypt its sent message.")
			return
		}
	}
	message, _, err := s.store.CreateMessage(r.Context(), store.CreateMessageParams{
		ID: request.ID, ClientMessageID: request.ClientMessageID, ConversationID: conversationID,
		SenderID: id.UserID, SenderDeviceID: id.DeviceID, ContentType: request.ContentType,
		Ciphertext: request.Ciphertext, Envelope: request.Envelope, ReplyToID: request.ReplyToID,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if production05bTransition {
		observability.LegacyTransitionMessages.Inc()
	}
	writeJSON(w, http.StatusCreated, message)
}

type e2eeMessageEnvelope struct {
	Protocol           string `json:"protocol"`
	Version            int    `json:"version"`
	SenderIdentityKey  string `json:"sender_identity_key"`
	SenderEphemeralKey string `json:"sender_ephemeral_key"`
	Recipients         []struct {
		DeviceID   uuid.UUID `json:"device_id"`
		KeyID      uint32    `json:"key_id"`
		WrappedKey string    `json:"wrapped_key"`
	} `json:"recipients"`
	Signature string `json:"signature"`
}

func parseE2EEEnvelope(value json.RawMessage) (e2eeMessageEnvelope, bool) {
	var envelope e2eeMessageEnvelope
	if json.Unmarshal(value, &envelope) != nil || envelope.Protocol != "clixor-e2ee-v1" ||
		envelope.Version != 1 || len(envelope.Recipients) == 0 || len(envelope.Recipients) > 4096 ||
		!hasEncodedSize(envelope.SenderIdentityKey, 32) ||
		!hasEncodedSize(envelope.SenderEphemeralKey, 32) || !hasEncodedSize(envelope.Signature, 64) {
		return e2eeMessageEnvelope{}, false
	}
	seen := make(map[uuid.UUID]struct{}, len(envelope.Recipients))
	for _, recipient := range envelope.Recipients {
		if recipient.DeviceID == uuid.Nil || recipient.KeyID == 0 || !hasEncodedSize(recipient.WrappedKey, 60) {
			return e2eeMessageEnvelope{}, false
		}
		if _, duplicate := seen[recipient.DeviceID]; duplicate {
			return e2eeMessageEnvelope{}, false
		}
		seen[recipient.DeviceID] = struct{}{}
	}
	return envelope, true
}

// validProduction05bTransitionEnvelope is the narrow compatibility contract for
// the installed production-05b app. Its ciphertext is base64-encoded JSON and is
// therefore plaintext-equivalent at the server; it is not E2EE. Only the exact
// one-field legacy envelope is accepted so malformed or extended lookalikes
// cannot bypass the full clixor-e2ee-v1 identity and recipient checks.
func validProduction05bTransitionEnvelope(value json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') || !decoder.More() {
		return false
	}
	key, err := decoder.Token()
	if err != nil || key != "protocol" {
		return false
	}
	var protocol string
	if decoder.Decode(&protocol) != nil || protocol != "clustr-transition-v1" || decoder.More() {
		return false
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func (e e2eeMessageEnvelope) hasRecipient(deviceID uuid.UUID) bool {
	for _, recipient := range e.Recipients {
		if recipient.DeviceID == deviceID {
			return true
		}
	}
	return false
}

func hasEncodedSize(value string, size int) bool {
	_, ok := decodeEncodedBytes(value, size)
	return ok
}

func decodeEncodedBytes(value string, size int) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	return decoded, err == nil && len(decoded) == size
}

func (s *Server) listMessages(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	params, err := messagePageParams(r, conversationID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	items, err := s.store.ListMessages(r.Context(), params)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	next := ""
	if len(items) == params.Limit {
		if params.AfterSeq != nil {
			next = strconv.FormatInt(items[len(items)-1].Seq, 10)
		} else {
			next = strconv.FormatInt(items[0].Seq, 10)
		}
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.Message]{Items: items, NextCursor: next})
}

func messagePageParams(
	r *http.Request,
	conversationID uuid.UUID,
	userID uuid.UUID,
) (store.ListMessagesParams, error) {
	params := store.ListMessagesParams{
		ConversationID: conversationID,
		UserID:         userID,
		Limit:          100,
	}
	query := r.URL.Query()
	if rawLimit := query.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > store.MaxMessagePageSize {
			return store.ListMessagesParams{}, domain.ErrInvalid
		}
		params.Limit = limit
	}
	if rawBefore := query.Get("before_seq"); rawBefore != "" {
		before, err := strconv.ParseInt(rawBefore, 10, 64)
		if err != nil {
			return store.ListMessagesParams{}, domain.ErrInvalid
		}
		params.BeforeSeq = &before
	}
	if rawAfter := query.Get("after_seq"); rawAfter != "" {
		after, err := strconv.ParseInt(rawAfter, 10, 64)
		if err != nil {
			return store.ListMessagesParams{}, domain.ErrInvalid
		}
		params.AfterSeq = &after
	}
	if err := params.Validate(); err != nil {
		return store.ListMessagesParams{}, err
	}
	return params, nil
}

func (s *Server) putReceipt(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	var request struct {
		DeliveredSeq int64 `json:"delivered_seq"`
		ReadSeq      int64 `json:"read_seq"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.DeliveredSeq < 0 || request.ReadSeq < 0 || request.ReadSeq > request.DeliveredSeq {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	conversation, err := s.store.Conversation(r.Context(), conversationID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if request.DeliveredSeq > conversation.LastSeq {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	receipt, err := s.store.UpsertReceipt(r.Context(), domain.Receipt{
		ConversationID: conversationID, UserID: id.UserID,
		DeliveredSeq: request.DeliveredSeq, ReadSeq: request.ReadSeq,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) listReceipts(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	receipts, err := s.store.ListReceipts(r.Context(), conversationID, id.UserID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.Receipt]{Items: receipts})
}

func requestConversation(w http.ResponseWriter, r *http.Request) (identity, uuid.UUID, bool) {
	id, ok := identityFrom(r.Context())
	if !ok {
		writeDomainError(w, domain.ErrUnauthenticated)
		return identity{}, uuid.Nil, false
	}
	conversationID, err := uuid.Parse(chi.URLParam(r, "conversationID"))
	if err != nil {
		writeDomainError(w, domain.ErrInvalid)
		return identity{}, uuid.Nil, false
	}
	return id, conversationID, true
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func parseLimit(value string, fallback, maximum int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	if parsed > maximum {
		return maximum
	}
	return parsed
}

func allowedContentType(value string) bool {
	switch value {
	case "text", "image", "video", "audio", "file", "location":
		return true
	default:
		return false
	}
}

func normalizePhones(values []string) ([]string, bool) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		phone := strings.TrimSpace(value)
		if !e164Pattern.MatchString(phone) {
			return nil, false
		}
		if _, duplicate := seen[phone]; duplicate {
			continue
		}
		seen[phone] = struct{}{}
		result = append(result, phone)
	}
	return result, true
}

func uniqueIDs(values []uuid.UUID) []uuid.UUID {
	result := make([]uuid.UUID, 0, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, value := range values {
		if value == uuid.Nil {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
