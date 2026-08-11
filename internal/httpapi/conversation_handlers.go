package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
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
	recipients, _ := s.store.ConversationMemberIDs(r.Context(), conversationID)
	payload, _ := json.Marshal(conversation)
	_ = s.bus.Publish(r.Context(), recipients, domain.RealtimeEvent{
		ID: uuid.NewString(), Type: "conversation.updated", ConversationID: &conversationID,
		Payload: payload, OccurredAt: time.Now().UTC(),
	})
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
		Phones []string `json:"phones"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	phones, ok := normalizePhones(request.Phones)
	if !ok || len(phones) > 1024 {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	users, err := s.store.UsersByPhones(r.Context(), phones)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.User]{Items: users})
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
	recipients, _ := s.store.ConversationMemberIDs(r.Context(), conversationID)
	if err := s.store.RemoveConversationMember(r.Context(), conversationID, id.UserID, userID); err != nil {
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
	if len(request.ClientMessageID) < 8 || len(request.ClientMessageID) > 128 ||
		len(request.Ciphertext) == 0 || len(request.Ciphertext) > 2<<20 ||
		!allowedContentType(request.ContentType) {
		writeDomainError(w, domain.ErrInvalid)
		return
	}
	if _, err := base64.StdEncoding.DecodeString(request.Ciphertext); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_ciphertext", "Ciphertext must be base64 encoded.")
		return
	}
	message, recipients, err := s.store.CreateMessage(r.Context(), store.CreateMessageParams{
		ID: request.ID, ClientMessageID: request.ClientMessageID, ConversationID: conversationID,
		SenderID: id.UserID, SenderDeviceID: id.DeviceID, ContentType: request.ContentType,
		Ciphertext: request.Ciphertext, Envelope: request.Envelope, ReplyToID: request.ReplyToID,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	eventPayload, _ := json.Marshal(message)
	_ = s.bus.Publish(r.Context(), recipients, domain.RealtimeEvent{
		ID: message.ID.String(), Type: "message.created", ConversationID: &conversationID,
		Seq: message.Seq, Payload: eventPayload, OccurredAt: time.Now().UTC(),
	})
	writeJSON(w, http.StatusCreated, message)
}

func (s *Server) listMessages(w http.ResponseWriter, r *http.Request) {
	id, conversationID, ok := requestConversation(w, r)
	if !ok {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after_seq"), 10, 64)
	limit := parseLimit(r.URL.Query().Get("limit"), 100, 500)
	items, err := s.store.ListMessages(r.Context(), conversationID, id.UserID, after, limit)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	next := ""
	if len(items) == limit {
		next = strconv.FormatInt(items[len(items)-1].Seq, 10)
	}
	writeJSON(w, http.StatusOK, domain.Page[domain.Message]{Items: items, NextCursor: next})
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
	recipients, _ := s.store.ConversationMemberIDs(r.Context(), conversationID)
	payload, _ := json.Marshal(receipt)
	_ = s.bus.Publish(r.Context(), recipients, domain.RealtimeEvent{
		ID: uuid.NewString(), Type: "receipt.updated", ConversationID: &conversationID,
		Seq: max(request.DeliveredSeq, request.ReadSeq), Payload: payload, OccurredAt: time.Now().UTC(),
	})
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
