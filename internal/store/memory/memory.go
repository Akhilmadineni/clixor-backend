package memory

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

type Store struct {
	mu sync.RWMutex

	users          map[uuid.UUID]domain.User
	emailToUser    map[string]uuid.UUID
	phoneToUser    map[string]uuid.UUID
	externalUsers  map[string]uuid.UUID
	devices        map[uuid.UUID]domain.Device
	preKeys        map[uuid.UUID][]domain.OneTimePreKey
	sessions       map[uuid.UUID]domain.Session
	conversations  map[uuid.UUID]domain.Conversation
	members        map[uuid.UUID]map[uuid.UUID]domain.ConversationMember
	invites        map[uuid.UUID]map[string]uuid.UUID
	messages       map[uuid.UUID][]domain.Message
	clientMessages map[string]domain.Message
	receipts       map[string]domain.Receipt
	entities       map[string]domain.Entity
	media          map[uuid.UUID]domain.MediaObject
	outbox         []domain.OutboxEvent
	nextOutboxID   int64
}

func New() *Store {
	return &Store{
		users:          make(map[uuid.UUID]domain.User),
		emailToUser:    make(map[string]uuid.UUID),
		phoneToUser:    make(map[string]uuid.UUID),
		externalUsers:  make(map[string]uuid.UUID),
		devices:        make(map[uuid.UUID]domain.Device),
		preKeys:        make(map[uuid.UUID][]domain.OneTimePreKey),
		sessions:       make(map[uuid.UUID]domain.Session),
		conversations:  make(map[uuid.UUID]domain.Conversation),
		members:        make(map[uuid.UUID]map[uuid.UUID]domain.ConversationMember),
		invites:        make(map[uuid.UUID]map[string]uuid.UUID),
		messages:       make(map[uuid.UUID][]domain.Message),
		clientMessages: make(map[string]domain.Message),
		receipts:       make(map[string]domain.Receipt),
		entities:       make(map[string]domain.Entity),
		media:          make(map[uuid.UUID]domain.MediaObject),
		nextOutboxID:   1,
	}
}

func (*Store) Close()                     {}
func (*Store) Ping(context.Context) error { return nil }

func (s *Store) CreateUser(_ context.Context, p store.CreateUserParams) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	email := strings.ToLower(strings.TrimSpace(p.Email))
	if email != "" {
		if _, exists := s.emailToUser[email]; exists {
			return domain.User{}, domain.ErrConflict
		}
	}
	if p.Phone != "" {
		if _, exists := s.phoneToUser[p.Phone]; exists {
			return domain.User{}, domain.ErrConflict
		}
	}
	now := time.Now().UTC()
	user := domain.User{
		ID: uuid.New(), Email: email, Phone: p.Phone, DisplayName: p.DisplayName,
		PasswordHash: p.PasswordHash, CreatedAt: now, UpdatedAt: now,
	}
	s.users[user.ID] = user
	if email != "" {
		s.emailToUser[email] = user.ID
	}
	if p.Phone != "" {
		s.phoneToUser[p.Phone] = user.ID
	}
	return user, nil
}

func (s *Store) UserByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return user, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (domain.User, error) {
	s.mu.RLock()
	id, ok := s.emailToUser[strings.ToLower(strings.TrimSpace(email))]
	s.mu.RUnlock()
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return s.UserByID(ctx, id)
}

func (s *Store) UserByPhone(ctx context.Context, phone string) (domain.User, error) {
	s.mu.RLock()
	id, ok := s.phoneToUser[phone]
	s.mu.RUnlock()
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return s.UserByID(ctx, id)
}

func (s *Store) UsersByPhones(_ context.Context, phones []string) ([]domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.User, 0, len(phones))
	seen := make(map[uuid.UUID]struct{})
	for _, phone := range phones {
		id, ok := s.phoneToUser[phone]
		if !ok {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, s.users[id])
	}
	return result, nil
}

func (s *Store) UserByExternalIdentity(ctx context.Context, provider, subject string) (domain.User, error) {
	s.mu.RLock()
	id, ok := s.externalUsers[provider+":"+subject]
	s.mu.RUnlock()
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return s.UserByID(ctx, id)
}

func (s *Store) LinkExternalIdentity(_ context.Context, provider, subject string, userID uuid.UUID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return domain.ErrNotFound
	}
	key := provider + ":" + subject
	if existing, ok := s.externalUsers[key]; ok && existing != userID {
		return domain.ErrConflict
	}
	s.externalUsers[key] = userID
	return nil
}

func (s *Store) UpdateUserProfile(_ context.Context, id uuid.UUID, profile json.RawMessage) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	user.Profile = cloneJSON(profile)
	var p struct {
		DisplayName string `json:"display_name"`
		AvatarURL   string `json:"avatar_url"`
	}
	_ = json.Unmarshal(profile, &p)
	if p.DisplayName != "" {
		user.DisplayName = p.DisplayName
	}
	if p.AvatarURL != "" {
		user.AvatarURL = p.AvatarURL
	}
	user.UpdatedAt = time.Now().UTC()
	s.users[id] = user
	return user, nil
}

func (s *Store) UpsertDevice(_ context.Context, device domain.Device) (domain.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if device.ID == uuid.Nil {
		device.ID = uuid.New()
	}
	if existing, ok := s.devices[device.ID]; ok {
		if existing.UserID != device.UserID {
			return domain.Device{}, domain.ErrConflict
		}
		if device.PushToken == "" {
			device.PushToken = existing.PushToken
		}
		if device.IdentityKey == "" {
			device.IdentityKey = existing.IdentityKey
		}
		if len(device.SignedPreKey) == 0 || string(device.SignedPreKey) == "null" {
			device.SignedPreKey = existing.SignedPreKey
		}
		device.CreatedAt = existing.CreatedAt
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}
	device.LastSeenAt = time.Now().UTC()
	s.devices[device.ID] = device
	return device, nil
}

func (s *Store) Device(_ context.Context, userID, deviceID uuid.UUID) (domain.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, ok := s.devices[deviceID]
	if !ok {
		return domain.Device{}, domain.ErrNotFound
	}
	if device.UserID != userID {
		return domain.Device{}, domain.ErrForbidden
	}
	return device, nil
}

func (s *Store) ListDevices(_ context.Context, userID uuid.UUID) ([]domain.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []domain.Device
	for _, device := range s.devices {
		if device.UserID == userID {
			result = append(result, device)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}

func (s *Store) ClearDevicePushToken(_ context.Context, userID, deviceID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.devices[deviceID]
	if !ok {
		return domain.ErrNotFound
	}
	if device.UserID != userID {
		return domain.ErrForbidden
	}
	device.PushToken = ""
	s.devices[deviceID] = device
	return nil
}

func (s *Store) PutOneTimePreKeys(_ context.Context, deviceID uuid.UUID, keys []domain.OneTimePreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := make(map[uint32]struct{}, len(s.preKeys[deviceID]))
	for _, key := range s.preKeys[deviceID] {
		existing[key.KeyID] = struct{}{}
	}
	for i := range keys {
		if _, duplicate := existing[keys[i].KeyID]; duplicate {
			continue
		}
		keys[i].DeviceID = deviceID
		s.preKeys[deviceID] = append(s.preKeys[deviceID], keys[i])
		existing[keys[i].KeyID] = struct{}{}
	}
	return nil
}

func (s *Store) ClaimPreKeys(_ context.Context, targetUserID uuid.UUID) ([]domain.PreKeyBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []domain.PreKeyBundle
	for _, device := range s.devices {
		if device.UserID != targetUserID || device.IdentityKey == "" {
			continue
		}
		bundle := domain.PreKeyBundle{
			DeviceID: device.ID, IdentityKey: device.IdentityKey, SignedPreKey: device.SignedPreKey,
		}
		keys := s.preKeys[device.ID]
		for i := range keys {
			if keys[i].ClaimedAt == nil {
				now := time.Now().UTC()
				keys[i].ClaimedAt = &now
				s.preKeys[device.ID] = keys
				key := keys[i]
				bundle.OneTimePreKey = &key
				break
			}
		}
		result = append(result, bundle)
	}
	if len(result) == 0 {
		return nil, domain.ErrNotFound
	}
	return result, nil
}

func (s *Store) CreateSession(_ context.Context, session domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *Store) RotateSession(_ context.Context, id uuid.UUID, oldHash, newHash []byte, expiresAt time.Time) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || session.RevokedAt != nil || session.ExpiresAt.Before(time.Now()) {
		return domain.Session{}, domain.ErrUnauthenticated
	}
	if !equalTokenHash(session.RefreshTokenHash, oldHash) {
		if equalTokenHash(session.PreviousRefreshTokenHash, oldHash) {
			now := time.Now().UTC()
			session.RevokedAt = &now
			s.sessions[id] = session
		}
		return domain.Session{}, domain.ErrUnauthenticated
	}
	session.PreviousRefreshTokenHash = append([]byte(nil), session.RefreshTokenHash...)
	session.RefreshTokenHash = append([]byte(nil), newHash...)
	session.ExpiresAt = expiresAt
	s.sessions[id] = session
	return session, nil
}

func equalTokenHash(first, second []byte) bool {
	return len(first) == len(second) && len(first) > 0 &&
		subtle.ConstantTimeCompare(first, second) == 1
}

func (s *Store) RevokeSession(_ context.Context, id, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return domain.ErrNotFound
	}
	if session.UserID != userID {
		return domain.ErrForbidden
	}
	now := time.Now().UTC()
	session.RevokedAt = &now
	s.sessions[id] = session
	return nil
}

func (s *Store) SessionActive(_ context.Context, id, userID, deviceID uuid.UUID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return false, nil
	}
	return session.UserID == userID && session.DeviceID == deviceID &&
		session.RevokedAt == nil && session.ExpiresAt.After(time.Now()), nil
}

func (s *Store) CreateConversation(_ context.Context, p store.CreateConversationParams) (domain.Conversation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Kind == "direct" {
		targets := uniqueUUIDs(append([]uuid.UUID{p.CreatedBy}, p.MemberIDs...))
		for conversationID, conversation := range s.conversations {
			if conversation.Kind != "direct" || len(s.members[conversationID]) != len(targets) {
				continue
			}
			allPresent := true
			for _, userID := range targets {
				if _, ok := s.members[conversationID][userID]; !ok {
					allPresent = false
					break
				}
			}
			if allPresent {
				return conversation, nil
			}
		}
	}
	now := time.Now().UTC()
	conversationID := p.ID
	if conversationID == uuid.Nil {
		conversationID = uuid.New()
	}
	if existing, exists := s.conversations[conversationID]; exists {
		if existing.CreatedBy == p.CreatedBy {
			return existing, nil
		}
		return domain.Conversation{}, domain.ErrConflict
	}
	conversation := domain.Conversation{
		ID: conversationID, Kind: p.Kind, Title: p.Title, Metadata: cloneJSON(p.Metadata),
		CreatedBy: p.CreatedBy, CreatedAt: now, UpdatedAt: now,
	}
	s.conversations[conversation.ID] = conversation
	s.members[conversation.ID] = make(map[uuid.UUID]domain.ConversationMember)
	s.invites[conversation.ID] = make(map[string]uuid.UUID)
	memberIDs := append([]uuid.UUID{p.CreatedBy}, p.MemberIDs...)
	for _, id := range uniqueUUIDs(memberIDs) {
		role := "member"
		if id == p.CreatedBy {
			role = "owner"
		}
		s.members[conversation.ID][id] = domain.ConversationMember{
			ConversationID: conversation.ID, UserID: id, Role: role, JoinedAt: now,
		}
	}
	for _, phone := range p.InvitePhones {
		s.invites[conversation.ID][phone] = p.CreatedBy
	}
	return conversation, nil
}

func (s *Store) UpdateConversation(_ context.Context, conversationID, actorID uuid.UUID, p store.UpdateConversationParams) (domain.Conversation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	conversation, ok := s.conversations[conversationID]
	if !ok {
		return domain.Conversation{}, domain.ErrNotFound
	}
	actor, ok := s.members[conversationID][actorID]
	if !ok || (actor.Role != "owner" && actor.Role != "admin") {
		return domain.Conversation{}, domain.ErrForbidden
	}
	if p.Title != nil {
		conversation.Title = *p.Title
	}
	if p.AvatarURL != nil {
		conversation.AvatarURL = *p.AvatarURL
	}
	if p.Metadata != nil {
		conversation.Metadata = cloneJSON(*p.Metadata)
	}
	conversation.UpdatedAt = time.Now().UTC()
	s.conversations[conversationID] = conversation
	return conversation, nil
}

func (s *Store) DeleteConversation(_ context.Context, conversationID, actorID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	conversation, ok := s.conversations[conversationID]
	if !ok {
		return domain.ErrNotFound
	}
	if conversation.CreatedBy != actorID || s.members[conversationID][actorID].Role != "owner" {
		return domain.ErrForbidden
	}
	delete(s.conversations, conversationID)
	delete(s.members, conversationID)
	delete(s.invites, conversationID)
	delete(s.messages, conversationID)
	return nil
}

func (s *Store) Conversation(_ context.Context, id, userID uuid.UUID) (domain.Conversation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conversation, ok := s.conversations[id]
	if !ok {
		return domain.Conversation{}, domain.ErrNotFound
	}
	if _, ok := s.members[id][userID]; !ok {
		return domain.Conversation{}, domain.ErrForbidden
	}
	return conversation, nil
}

func (s *Store) ListConversations(_ context.Context, userID uuid.UUID, before time.Time, limit int) ([]domain.Conversation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []domain.Conversation
	for id, conversation := range s.conversations {
		if _, ok := s.members[id][userID]; ok && (before.IsZero() || conversation.UpdatedAt.Before(before)) {
			result = append(result, conversation)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt.After(result[j].UpdatedAt) })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) ListConversationMembers(_ context.Context, conversationID, actorID uuid.UUID) ([]domain.ConversationMember, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	members, ok := s.members[conversationID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if _, ok := members[actorID]; !ok {
		return nil, domain.ErrForbidden
	}
	result := make([]domain.ConversationMember, 0, len(members))
	for _, member := range members {
		result = append(result, member)
	}
	return result, nil
}

func (s *Store) ConversationMemberIDs(_ context.Context, conversationID uuid.UUID) ([]uuid.UUID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	members, ok := s.members[conversationID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return memberIDs(members), nil
}

func (s *Store) UsersShareConversation(_ context.Context, first, second uuid.UUID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, members := range s.members {
		if _, firstPresent := members[first]; !firstPresent {
			continue
		}
		if _, secondPresent := members[second]; secondPresent {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) AddConversationMember(_ context.Context, conversationID, actorID, userID uuid.UUID, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	members, ok := s.members[conversationID]
	if !ok {
		return domain.ErrNotFound
	}
	if s.conversations[conversationID].Kind != "group" {
		return domain.ErrInvalid
	}
	if actor := members[actorID]; actor.Role != "owner" && actor.Role != "admin" {
		return domain.ErrForbidden
	}
	if target, exists := members[userID]; exists && target.Role == "owner" {
		return domain.ErrForbidden
	}
	if _, exists := members[userID]; !exists && len(members) >= 1024 {
		return domain.ErrInvalid
	}
	members[userID] = domain.ConversationMember{
		ConversationID: conversationID, UserID: userID, Role: role, JoinedAt: time.Now().UTC(),
	}
	conversation := s.conversations[conversationID]
	conversation.UpdatedAt = time.Now().UTC()
	s.conversations[conversationID] = conversation
	return nil
}

func (s *Store) CreateConversationInvites(_ context.Context, conversationID, actorID uuid.UUID, phones []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, ok := s.members[conversationID][actorID]
	if !ok || (actor.Role != "owner" && actor.Role != "admin") {
		return domain.ErrForbidden
	}
	if s.invites[conversationID] == nil {
		s.invites[conversationID] = make(map[string]uuid.UUID)
	}
	for _, phone := range phones {
		s.invites[conversationID][phone] = actorID
	}
	return nil
}

func (s *Store) ClaimConversationInvites(_ context.Context, userID uuid.UUID, phone string) ([]uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var claimed []uuid.UUID
	for conversationID, phones := range s.invites {
		if _, ok := phones[phone]; !ok {
			continue
		}
		delete(phones, phone)
		if _, exists := s.members[conversationID][userID]; !exists {
			s.members[conversationID][userID] = domain.ConversationMember{
				ConversationID: conversationID, UserID: userID, Role: "member", JoinedAt: time.Now().UTC(),
			}
		}
		claimed = append(claimed, conversationID)
	}
	return claimed, nil
}

func (s *Store) RemoveConversationMember(_ context.Context, conversationID, actorID, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	members, ok := s.members[conversationID]
	if !ok {
		return domain.ErrNotFound
	}
	if s.conversations[conversationID].Kind != "group" {
		return domain.ErrInvalid
	}
	actor := members[actorID]
	target, exists := members[userID]
	if !exists {
		return domain.ErrNotFound
	}
	if target.Role == "owner" {
		return domain.ErrForbidden
	}
	if actorID != userID && actor.Role != "owner" && actor.Role != "admin" {
		return domain.ErrForbidden
	}
	delete(members, userID)
	conversation := s.conversations[conversationID]
	conversation.UpdatedAt = time.Now().UTC()
	s.conversations[conversationID] = conversation
	return nil
}

func (s *Store) TransferConversationOwnership(_ context.Context, conversationID, actorID, targetID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conversations[conversationID].Kind != "group" {
		return domain.ErrInvalid
	}
	members, ok := s.members[conversationID]
	if !ok {
		return domain.ErrNotFound
	}
	actor, actorPresent := members[actorID]
	target, targetPresent := members[targetID]
	if !actorPresent || actor.Role != "owner" {
		return domain.ErrForbidden
	}
	if !targetPresent || targetID == actorID {
		return domain.ErrInvalid
	}
	actor.Role = "admin"
	target.Role = "owner"
	members[actorID] = actor
	members[targetID] = target
	conversation := s.conversations[conversationID]
	conversation.UpdatedAt = time.Now().UTC()
	s.conversations[conversationID] = conversation
	return nil
}

func (s *Store) CreateMessage(_ context.Context, p store.CreateMessageParams) (domain.Message, []uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	members, ok := s.members[p.ConversationID]
	if !ok {
		return domain.Message{}, nil, domain.ErrNotFound
	}
	if _, ok := members[p.SenderID]; !ok {
		return domain.Message{}, nil, domain.ErrForbidden
	}
	idempotencyKey := p.ConversationID.String() + ":" + p.SenderID.String() + ":" + p.ClientMessageID
	if existing, ok := s.clientMessages[idempotencyKey]; ok {
		return existing, memberIDs(members), nil
	}
	conversation := s.conversations[p.ConversationID]
	conversation.LastSeq++
	now := time.Now().UTC()
	conversation.UpdatedAt = now
	s.conversations[p.ConversationID] = conversation
	message := domain.Message{
		ID: p.ID, ClientMessageID: p.ClientMessageID, ConversationID: p.ConversationID,
		SenderID: p.SenderID, SenderDeviceID: p.SenderDeviceID, Seq: conversation.LastSeq,
		ContentType: p.ContentType, Ciphertext: p.Ciphertext, Envelope: cloneJSON(p.Envelope),
		ReplyToID: p.ReplyToID, CreatedAt: now, ServerReceivedAt: now,
	}
	if message.ID == uuid.Nil {
		message.ID = uuid.New()
	}
	s.messages[p.ConversationID] = append(s.messages[p.ConversationID], message)
	s.clientMessages[idempotencyKey] = message
	payload, _ := json.Marshal(message)
	s.appendOutbox("message.created", p.ConversationID, payload)
	return message, memberIDs(members), nil
}

func (s *Store) ListMessages(_ context.Context, conversationID, userID uuid.UUID, afterSeq int64, limit int) ([]domain.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.members[conversationID][userID]; !ok {
		return nil, domain.ErrForbidden
	}
	var result []domain.Message
	for _, message := range s.messages[conversationID] {
		if message.Seq > afterSeq {
			result = append(result, message)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (s *Store) UpsertReceipt(_ context.Context, receipt domain.Receipt) (domain.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.members[receipt.ConversationID][receipt.UserID]; !ok {
		return domain.Receipt{}, domain.ErrForbidden
	}
	key := receipt.ConversationID.String() + ":" + receipt.UserID.String()
	current := s.receipts[key]
	if receipt.DeliveredSeq < current.DeliveredSeq || receipt.ReadSeq < current.ReadSeq {
		return domain.Receipt{}, domain.ErrConflict
	}
	receipt.UpdatedAt = time.Now().UTC()
	s.receipts[key] = receipt
	payload, _ := json.Marshal(receipt)
	s.appendOutbox("receipt.updated", receipt.ConversationID, payload)
	return receipt, nil
}

func (s *Store) ListReceipts(_ context.Context, conversationID, actorID uuid.UUID) ([]domain.Receipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.members[conversationID][actorID]; !ok {
		return nil, domain.ErrForbidden
	}
	result := make([]domain.Receipt, 0, len(s.members[conversationID]))
	prefix := conversationID.String() + ":"
	for key, receipt := range s.receipts {
		if strings.HasPrefix(key, prefix) {
			result = append(result, receipt)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UserID.String() < result[j].UserID.String() })
	return result, nil
}

func (s *Store) PutEntity(_ context.Context, entity domain.Entity, expectedVersion *int64) (domain.Entity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.members[entity.ConversationID][entity.CreatedBy]; !ok {
		return domain.Entity{}, domain.ErrForbidden
	}
	key := entityKey(entity.ConversationID, entity.Kind, entity.ID)
	now := time.Now().UTC()
	existing, exists := s.entities[key]
	if expectedVersion != nil {
		if (!exists && *expectedVersion != 0) || (exists && existing.Version != *expectedVersion) {
			return domain.Entity{}, domain.ErrConflict
		}
	}
	if exists {
		entity.Version = existing.Version + 1
		entity.CreatedAt = existing.CreatedAt
	} else {
		entity.Version = 1
		entity.CreatedAt = now
	}
	entity.UpdatedAt = now
	entity.Payload = cloneJSON(entity.Payload)
	s.entities[key] = entity
	payload, _ := json.Marshal(entity)
	s.appendOutbox("entity.updated", entity.ConversationID, payload)
	return entity, nil
}

func (s *Store) ListEntities(_ context.Context, conversationID, userID uuid.UUID, kind string, since time.Time, limit int) ([]domain.Entity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.members[conversationID][userID]; !ok {
		return nil, domain.ErrForbidden
	}
	var result []domain.Entity
	for _, entity := range s.entities {
		if entity.ConversationID == conversationID && entity.Kind == kind &&
			(since.IsZero() || entity.UpdatedAt.After(since)) {
			result = append(result, entity)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt.Before(result[j].UpdatedAt) })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) DeleteEntity(_ context.Context, conversationID, actorID uuid.UUID, kind string, id uuid.UUID, expectedVersion *int64) (domain.Entity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.members[conversationID][actorID]; !ok {
		return domain.Entity{}, domain.ErrForbidden
	}
	key := entityKey(conversationID, kind, id)
	entity, ok := s.entities[key]
	if !ok {
		return domain.Entity{}, domain.ErrNotFound
	}
	if expectedVersion != nil && entity.Version != *expectedVersion {
		return domain.Entity{}, domain.ErrConflict
	}
	now := time.Now().UTC()
	entity.DeletedAt = &now
	entity.UpdatedAt = now
	entity.Version++
	s.entities[key] = entity
	payload, _ := json.Marshal(entity)
	s.appendOutbox("entity.deleted", conversationID, payload)
	return entity, nil
}

func (s *Store) CreateMedia(_ context.Context, media domain.MediaObject) (domain.MediaObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.members[media.ConversationID][media.OwnerID]; !ok {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	if _, exists := s.media[media.ID]; exists {
		return domain.MediaObject{}, domain.ErrConflict
	}
	now := time.Now().UTC()
	media.CreatedAt, media.UpdatedAt, media.Status = now, now, "pending"
	s.media[media.ID] = media
	return media, nil
}

func (s *Store) Media(_ context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	media, ok := s.media[id]
	if !ok {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if _, ok := s.members[media.ConversationID][actorID]; !ok {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	return media, nil
}

func (s *Store) MarkMediaReady(_ context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	media, ok := s.media[id]
	if !ok {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	media.Status = "ready"
	media.UpdatedAt = time.Now().UTC()
	s.media[id] = media
	return media, nil
}

func (s *Store) LockOutboxBatch(_ context.Context, limit int) ([]domain.OutboxEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit > len(s.outbox) {
		limit = len(s.outbox)
	}
	return append([]domain.OutboxEvent(nil), s.outbox[:limit]...), nil
}

func (s *Store) MarkOutboxPublished(_ context.Context, ids []int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	filtered := s.outbox[:0]
	for _, event := range s.outbox {
		if _, ok := set[event.ID]; !ok {
			filtered = append(filtered, event)
		}
	}
	s.outbox = filtered
	return nil
}

func (s *Store) appendOutbox(topic string, aggregateID uuid.UUID, payload []byte) {
	s.outbox = append(s.outbox, domain.OutboxEvent{
		ID: s.nextOutboxID, Topic: topic, AggregateID: aggregateID,
		Payload: cloneJSON(payload), CreatedAt: time.Now().UTC(),
	})
	s.nextOutboxID++
}

func entityKey(conversationID uuid.UUID, kind string, id uuid.UUID) string {
	return conversationID.String() + ":" + kind + ":" + id.String()
}

func memberIDs(members map[uuid.UUID]domain.ConversationMember) []uuid.UUID {
	result := make([]uuid.UUID, 0, len(members))
	for id := range members {
		result = append(result, id)
	}
	return result
}

func uniqueUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	result := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if id == uuid.Nil {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func cloneJSON(value []byte) json.RawMessage {
	if value == nil {
		return nil
	}
	return append(json.RawMessage(nil), value...)
}
