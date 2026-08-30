package memory

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/mediakey"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

type Store struct {
	mu sync.RWMutex

	users                     map[uuid.UUID]domain.User
	emailToUser               map[string]uuid.UUID
	phoneToUser               map[string]uuid.UUID
	usernameToUser            map[string]uuid.UUID
	externalUsers             map[string]uuid.UUID
	ageAssurances             map[uuid.UUID]domain.AgeAssurance
	passwordResets            map[uuid.UUID]domain.PasswordResetChallenge
	devices                   map[uuid.UUID]domain.Device
	preKeys                   map[uuid.UUID][]domain.OneTimePreKey
	sessions                  map[uuid.UUID]domain.Session
	conversations             map[uuid.UUID]domain.Conversation
	members                   map[uuid.UUID]map[uuid.UUID]domain.ConversationMember
	invites                   map[uuid.UUID]map[string]uuid.UUID
	inviteLinks               map[string]domain.ConversationInvite
	inviteLinkKeys            map[uuid.UUID]string
	messages                  map[uuid.UUID][]domain.Message
	clientMessages            map[string]domain.Message
	receipts                  map[string]domain.Receipt
	entities                  map[string]domain.Entity
	media                     map[uuid.UUID]domain.MediaObject
	mediaUploadCapabilities   map[uuid.UUID]string
	outbox                    []domain.OutboxEvent
	nextOutboxID              int64
	pushDeliveries            map[int64]domain.PushDelivery
	pushDeliveryByEventDevice map[string]int64
	nextPushDeliveryID        int64
}

func New() *Store {
	return &Store{
		users:                     make(map[uuid.UUID]domain.User),
		emailToUser:               make(map[string]uuid.UUID),
		phoneToUser:               make(map[string]uuid.UUID),
		usernameToUser:            make(map[string]uuid.UUID),
		externalUsers:             make(map[string]uuid.UUID),
		ageAssurances:             make(map[uuid.UUID]domain.AgeAssurance),
		passwordResets:            make(map[uuid.UUID]domain.PasswordResetChallenge),
		devices:                   make(map[uuid.UUID]domain.Device),
		preKeys:                   make(map[uuid.UUID][]domain.OneTimePreKey),
		sessions:                  make(map[uuid.UUID]domain.Session),
		conversations:             make(map[uuid.UUID]domain.Conversation),
		members:                   make(map[uuid.UUID]map[uuid.UUID]domain.ConversationMember),
		invites:                   make(map[uuid.UUID]map[string]uuid.UUID),
		inviteLinks:               make(map[string]domain.ConversationInvite),
		inviteLinkKeys:            make(map[uuid.UUID]string),
		messages:                  make(map[uuid.UUID][]domain.Message),
		clientMessages:            make(map[string]domain.Message),
		receipts:                  make(map[string]domain.Receipt),
		entities:                  make(map[string]domain.Entity),
		media:                     make(map[uuid.UUID]domain.MediaObject),
		mediaUploadCapabilities:   make(map[uuid.UUID]string),
		nextOutboxID:              1,
		pushDeliveries:            make(map[int64]domain.PushDelivery),
		pushDeliveryByEventDevice: make(map[string]int64),
		nextPushDeliveryID:        1,
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
	if !ok || string(user.Profile) == `{"deleted":true}` {
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

func normalizeUsernameMemory(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "@")
	return strings.ToLower(trimmed)
}

func profileUsername(profile json.RawMessage) string {
	var p struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(profile, &p)
	return normalizeUsernameMemory(p.Username)
}

func (s *Store) UsersByUsernames(_ context.Context, usernames []string) ([]domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.User, 0, len(usernames))
	seen := make(map[uuid.UUID]struct{})
	for _, username := range usernames {
		key := normalizeUsernameMemory(username)
		if key == "" {
			continue
		}
		id, ok := s.usernameToUser[key]
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

func (s *Store) SearchUsersByUsername(_ context.Context, query string, limit int) ([]domain.User, error) {
	q := normalizeUsernameMemory(query)
	if q == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0)
	for key := range s.usernameToUser {
		if strings.HasPrefix(key, q) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	result := make([]domain.User, 0, len(keys))
	for _, key := range keys {
		if id, ok := s.usernameToUser[key]; ok {
			result = append(result, s.users[id])
		}
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

func (s *Store) AgeAssurance(_ context.Context, userID uuid.UUID) (domain.AgeAssurance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	assurance, ok := s.ageAssurances[userID]
	if !ok {
		return domain.AgeAssurance{}, domain.ErrNotFound
	}
	return assurance, nil
}

func (s *Store) UpsertAgeAssurance(_ context.Context, assurance domain.AgeAssurance) (domain.AgeAssurance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[assurance.UserID]
	if !ok || string(user.Profile) == `{"deleted":true}` {
		return domain.AgeAssurance{}, domain.ErrNotFound
	}
	s.ageAssurances[assurance.UserID] = assurance
	return assurance, nil
}

func (s *Store) UpdateUserProfile(_ context.Context, id uuid.UUID, profile json.RawMessage) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok || string(user.Profile) == `{"deleted":true}` {
		return domain.User{}, domain.ErrNotFound
	}
	var patch map[string]any
	if err := json.Unmarshal(profile, &patch); err != nil || patch == nil {
		return domain.User{}, domain.ErrInvalid
	}
	var existing map[string]any
	if len(user.Profile) > 0 && json.Unmarshal(user.Profile, &existing) != nil {
		return domain.User{}, domain.ErrInvalid
	}
	if existing == nil {
		existing = make(map[string]any)
	}
	if rawUsername, present := patch["username"]; present {
		old := profileUsername(user.Profile)
		newUsername := ""
		if rawUsername != nil {
			username, ok := rawUsername.(string)
			if !ok {
				return domain.User{}, domain.ErrInvalid
			}
			normalized := normalizeUsernameMemory(username)
			if normalized != "" {
				if len(normalized) < 3 || len(normalized) > 30 {
					return domain.User{}, domain.ErrInvalid
				}
				if owner, exists := s.usernameToUser[normalized]; exists && owner != id {
					return domain.User{}, domain.ErrConflict
				}
				patch["username"] = "@" + normalized
				newUsername = normalized
			}
		}
		if old != "" && old != newUsername {
			delete(s.usernameToUser, old)
		}
		if newUsername != "" {
			s.usernameToUser[newUsername] = id
		}
	}
	for key, value := range patch {
		existing[key] = value
	}
	merged, err := json.Marshal(existing)
	if err != nil {
		return domain.User{}, err
	}
	user.Profile = merged
	if displayName, ok := patch["display_name"].(string); ok && displayName != "" {
		user.DisplayName = displayName
	}
	user.UpdatedAt = time.Now().UTC()
	s.users[id] = user
	return user, nil
}

func (s *Store) UpdateUserPhone(_ context.Context, id uuid.UUID, phone string) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok || string(user.Profile) == `{"deleted":true}` {
		return domain.User{}, domain.ErrNotFound
	}
	if existing, exists := s.phoneToUser[phone]; exists && existing != id {
		return domain.User{}, domain.ErrConflict
	}
	if user.Phone != "" {
		delete(s.phoneToUser, user.Phone)
	}
	user.Phone = phone
	user.UpdatedAt = time.Now().UTC()
	s.users[id] = user
	s.phoneToUser[phone] = id
	return user, nil
}

func (s *Store) DeleteAccount(_ context.Context, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[userID]
	if !ok || string(user.Profile) == `{"deleted":true}` {
		return domain.ErrNotFound
	}
	identity := store.AccountIdentity{
		UserID: userID, Email: user.Email, Phone: user.Phone,
		DisplayName: user.DisplayName, Username: profileUsername(user.Profile),
	}
	now := time.Now().UTC()
	deletedConversations := make(map[uuid.UUID]struct{})
	var objectKeys []string
	mediaDeleteNotBefore := now.Add(store.MediaDeleteGrace)
	var updatedEntities []domain.Entity

	for conversationID, members := range s.members {
		if _, present := members[userID]; !present {
			continue
		}
		if len(members) == 1 {
			deletedConversations[conversationID] = struct{}{}
			delete(s.conversations, conversationID)
			delete(s.members, conversationID)
			delete(s.invites, conversationID)
			delete(s.messages, conversationID)
			continue
		}

		successor := oldestMember(members, userID)
		conversation := s.conversations[conversationID]
		if conversation.CreatedBy == userID {
			conversation.CreatedBy = successor.UserID
		}
		if metadata, changed, err := store.AnonymizeAccountJSON(conversation.Metadata, identity); err == nil && changed {
			conversation.Metadata = metadata
		}
		conversation.UpdatedAt = now
		s.conversations[conversationID] = conversation
		if members[userID].Role == "owner" {
			successor.Role = "owner"
			members[successor.UserID] = successor
		}
		delete(members, userID)
		delete(s.receipts, conversationID.String()+":"+userID.String())

		for key, entity := range s.entities {
			if entity.ConversationID != conversationID {
				continue
			}
			payload, changed, err := store.AnonymizeAccountJSON(entity.Payload, identity)
			if err != nil || !changed {
				continue
			}
			entity.Payload = payload
			entity.Version++
			entity.UpdatedAt = now
			s.entities[key] = entity
			updatedEntities = append(updatedEntities, entity)
		}
	}

	for key, message := range s.clientMessages {
		if _, deleted := deletedConversations[message.ConversationID]; deleted {
			delete(s.clientMessages, key)
		}
	}
	for key, receipt := range s.receipts {
		_, conversationDeleted := deletedConversations[receipt.ConversationID]
		if receipt.UserID == userID || conversationDeleted {
			delete(s.receipts, key)
		}
	}
	for key, entity := range s.entities {
		if _, deleted := deletedConversations[entity.ConversationID]; deleted {
			delete(s.entities, key)
		}
	}
	for id, mediaObject := range s.media {
		_, conversationDeleted := deletedConversations[mediaObject.ConversationID]
		if conversationDeleted || (mediaObject.Scope == domain.MediaScopeProfile && mediaObject.OwnerID == userID) {
			objectKeys = append(objectKeys, mediaObject.ObjectKey)
			if candidate := memoryMediaDeleteNotBefore(mediaObject.UploadValidUntil); candidate.After(mediaDeleteNotBefore) {
				mediaDeleteNotBefore = candidate
			}
			delete(s.media, id)
			delete(s.mediaUploadCapabilities, id)
		}
	}
	for conversationID, phones := range s.invites {
		for phone, invitedBy := range phones {
			if invitedBy == userID || phone == user.Phone {
				delete(phones, phone)
			}
		}
		if len(phones) == 0 {
			delete(s.invites, conversationID)
		}
	}
	for tokenKey, invite := range s.inviteLinks {
		if _, deleted := deletedConversations[invite.ConversationID]; deleted {
			delete(s.inviteLinks, tokenKey)
			delete(s.inviteLinkKeys, invite.ID)
			continue
		}
		if invite.CreatedBy == userID && invite.RevokedAt == nil {
			revokedAt := now
			invite.RevokedAt = &revokedAt
			s.inviteLinks[tokenKey] = invite
		}
	}
	for key, linkedUserID := range s.externalUsers {
		if linkedUserID == userID {
			delete(s.externalUsers, key)
		}
	}
	delete(s.ageAssurances, userID)
	for challengeID, challenge := range s.passwordResets {
		if challenge.UserID == userID {
			delete(s.passwordResets, challengeID)
		}
	}
	for sessionID, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, sessionID)
		}
	}
	for deviceID, device := range s.devices {
		if device.UserID != userID {
			continue
		}
		delete(s.preKeys, deviceID)
		device.Name = "Deleted device"
		device.PushToken = ""
		device.IdentityKey = ""
		device.SignedPreKey = nil
		s.devices[deviceID] = device
	}
	delete(s.emailToUser, strings.ToLower(strings.TrimSpace(user.Email)))
	delete(s.phoneToUser, user.Phone)
	delete(s.usernameToUser, profileUsername(user.Profile))

	user.Email = ""
	user.Phone = ""
	user.DisplayName = store.DeletedUserDisplayName
	user.AvatarURL = ""
	user.Profile = json.RawMessage(`{"deleted":true}`)
	user.PasswordHash = ""
	user.UpdatedAt = now
	s.users[userID] = user

	filtered := s.outbox[:0]
	removedOutboxIDs := make(map[int64]struct{})
	needles := [][]byte{[]byte(userID.String()), []byte(identity.Email), []byte(identity.Phone), []byte(identity.Username)}
	for _, event := range s.outbox {
		if _, deleted := deletedConversations[event.AggregateID]; deleted || containsAny(event.Payload, needles) {
			removedOutboxIDs[event.ID] = struct{}{}
			continue
		}
		filtered = append(filtered, event)
	}
	s.outbox = filtered
	for deliveryID, delivery := range s.pushDeliveries {
		if _, removed := removedOutboxIDs[delivery.OutboxEventID]; !removed {
			continue
		}
		delete(s.pushDeliveries, deliveryID)
		delete(s.pushDeliveryByEventDevice, pushDeliveryKey(delivery.OutboxEventID, delivery.DeviceID))
	}
	for _, entity := range updatedEntities {
		payload, _ := json.Marshal(entity)
		s.appendOutbox("entity.updated", entity.ConversationID, payload)
	}
	if len(objectKeys) > 0 {
		sort.Strings(objectKeys)
		s.appendMediaDeletesAt(userID, objectKeys, mediaDeleteNotBefore)
	}
	return nil
}

func oldestMember(members map[uuid.UUID]domain.ConversationMember, excluded uuid.UUID) domain.ConversationMember {
	var result domain.ConversationMember
	for id, member := range members {
		if id == excluded {
			continue
		}
		if result.UserID == uuid.Nil || member.JoinedAt.Before(result.JoinedAt) ||
			(member.JoinedAt.Equal(result.JoinedAt) && id.String() < result.UserID.String()) {
			result = member
		}
	}
	return result
}

func containsAny(payload []byte, needles [][]byte) bool {
	for _, needle := range needles {
		if len(needle) > 0 && bytes.Contains(payload, needle) {
			return true
		}
	}
	return false
}

func (s *Store) UpsertDevice(_ context.Context, device domain.Device) (domain.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device.PushToken = strings.ToLower(strings.TrimSpace(device.PushToken))
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
	if device.PushToken != "" {
		// A nonempty APNs token identifies one installation. Moving it to this
		// authenticated device atomically removes it from every previous row.
		for existingID, existing := range s.devices {
			if existingID == device.ID || existing.PushToken != device.PushToken {
				continue
			}
			existing.PushToken = ""
			s.devices[existingID] = existing
		}
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
	payload, _ := json.Marshal(conversation)
	s.appendOutbox("conversation.created", conversation.ID, payload)
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
	var objectKeys []string
	deleteNotBefore := time.Now().UTC().Add(store.MediaDeleteGrace)
	for id, object := range s.media {
		if object.Scope == domain.MediaScopeConversation && object.ConversationID == conversationID {
			objectKeys = append(objectKeys, object.ObjectKey)
			if candidate := memoryMediaDeleteNotBefore(object.UploadValidUntil); candidate.After(deleteNotBefore) {
				deleteNotBefore = candidate
			}
			delete(s.media, id)
			delete(s.mediaUploadCapabilities, id)
		}
	}
	filtered := s.outbox[:0]
	for _, event := range s.outbox {
		if event.AggregateID != conversationID {
			filtered = append(filtered, event)
		}
	}
	s.outbox = filtered
	delete(s.conversations, conversationID)
	delete(s.members, conversationID)
	delete(s.invites, conversationID)
	for tokenKey, invite := range s.inviteLinks {
		if invite.ConversationID == conversationID {
			delete(s.inviteLinks, tokenKey)
			delete(s.inviteLinkKeys, invite.ID)
		}
	}
	delete(s.messages, conversationID)
	if len(objectKeys) > 0 {
		sort.Strings(objectKeys)
		for start := 0; start < len(objectKeys); start += store.MediaDeleteBatchSize {
			end := min(start+store.MediaDeleteBatchSize, len(objectKeys))
			s.appendMediaDeletesAt(conversationID, objectKeys[start:end], deleteNotBefore)
		}
	}
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
	target, targetExists := members[userID]
	if targetExists && target.Role == "owner" {
		return domain.ErrForbidden
	}
	if !targetExists && len(members) >= 1024 {
		return domain.ErrInvalid
	}
	members[userID] = domain.ConversationMember{
		ConversationID: conversationID, UserID: userID, Role: role, JoinedAt: time.Now().UTC(),
	}
	conversation := s.conversations[conversationID]
	conversation.UpdatedAt = time.Now().UTC()
	s.conversations[conversationID] = conversation
	if !targetExists {
		payload, _ := json.Marshal(domain.ConversationMemberAdded{
			ConversationID: conversationID, ActorID: actorID, UserID: userID,
		})
		s.appendOutbox("conversation.member_added", conversationID, payload)
	}
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

func (s *Store) CreateConversationInvite(_ context.Context, p store.CreateConversationInviteParams) (domain.ConversationInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p.TokenHash) != 32 || p.MaxUses < 1 || p.MaxUses > 1000 || !p.ExpiresAt.After(time.Now()) {
		return domain.ConversationInvite{}, domain.ErrInvalid
	}
	conversation, exists := s.conversations[p.ConversationID]
	actor, member := s.members[p.ConversationID][p.ActorID]
	if !exists || !member || (actor.Role != "owner" && actor.Role != "admin") {
		return domain.ConversationInvite{}, domain.ErrForbidden
	}
	if conversation.Kind != "group" {
		return domain.ConversationInvite{}, domain.ErrInvalid
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	tokenKey := string(p.TokenHash)
	if _, duplicate := s.inviteLinks[tokenKey]; duplicate {
		return domain.ConversationInvite{}, domain.ErrConflict
	}
	if _, duplicate := s.inviteLinkKeys[p.ID]; duplicate {
		return domain.ConversationInvite{}, domain.ErrConflict
	}
	now := time.Now().UTC()
	invite := domain.ConversationInvite{
		ID: p.ID, ConversationID: p.ConversationID, CreatedBy: p.ActorID,
		MaxUses: p.MaxUses, ExpiresAt: p.ExpiresAt.UTC(), CreatedAt: now,
	}
	s.inviteLinks[tokenKey] = invite
	s.inviteLinkKeys[invite.ID] = tokenKey
	return invite, nil
}

func (s *Store) ConversationInvitePreview(_ context.Context, tokenHash []byte, userID uuid.UUID) (domain.ConversationInvitePreview, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	invite, ok := s.inviteLinks[string(tokenHash)]
	if !ok {
		return domain.ConversationInvitePreview{}, domain.ErrNotFound
	}
	if err := conversationInviteActiveError(invite, time.Now()); err != nil {
		return domain.ConversationInvitePreview{}, err
	}
	conversation, ok := s.conversations[invite.ConversationID]
	if !ok {
		return domain.ConversationInvitePreview{}, domain.ErrNotFound
	}
	_, alreadyMember := s.members[invite.ConversationID][userID]
	return domain.ConversationInvitePreview{
		InviteID: invite.ID, Kind: conversation.Kind, Title: conversation.Title,
		AvatarURL: conversation.AvatarURL, ExpiresAt: invite.ExpiresAt,
		AlreadyMember: alreadyMember,
	}, nil
}

func (s *Store) AcceptConversationInvite(_ context.Context, tokenHash []byte, userID uuid.UUID) (domain.ConversationInviteAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokenKey := string(tokenHash)
	invite, ok := s.inviteLinks[tokenKey]
	if !ok {
		return domain.ConversationInviteAcceptance{}, domain.ErrNotFound
	}
	now := time.Now().UTC()
	if invite.RevokedAt != nil {
		return domain.ConversationInviteAcceptance{}, domain.ErrInviteRevoked
	}
	if !invite.ExpiresAt.After(now) {
		return domain.ConversationInviteAcceptance{}, domain.ErrInviteExpired
	}
	conversation, ok := s.conversations[invite.ConversationID]
	if !ok {
		return domain.ConversationInviteAcceptance{}, domain.ErrNotFound
	}
	members := s.members[invite.ConversationID]
	if _, alreadyMember := members[userID]; alreadyMember {
		return domain.ConversationInviteAcceptance{Conversation: conversation, Joined: false}, nil
	}
	if invite.Uses >= invite.MaxUses {
		return domain.ConversationInviteAcceptance{}, domain.ErrInviteExhausted
	}
	if conversation.Kind != "group" || len(members) >= 1024 {
		return domain.ConversationInviteAcceptance{}, domain.ErrInvalid
	}
	members[userID] = domain.ConversationMember{
		ConversationID: conversation.ID, UserID: userID, Role: "member", JoinedAt: now,
	}
	invite.Uses++
	s.inviteLinks[tokenKey] = invite
	conversation.UpdatedAt = now
	s.conversations[conversation.ID] = conversation
	payload, _ := json.Marshal(domain.ConversationMemberAdded{
		ConversationID: conversation.ID, ActorID: userID, UserID: userID,
	})
	s.appendOutbox("conversation.member_added", conversation.ID, payload)
	return domain.ConversationInviteAcceptance{Conversation: conversation, Joined: true}, nil
}

func (s *Store) RevokeConversationInvite(_ context.Context, conversationID, actorID, inviteID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, ok := s.members[conversationID][actorID]
	if !ok || (actor.Role != "owner" && actor.Role != "admin") {
		return domain.ErrForbidden
	}
	tokenKey, ok := s.inviteLinkKeys[inviteID]
	if !ok {
		return domain.ErrNotFound
	}
	invite := s.inviteLinks[tokenKey]
	if invite.ConversationID != conversationID {
		return domain.ErrNotFound
	}
	if invite.RevokedAt == nil {
		now := time.Now().UTC()
		invite.RevokedAt = &now
		s.inviteLinks[tokenKey] = invite
	}
	return nil
}

func conversationInviteActiveError(invite domain.ConversationInvite, now time.Time) error {
	if invite.RevokedAt != nil {
		return domain.ErrInviteRevoked
	}
	if !invite.ExpiresAt.After(now) {
		return domain.ErrInviteExpired
	}
	if invite.Uses >= invite.MaxUses {
		return domain.ErrInviteExhausted
	}
	return nil
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

func (s *Store) ListMessages(_ context.Context, p store.ListMessagesParams) ([]domain.Message, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.members[p.ConversationID][p.UserID]; !ok {
		return nil, domain.ErrForbidden
	}
	messages := s.messages[p.ConversationID]
	result := make([]domain.Message, 0, min(p.Limit, len(messages)))
	if p.AfterSeq != nil {
		for _, message := range messages {
			if message.Seq <= *p.AfterSeq {
				continue
			}
			result = append(result, message)
			if len(result) == p.Limit {
				break
			}
		}
		return result, nil
	}

	end := len(messages)
	if p.BeforeSeq != nil {
		end = sort.Search(len(messages), func(index int) bool {
			return messages[index].Seq >= *p.BeforeSeq
		})
	}
	start := max(0, end-p.Limit)
	result = append(result, messages[start:end]...)
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

func (s *Store) CreateMedia(_ context.Context, media domain.MediaObject, limits store.MediaReservationLimits) (domain.MediaObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := limits.Validate(); err != nil {
		return domain.MediaObject{}, err
	}
	if _, ok := s.members[media.ConversationID][media.OwnerID]; !ok {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	media.Scope = domain.MediaScopeConversation
	return s.createMediaLocked(media, limits)
}

func (s *Store) CreateProfileMedia(_ context.Context, media domain.MediaObject, limits store.MediaReservationLimits) (domain.MediaObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := limits.Validate(); err != nil {
		return domain.MediaObject{}, err
	}
	user, ok := s.users[media.OwnerID]
	if !ok || string(user.Profile) == `{"deleted":true}` {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	media.Scope = domain.MediaScopeProfile
	media.ConversationID = uuid.Nil
	return s.createMediaLocked(media, limits)
}

func (s *Store) PersistMediaUploadCapability(
	_ context.Context,
	id, actorID uuid.UUID,
	revocationToken string,
) error {
	revocationToken = strings.TrimSpace(revocationToken)
	if id == uuid.Nil || actorID == uuid.Nil || revocationToken == "" || len(revocationToken) > 1024 {
		return domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return domain.ErrForbidden
	}
	if media.Status != "pending" {
		return domain.ErrConflict
	}
	if existing := s.mediaUploadCapabilities[id]; existing != "" && existing != revocationToken {
		return domain.ErrConflict
	}
	s.mediaUploadCapabilities[id] = revocationToken
	return nil
}

func (s *Store) MediaUploadCapability(
	_ context.Context,
	id, actorID uuid.UUID,
) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return "", domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return "", domain.ErrForbidden
	}
	return s.mediaUploadCapabilities[id], nil
}

func (s *Store) createMediaLocked(media domain.MediaObject, limits store.MediaReservationLimits) (domain.MediaObject, error) {
	if media.ID == uuid.Nil || media.OwnerID == uuid.Nil || media.ByteSize < 1 ||
		strings.TrimSpace(media.ObjectKey) == "" || strings.TrimSpace(media.ContentType) == "" {
		return domain.MediaObject{}, domain.ErrInvalid
	}
	if _, exists := s.media[media.ID]; exists {
		return domain.MediaObject{}, domain.ErrConflict
	}
	if media.ByteSize > limits.MaxPendingBytesPerUser ||
		media.ByteSize > limits.MaxStoredBytesPerUser ||
		(media.Scope == domain.MediaScopeConversation &&
			(media.ByteSize > limits.MaxPendingBytesConversation ||
				media.ByteSize > limits.MaxStoredBytesConversation)) {
		return domain.MediaObject{}, domain.ErrQuotaExceeded
	}
	var userPendingCount, conversationPendingCount int
	var userStoredCount, conversationStoredCount int
	var userPendingBytes, conversationPendingBytes int64
	var userStoredBytes, conversationStoredBytes int64
	for _, existing := range s.media {
		if existing.Status == "deleted" {
			continue
		}
		if existing.OwnerID == media.OwnerID {
			userStoredCount++
			userStoredBytes += existing.ByteSize
			if existing.Status == "pending" {
				userPendingCount++
				userPendingBytes += existing.ByteSize
			}
		}
		if media.Scope == domain.MediaScopeConversation &&
			existing.Scope == domain.MediaScopeConversation &&
			existing.ConversationID == media.ConversationID {
			conversationStoredCount++
			conversationStoredBytes += existing.ByteSize
			if existing.Status == "pending" {
				conversationPendingCount++
				conversationPendingBytes += existing.ByteSize
			}
		}
	}
	if userPendingCount+1 > limits.MaxPendingCountPerUser ||
		userPendingBytes+media.ByteSize > limits.MaxPendingBytesPerUser ||
		userStoredCount+1 > limits.MaxStoredCountPerUser ||
		userStoredBytes+media.ByteSize > limits.MaxStoredBytesPerUser ||
		(media.Scope == domain.MediaScopeConversation &&
			(conversationPendingCount+1 > limits.MaxPendingCountConversation ||
				conversationPendingBytes+media.ByteSize > limits.MaxPendingBytesConversation ||
				conversationStoredCount+1 > limits.MaxStoredCountConversation ||
				conversationStoredBytes+media.ByteSize > limits.MaxStoredBytesConversation)) {
		return domain.MediaObject{}, domain.ErrQuotaExceeded
	}
	now := time.Now().UTC()
	media.CreatedAt, media.UpdatedAt, media.Status = now, now, "pending"
	expiresAt := now.Add(limits.PendingTTL)
	media.ExpiresAt = &expiresAt
	media.UploadValidUntil = expiresAt
	s.media[media.ID] = media
	return media, nil
}

func (s *Store) Media(_ context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if media.Scope == domain.MediaScopeProfile {
		if media.Status != "ready" && media.OwnerID != actorID {
			return domain.MediaObject{}, domain.ErrForbidden
		}
		return media, nil
	}
	if _, ok := s.members[media.ConversationID][actorID]; !ok {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	return media, nil
}

func (s *Store) ClaimMediaVerification(
	_ context.Context,
	id, actorID uuid.UUID,
	leaseDuration time.Duration,
) (domain.MediaObject, error) {
	if id == uuid.Nil || actorID == uuid.Nil || leaseDuration < time.Second || leaseDuration > 5*time.Minute {
		return domain.MediaObject{}, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	if media.Status == "ready" {
		return media, nil
	}
	if media.Status != "pending" {
		return domain.MediaObject{}, domain.ErrConflict
	}
	now := time.Now().UTC()
	if media.ExpiresAt == nil || !media.ExpiresAt.After(now) {
		return domain.MediaObject{}, domain.ErrMediaExpired
	}
	if media.VerificationLeaseToken != nil && media.VerificationLockedUntil != nil &&
		media.VerificationLockedUntil.After(now) {
		return domain.MediaObject{}, domain.ErrConflict
	}
	leaseToken := uuid.New()
	lockedUntil := now.Add(leaseDuration)
	media.VerificationLeaseToken = &leaseToken
	media.VerificationLockedUntil = &lockedUntil
	media.UpdatedAt = now
	s.media[id] = media
	return media, nil
}

func (s *Store) MarkMediaReady(
	_ context.Context,
	id, actorID, leaseToken uuid.UUID,
	publishedObjectKey string,
) (domain.MediaObject, error) {
	if err := mediakey.Validate(publishedObjectKey); err != nil {
		return domain.MediaObject{}, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	if media.Status == "ready" {
		return media, nil
	}
	if media.Status != "pending" || leaseToken == uuid.Nil ||
		media.VerificationLeaseToken == nil || *media.VerificationLeaseToken != leaseToken ||
		media.VerificationLockedUntil == nil || !media.VerificationLockedUntil.After(time.Now().UTC()) {
		return domain.MediaObject{}, domain.ErrConflict
	}
	if media.ExpiresAt == nil || !media.ExpiresAt.After(time.Now().UTC()) {
		return domain.MediaObject{}, domain.ErrMediaExpired
	}
	stagingObjectKey := media.ObjectKey
	media.ObjectKey = publishedObjectKey
	media.Status = "ready"
	media.UpdatedAt = time.Now().UTC()
	media.ExpiresAt = nil
	media.VerificationLeaseToken = nil
	media.VerificationLockedUntil = nil
	s.media[id] = media
	delete(s.mediaUploadCapabilities, id)
	if stagingObjectKey != publishedObjectKey {
		s.appendExactMediaDeletesAt(
			actorID, []string{stagingObjectKey}, memoryMediaDeleteNotBefore(media.UploadValidUntil),
		)
	}
	if media.Scope == domain.MediaScopeProfile {
		reference := "clustr-media://" + media.ID.String()
		user := s.users[actorID]
		oldReference := user.AvatarURL
		user.AvatarURL = reference
		user.Profile = setProfileMediaReference(user.Profile, reference)
		user.UpdatedAt = media.UpdatedAt
		s.users[actorID] = user
		if oldID := profileMediaID(oldReference); oldID != uuid.Nil && oldID != media.ID {
			if old, ok := s.media[oldID]; ok && old.OwnerID == actorID && old.Scope == domain.MediaScopeProfile && old.Status != "deleted" {
				old.Status = "deleted"
				old.UpdatedAt = media.UpdatedAt
				old.ExpiresAt = nil
				old.VerificationLeaseToken = nil
				old.VerificationLockedUntil = nil
				s.media[oldID] = old
				delete(s.mediaUploadCapabilities, oldID)
				s.appendMediaDeletesAt(
					actorID,
					[]string{old.ObjectKey},
					memoryMediaDeleteNotBefore(old.UploadValidUntil),
				)
			}
		}
	}
	return media, nil
}

func (s *Store) ReleaseMediaVerification(
	_ context.Context,
	id, actorID, leaseToken uuid.UUID,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return domain.ErrForbidden
	}
	if media.Status != "pending" || leaseToken == uuid.Nil ||
		media.VerificationLeaseToken == nil || *media.VerificationLeaseToken != leaseToken {
		return domain.ErrConflict
	}
	media.VerificationLeaseToken = nil
	media.VerificationLockedUntil = nil
	media.UpdatedAt = time.Now().UTC()
	s.media[id] = media
	return nil
}

func (s *Store) RejectMediaVerification(
	ctx context.Context,
	id, actorID, leaseToken uuid.UUID,
) (domain.MediaObject, error) {
	return s.rejectPendingMedia(ctx, id, actorID, leaseToken)
}

func (s *Store) RejectPendingMedia(ctx context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	return s.rejectPendingMedia(ctx, id, actorID, uuid.Nil)
}

func (s *Store) rejectPendingMedia(
	_ context.Context,
	id, actorID, leaseToken uuid.UUID,
) (domain.MediaObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	if media.Status != "pending" {
		return domain.MediaObject{}, domain.ErrConflict
	}
	if leaseToken != uuid.Nil &&
		(media.VerificationLeaseToken == nil || *media.VerificationLeaseToken != leaseToken ||
			media.VerificationLockedUntil == nil || !media.VerificationLockedUntil.After(time.Now().UTC())) {
		return domain.MediaObject{}, domain.ErrConflict
	}
	now := time.Now().UTC()
	deleteNotBefore := memoryMediaDeleteNotBefore(media.UploadValidUntil)
	media.Status = "deleted"
	media.UpdatedAt = now
	media.ExpiresAt = nil
	media.VerificationLeaseToken = nil
	media.VerificationLockedUntil = nil
	s.media[id] = media
	delete(s.mediaUploadCapabilities, id)
	s.appendMediaDeletesAt(actorID, []string{media.ObjectKey}, deleteNotBefore)
	return media, nil
}

func (s *Store) DeleteMedia(_ context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	media, ok := s.media[id]
	if !ok || media.Status == "deleted" {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if media.OwnerID != actorID {
		return domain.MediaObject{}, domain.ErrForbidden
	}
	now := time.Now().UTC()
	deleteNotBefore := memoryMediaDeleteNotBefore(media.UploadValidUntil)
	media.Status = "deleted"
	media.UpdatedAt = now
	media.ExpiresAt = nil
	media.VerificationLeaseToken = nil
	media.VerificationLockedUntil = nil
	s.media[id] = media
	delete(s.mediaUploadCapabilities, id)
	if media.Scope == domain.MediaScopeProfile {
		user := s.users[actorID]
		if profileMediaID(user.AvatarURL) == id {
			user.AvatarURL = ""
			user.Profile = setProfileMediaReference(user.Profile, "")
			user.UpdatedAt = media.UpdatedAt
			s.users[actorID] = user
		}
	}
	s.appendMediaDeletesAt(actorID, []string{media.ObjectKey}, deleteNotBefore)
	return media, nil
}

func (s *Store) ExpirePendingMedia(_ context.Context, cutoff time.Time, limit int) (int, error) {
	if limit < 1 || limit > store.MediaDeleteBatchSize {
		return 0, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	type expiredObject struct {
		id  uuid.UUID
		key string
	}
	objects := make([]expiredObject, 0)
	for id, object := range s.media {
		if object.Status == "pending" && object.ExpiresAt != nil && !object.ExpiresAt.After(cutoff) {
			objects = append(objects, expiredObject{id: id, key: object.ObjectKey})
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].key < objects[j].key })
	if len(objects) > limit {
		objects = objects[:limit]
	}
	keys := make([]string, 0, len(objects))
	for _, expired := range objects {
		object := s.media[expired.id]
		object.Status = "deleted"
		object.UpdatedAt = cutoff
		object.ExpiresAt = nil
		object.VerificationLeaseToken = nil
		object.VerificationLockedUntil = nil
		s.media[expired.id] = object
		delete(s.mediaUploadCapabilities, expired.id)
		keys = append(keys, object.ObjectKey)
	}
	if len(keys) > 0 {
		deleteNotBefore := time.Now().UTC().Add(store.MediaDeleteGrace)
		for _, expired := range objects {
			if candidate := memoryMediaDeleteNotBefore(s.media[expired.id].UploadValidUntil); candidate.After(deleteNotBefore) {
				deleteNotBefore = candidate
			}
		}
		s.appendMediaDeletesAt(uuid.Nil, keys, deleteNotBefore)
	}
	return len(keys), nil
}

func (s *Store) appendMediaDeletesAt(aggregateID uuid.UUID, objectKeys []string, notBefore time.Time) {
	seen := make(map[string]struct{}, len(objectKeys)*2)
	expanded := make([]string, 0, len(objectKeys)*2)
	for _, objectKey := range objectKeys {
		keys, err := mediakey.DeletionKeys(objectKey)
		if err != nil {
			keys = []string{objectKey}
		}
		for _, key := range keys {
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			expanded = append(expanded, key)
		}
	}
	s.appendExactMediaDeletesAt(aggregateID, expanded, notBefore)
}

func (s *Store) appendExactMediaDeletesAt(aggregateID uuid.UUID, objectKeys []string, notBefore time.Time) {
	for start := 0; start < len(objectKeys); start += store.MediaDeleteBatchSize {
		end := min(start+store.MediaDeleteBatchSize, len(objectKeys))
		payload, _ := json.Marshal(store.NewMediaDeletePayloadAt(objectKeys[start:end], notBefore))
		s.appendOutboxAt("media.delete", aggregateID, payload, notBefore)
	}
}

func memoryMediaDeleteNotBefore(uploadValidUntil time.Time) time.Time {
	notBefore := time.Now().UTC().Add(store.MediaDeleteGrace)
	if candidate := uploadValidUntil.UTC().Add(store.MediaDeleteGrace); candidate.After(notBefore) {
		return candidate
	}
	return notBefore
}

func profileMediaID(reference string) uuid.UUID {
	const prefix = "clustr-media://"
	if !strings.HasPrefix(reference, prefix) {
		return uuid.Nil
	}
	id, _ := uuid.Parse(strings.TrimPrefix(reference, prefix))
	return id
}

func setProfileMediaReference(profile json.RawMessage, reference string) json.RawMessage {
	value := make(map[string]any)
	if len(profile) > 0 {
		_ = json.Unmarshal(profile, &value)
	}
	delete(value, "profileImageURL")
	if reference == "" {
		delete(value, "profile_image_url")
	} else {
		value["profile_image_url"] = reference
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return profile
	}
	return encoded
}

func (s *Store) LockOutboxBatch(_ context.Context, limit int) ([]domain.OutboxEvent, error) {
	if limit < 1 {
		return nil, domain.ErrInvalid
	}
	// Compatibility inspection path for tests and development tooling. Durable
	// production workers use the topic-specific claim methods below.
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.OutboxEvent, 0, min(limit, len(s.outbox)))
	for _, event := range s.outbox {
		if event.PublishedAt == nil {
			result = append(result, event)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (s *Store) LockRealtimeOutboxBatch(_ context.Context, limit int) ([]domain.OutboxEvent, error) {
	return s.lockOutboxBatch(limit, "realtime")
}

func (s *Store) LockMediaDeleteOutboxBatch(_ context.Context, limit int) ([]domain.OutboxEvent, error) {
	return s.lockOutboxBatch(limit, "media.delete")
}

func (s *Store) lockOutboxBatch(limit int, claim string) ([]domain.OutboxEvent, error) {
	if limit < 1 {
		return nil, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	result := make([]domain.OutboxEvent, 0, min(limit, len(s.outbox)))
	for index := range s.outbox {
		event := s.outbox[index]
		if event.PublishedAt != nil || (!event.AvailableAt.IsZero() && event.AvailableAt.After(now)) ||
			(event.LockedUntil != nil && event.LockedUntil.After(now)) {
			continue
		}
		if (claim == "realtime" && event.Topic == "media.delete") ||
			(claim == "media.delete" && event.Topic != "media.delete") {
			continue
		}
		lockDuration := 30 * time.Second
		if claim == "media.delete" {
			lockDuration = 30 * time.Minute
		}
		lockedUntil := now.Add(lockDuration)
		event.LockedUntil = &lockedUntil
		event.Attempts++
		s.outbox[index] = event
		result = append(result, event)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (s *Store) ReleaseOutboxEvent(_ context.Context, id int64, availableAt time.Time) error {
	if id < 1 || availableAt.IsZero() {
		return domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.outbox {
		if s.outbox[index].ID != id || s.outbox[index].PublishedAt != nil {
			continue
		}
		s.outbox[index].AvailableAt = availableAt.UTC()
		s.outbox[index].LockedUntil = nil
		return nil
	}
	return domain.ErrNotFound
}

func (s *Store) MarkOutboxPublished(_ context.Context, ids []int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	now := time.Now().UTC()
	for index := range s.outbox {
		if _, ok := set[s.outbox[index].ID]; ok && s.outbox[index].PublishedAt == nil {
			publishedAt := now
			s.outbox[index].PublishedAt = &publishedAt
			s.outbox[index].LockedUntil = nil
		}
	}
	return nil
}

func (s *Store) EnqueuePushDeliveries(
	_ context.Context,
	delivery domain.PushDelivery,
	recipientIDs []uuid.UUID,
) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if delivery.OutboxEventID < 1 || delivery.ConversationID == uuid.Nil ||
		delivery.EntityID == uuid.Nil || strings.TrimSpace(delivery.NotificationID) == "" {
		return 0, domain.ErrInvalid
	}
	recipients := make(map[uuid.UUID]struct{}, len(recipientIDs))
	for _, recipientID := range recipientIDs {
		if recipientID != uuid.Nil {
			recipients[recipientID] = struct{}{}
		}
	}
	inserted := 0
	now := time.Now().UTC()
	for deviceID, device := range s.devices {
		if _, eligible := recipients[device.UserID]; !eligible ||
			device.Platform != "ios" || device.PushToken == "" {
			continue
		}
		key := pushDeliveryKey(delivery.OutboxEventID, deviceID)
		if _, duplicate := s.pushDeliveryByEventDevice[key]; duplicate {
			continue
		}
		queued := delivery
		queued.DeviceID = deviceID
		queued.ID = s.nextPushDeliveryID
		s.nextPushDeliveryID++
		queued.Status = domain.PushDeliveryPending
		queued.Attempts = 0
		queued.NextAttemptAt = now
		queued.CreatedAt = now
		queued.LeaseToken = uuid.Nil
		queued.LockedUntil = time.Time{}
		s.pushDeliveries[queued.ID] = queued
		s.pushDeliveryByEventDevice[key] = queued.ID
		inserted++
	}
	return inserted, nil
}

func (s *Store) LockPushDeliveryBatch(_ context.Context, limit int) ([]domain.PushDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 {
		return nil, domain.ErrInvalid
	}
	now := time.Now().UTC()
	ids := make([]int64, 0, len(s.pushDeliveries))
	for id, delivery := range s.pushDeliveries {
		if delivery.Status == domain.PushDeliveryPending &&
			!delivery.NextAttemptAt.After(now) &&
			(delivery.LockedUntil.IsZero() || !delivery.LockedUntil.After(now)) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		left, right := s.pushDeliveries[ids[i]], s.pushDeliveries[ids[j]]
		if !left.NextAttemptAt.Equal(right.NextAttemptAt) {
			return left.NextAttemptAt.Before(right.NextAttemptAt)
		}
		return ids[i] < ids[j]
	})
	if len(ids) > limit {
		ids = ids[:limit]
	}
	claimed := make([]domain.PushDelivery, 0, len(ids))
	for _, id := range ids {
		delivery := s.pushDeliveries[id]
		delivery.Attempts++
		delivery.LeaseToken = uuid.New()
		delivery.LockedUntil = now.Add(2 * time.Minute)
		if device, ok := s.devices[delivery.DeviceID]; ok {
			delivery.UserID = device.UserID
			delivery.PushToken = device.PushToken
		}
		s.pushDeliveries[id] = delivery
		claimed = append(claimed, delivery)
	}
	return claimed, nil
}

func (s *Store) FinishPushDelivery(
	_ context.Context,
	id int64,
	leaseToken uuid.UUID,
	result string,
	nextAttemptAt time.Time,
	errorClass string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delivery, ok := s.pushDeliveries[id]
	if !ok {
		return domain.ErrNotFound
	}
	if delivery.Status != domain.PushDeliveryPending || delivery.LeaseToken != leaseToken {
		return domain.ErrConflict
	}
	now := time.Now().UTC()
	switch result {
	case domain.PushDeliveryPending:
		if nextAttemptAt.IsZero() {
			nextAttemptAt = now
		}
		delivery.NextAttemptAt = nextAttemptAt
	case domain.PushDeliveryDelivered, domain.PushDeliveryInvalidToken, domain.PushDeliveryCanceled:
		delivery.Status = result
		delivery.DeliveredAt = &now
	case domain.PushDeliveryDeadLetter:
		delivery.Status = result
		delivery.DeadLetteredAt = &now
	default:
		return domain.ErrInvalid
	}
	delivery.LastErrorClass = errorClass
	delivery.LeaseToken = uuid.Nil
	delivery.LockedUntil = time.Time{}
	s.pushDeliveries[id] = delivery
	return nil
}

func (s *Store) InvalidatePushDelivery(
	_ context.Context,
	id int64,
	leaseToken, userID, deviceID uuid.UUID,
	pushToken string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delivery, ok := s.pushDeliveries[id]
	if !ok {
		return domain.ErrNotFound
	}
	if delivery.Status != domain.PushDeliveryPending || delivery.LeaseToken != leaseToken ||
		delivery.DeviceID != deviceID {
		return domain.ErrConflict
	}
	device, ok := s.devices[deviceID]
	if !ok || device.UserID != userID {
		return domain.ErrNotFound
	}
	if device.PushToken == pushToken {
		device.PushToken = ""
		s.devices[deviceID] = device
	}
	now := time.Now().UTC()
	delivery.Status = domain.PushDeliveryInvalidToken
	delivery.DeliveredAt = &now
	delivery.LastErrorClass = "invalid_token"
	delivery.LeaseToken = uuid.Nil
	delivery.LockedUntil = time.Time{}
	s.pushDeliveries[id] = delivery
	return nil
}

func (s *Store) PrunePushDeliveries(
	_ context.Context,
	deliveredBefore, deadLetterBefore time.Time,
	limit int,
) (int64, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return 0, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unpublishedOutbox := make(map[int64]struct{}, len(s.outbox))
	for _, event := range s.outbox {
		if event.PublishedAt == nil {
			unpublishedOutbox[event.ID] = struct{}{}
		}
	}
	candidates := make([]domain.PushDelivery, 0, len(s.pushDeliveries))
	for id, delivery := range s.pushDeliveries {
		if _, sourcePending := unpublishedOutbox[delivery.OutboxEventID]; sourcePending {
			continue
		}
		remove := (delivery.Status == domain.PushDeliveryDelivered ||
			delivery.Status == domain.PushDeliveryInvalidToken ||
			delivery.Status == domain.PushDeliveryCanceled) &&
			delivery.DeliveredAt != nil && delivery.DeliveredAt.Before(deliveredBefore)
		remove = remove || (delivery.Status == domain.PushDeliveryDeadLetter &&
			delivery.DeadLetteredAt != nil && delivery.DeadLetteredAt.Before(deadLetterBefore))
		if !remove {
			continue
		}
		delivery.ID = id
		candidates = append(candidates, delivery)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := terminalPushTime(candidates[i]), terminalPushTime(candidates[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return candidates[i].ID < candidates[j].ID
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	for _, delivery := range candidates {
		delete(s.pushDeliveries, delivery.ID)
		delete(s.pushDeliveryByEventDevice, pushDeliveryKey(delivery.OutboxEventID, delivery.DeviceID))
	}
	return int64(len(candidates)), nil
}

func (s *Store) PrunePublishedOutbox(
	_ context.Context,
	publishedBefore time.Time,
	limit int,
) (int64, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return 0, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	referenced := make(map[int64]struct{}, len(s.pushDeliveries))
	for _, delivery := range s.pushDeliveries {
		referenced[delivery.OutboxEventID] = struct{}{}
	}
	candidates := make([]domain.OutboxEvent, 0, len(s.outbox))
	for _, event := range s.outbox {
		if event.PublishedAt == nil || !event.PublishedAt.Before(publishedBefore) {
			continue
		}
		if _, retained := referenced[event.ID]; retained {
			continue
		}
		candidates = append(candidates, event)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].PublishedAt.Equal(*candidates[j].PublishedAt) {
			return candidates[i].PublishedAt.Before(*candidates[j].PublishedAt)
		}
		return candidates[i].ID < candidates[j].ID
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	selected := make(map[int64]struct{}, len(candidates))
	for _, event := range candidates {
		selected[event.ID] = struct{}{}
	}
	retained := s.outbox[:0]
	for _, event := range s.outbox {
		if _, remove := selected[event.ID]; !remove {
			retained = append(retained, event)
		}
	}
	s.outbox = retained
	return int64(len(candidates)), nil
}

func (s *Store) appendOutbox(topic string, aggregateID uuid.UUID, payload []byte) {
	s.appendOutboxAt(topic, aggregateID, payload, time.Now().UTC())
}

func (s *Store) appendOutboxAt(
	topic string,
	aggregateID uuid.UUID,
	payload []byte,
	availableAt time.Time,
) {
	s.outbox = append(s.outbox, domain.OutboxEvent{
		ID: s.nextOutboxID, Topic: topic, AggregateID: aggregateID,
		Payload: cloneJSON(payload), CreatedAt: time.Now().UTC(), AvailableAt: availableAt.UTC(),
	})
	s.nextOutboxID++
}

func pushDeliveryKey(outboxEventID int64, deviceID uuid.UUID) string {
	return strconv.FormatInt(outboxEventID, 10) + ":" + deviceID.String()
}

func terminalPushTime(delivery domain.PushDelivery) time.Time {
	if delivery.DeadLetteredAt != nil {
		return *delivery.DeadLetteredAt
	}
	if delivery.DeliveredAt != nil {
		return *delivery.DeliveredAt
	}
	return time.Time{}
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
