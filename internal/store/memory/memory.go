package memory

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
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
	// deliveryBarrier serializes account erasure with the small interval in
	// which a claimed realtime/APNs row is revalidated and handed to an
	// external transport.  It is deliberately separate from mu: delivery
	// callbacks may call ordinary Store methods without recursively acquiring
	// the data lock.
	deliveryBarrier sync.RWMutex
	// deviceDeliveryBarrier keeps APNs token ownership stable from the exact
	// delivery/device re-fetch through the external send. Token registration,
	// transfer, reset, and invalidation take the write side before mu.
	deviceDeliveryBarrier sync.RWMutex

	users                     map[uuid.UUID]domain.User
	emailToUser               map[string]uuid.UUID
	phoneToUser               map[string]uuid.UUID
	usernameToUser            map[string]uuid.UUID
	externalUsers             map[string]uuid.UUID
	ageAssurances             map[uuid.UUID]domain.AgeAssurance
	passwordResets            map[uuid.UUID]domain.PasswordResetChallenge
	accountDeletionIntents    map[uuid.UUID]domain.AccountDeletionIntent
	mailDeliveries            map[uuid.UUID]domain.MailDelivery
	devices                   map[uuid.UUID]domain.Device
	preKeys                   map[uuid.UUID][]domain.OneTimePreKey
	sessions                  map[uuid.UUID]domain.Session
	conversations             map[uuid.UUID]domain.Conversation
	members                   map[uuid.UUID]map[uuid.UUID]domain.ConversationMember
	memberLocalIDs            map[uuid.UUID]map[uuid.UUID]uuid.UUID
	memberTombstones          map[uuid.UUID]map[uuid.UUID]store.ConversationMemberTombstone
	invites                   map[uuid.UUID]map[string]uuid.UUID
	inviteLinks               map[string]domain.ConversationInvite
	inviteLinkKeys            map[uuid.UUID]string
	messages                  map[uuid.UUID][]domain.Message
	clientMessages            map[string]domain.Message
	receipts                  map[string]domain.Receipt
	entities                  map[string]domain.Entity
	choreRotations            map[uuid.UUID]memoryChoreRotation
	media                     map[uuid.UUID]domain.MediaObject
	mediaUploadCapabilities   map[uuid.UUID]string
	outbox                    []domain.OutboxEvent
	nextOutboxID              int64
	activeRealtimeDeliveries  map[int64]int
	pushDeliveries            map[int64]domain.PushDelivery
	pushDeliveryByEventDevice map[string]int64
	nextPushDeliveryID        int64
	activePushDeliveries      map[int64]uuid.UUID
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
		accountDeletionIntents:    make(map[uuid.UUID]domain.AccountDeletionIntent),
		mailDeliveries:            make(map[uuid.UUID]domain.MailDelivery),
		devices:                   make(map[uuid.UUID]domain.Device),
		preKeys:                   make(map[uuid.UUID][]domain.OneTimePreKey),
		sessions:                  make(map[uuid.UUID]domain.Session),
		conversations:             make(map[uuid.UUID]domain.Conversation),
		members:                   make(map[uuid.UUID]map[uuid.UUID]domain.ConversationMember),
		memberLocalIDs:            make(map[uuid.UUID]map[uuid.UUID]uuid.UUID),
		memberTombstones:          make(map[uuid.UUID]map[uuid.UUID]store.ConversationMemberTombstone),
		invites:                   make(map[uuid.UUID]map[string]uuid.UUID),
		inviteLinks:               make(map[string]domain.ConversationInvite),
		inviteLinkKeys:            make(map[uuid.UUID]string),
		messages:                  make(map[uuid.UUID][]domain.Message),
		clientMessages:            make(map[string]domain.Message),
		receipts:                  make(map[string]domain.Receipt),
		entities:                  make(map[string]domain.Entity),
		choreRotations:            make(map[uuid.UUID]memoryChoreRotation),
		media:                     make(map[uuid.UUID]domain.MediaObject),
		mediaUploadCapabilities:   make(map[uuid.UUID]string),
		nextOutboxID:              1,
		activeRealtimeDeliveries:  make(map[int64]int),
		pushDeliveries:            make(map[int64]domain.PushDelivery),
		pushDeliveryByEventDevice: make(map[string]int64),
		nextPushDeliveryID:        1,
		activePushDeliveries:      make(map[int64]uuid.UUID),
	}
}

type memoryChoreRotation struct {
	ConversationID, ActorID, ChoreID uuid.UUID
	RequestHash                      []byte
	Result                           store.RotateChoreResult
	ExpiresAt                        time.Time
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
	if user, ok := s.users[userID]; !ok || string(user.Profile) == `{"deleted":true}` {
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
	s.deliveryBarrier.Lock()
	defer s.deliveryBarrier.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteAccountLocked(userID)
}

func (s *Store) PutAccountDeletionIntent(_ context.Context, intent domain.AccountDeletionIntent) error {
	if intent.RequestID == uuid.Nil || intent.UserID == uuid.Nil || len(intent.TokenHash) != 32 {
		return domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, live := s.users[intent.UserID]
	if !live || string(user.Profile) == `{"deleted":true}` {
		return domain.ErrNotFound
	}
	if existing, found := s.accountDeletionIntents[intent.RequestID]; found {
		if existing.UserID != intent.UserID || subtle.ConstantTimeCompare(existing.TokenHash, intent.TokenHash) != 1 {
			return domain.ErrConflict
		}
		return nil
	}
	intent.TokenHash = append([]byte(nil), intent.TokenHash...)
	intent.State = domain.AccountDeletionPending
	intent.CreatedAt = time.Now().UTC()
	s.accountDeletionIntents[intent.RequestID] = intent
	return nil
}

func (s *Store) ExecuteAccountDeletionIntent(
	_ context.Context,
	requestID uuid.UUID,
	tokenHash []byte,
	fence store.AccountDeletionFence,
) error {
	if requestID == uuid.Nil || len(tokenHash) != 32 || fence == nil {
		return domain.ErrNotFound
	}
	s.deliveryBarrier.Lock()
	defer s.deliveryBarrier.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	intent, found := s.accountDeletionIntents[requestID]
	if !found || subtle.ConstantTimeCompare(intent.TokenHash, tokenHash) != 1 {
		return domain.ErrNotFound
	}
	if intent.State == domain.AccountDeletionCompleted {
		return nil
	}
	if intent.State != domain.AccountDeletionPending {
		return domain.ErrNotFound
	}
	if err := fence(intent.UserID); err != nil {
		return err
	}
	if err := s.deleteAccountLocked(intent.UserID); err != nil && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	now := time.Now().UTC()
	intent.State = domain.AccountDeletionCompleted
	intent.CompletedAt = &now
	s.accountDeletionIntents[requestID] = intent
	return nil
}

func (s *Store) deleteAccountLocked(userID uuid.UUID) error {
	user, ok := s.users[userID]
	if !ok || string(user.Profile) == `{"deleted":true}` {
		return domain.ErrNotFound
	}
	identity := store.AccountIdentity{
		UserID: userID, Email: user.Email, Phone: user.Phone,
		DisplayName: user.DisplayName, Username: profileUsername(user.Profile),
	}
	// Memory has no transactional rollback. Validate every shared, durable JSON
	// document before the first mutation so malformed metadata/entity payloads
	// fail closed with the same behavior as PostgreSQL without leaving a partial
	// account deletion behind.
	if err := s.validateAccountDeletionJSONLocked(userID, identity); err != nil {
		return err
	}
	now := time.Now().UTC()
	deletedConversations := make(map[uuid.UUID]struct{})
	sharedConversations := make(map[uuid.UUID]struct{})
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
			delete(s.memberLocalIDs, conversationID)
			delete(s.memberTombstones, conversationID)
			delete(s.invites, conversationID)
			delete(s.messages, conversationID)
			continue
		}
		sharedConversations[conversationID] = struct{}{}

		successor := oldestMember(members, userID)
		conversation := s.conversations[conversationID]
		if conversation.CreatedBy == userID {
			conversation.CreatedBy = successor.UserID
		}
		if metadata, changed, err := store.AnonymizeAccountJSON(conversation.Metadata, identity); err != nil {
			return err
		} else if changed {
			conversation.Metadata = metadata
		}
		conversation.UpdatedAt = now
		s.conversations[conversationID] = conversation
		if members[userID].Role == "owner" {
			successor.Role = "owner"
			members[successor.UserID] = successor
		}
		if s.memberTombstones[conversationID] == nil {
			s.memberTombstones[conversationID] = make(map[uuid.UUID]store.ConversationMemberTombstone)
		}
		localID := s.memberLocalIDs[conversationID][userID]
		if localID == uuid.Nil {
			localID = userID
		}
		s.memberTombstones[conversationID][userID] = store.ConversationMemberTombstone{
			UserID: userID, LocalID: localID,
		}
		delete(members, userID)
		s.projectConversationMembersLocked(conversationID)
		delete(s.receipts, conversationID.String()+":"+userID.String())

		for key, entity := range s.entities {
			if entity.ConversationID != conversationID {
				continue
			}
			referencesIdentity, err := store.AccountJSONReferencesIdentity(entity.Payload, identity)
			if err != nil {
				return err
			}
			if entity.CreatedBy != userID && !referencesIdentity {
				continue
			}
			payload, changed, err := store.AnonymizeAccountJSONWithAuthority(entity.Payload, identity)
			if err != nil {
				return err
			}
			if !changed {
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
	for operationID, operation := range s.choreRotations {
		if _, deleted := deletedConversations[operation.ConversationID]; deleted {
			delete(s.choreRotations, operationID)
			continue
		}
		if _, shared := sharedConversations[operation.ConversationID]; !shared {
			continue
		}
		chorePayload, choreChanged, choreErr := store.AnonymizeAccountJSON(
			operation.Result.Chore.Payload, identity,
		)
		feedPayload, feedChanged, feedErr := store.AnonymizeAccountJSON(
			operation.Result.FeedItem.Payload, identity,
		)
		// An operation result is a replay cache, not the source of financial
		// truth. Fail closed by discarding an unexpectedly malformed snapshot
		// instead of retaining identity data account deletion cannot inspect.
		if choreErr != nil || feedErr != nil {
			delete(s.choreRotations, operationID)
			continue
		}
		if choreChanged {
			operation.Result.Chore.Payload = chorePayload
		}
		if feedChanged {
			operation.Result.FeedItem.Payload = feedPayload
		}
		if choreChanged || feedChanged {
			s.choreRotations[operationID] = operation
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
			for deliveryID, delivery := range s.mailDeliveries {
				if delivery.ChallengeID == challengeID {
					delete(s.mailDeliveries, deliveryID)
				}
			}
		}
	}
	for sessionID, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, sessionID)
		}
	}
	deletedDeviceIDs := make(map[uuid.UUID]struct{})
	for deviceID, device := range s.devices {
		if device.UserID != userID {
			continue
		}
		deletedDeviceIDs[deviceID] = struct{}{}
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
	affectedEntities := make(map[string]struct{}, len(updatedEntities))
	for _, entity := range updatedEntities {
		affectedEntities[entity.ConversationID.String()+"\x00"+entity.Kind+"\x00"+entity.ID.String()] = struct{}{}
	}
	for _, event := range s.outbox {
		_, deleted := deletedConversations[event.AggregateID]
		if deleted {
			removedOutboxIDs[event.ID] = struct{}{}
			continue
		}
		if _, shared := sharedConversations[event.AggregateID]; shared &&
			store.AccountErasureOutboxTopic(event.Topic) {
			typed, schemaErr := store.DecodeAccountOutboxPayload(
				event.Topic, event.AggregateID, event.Payload,
			)
			if schemaErr != nil {
				// Known-topic transport state is disposable. A row outside the
				// exact service-owned schema cannot safely be replayed after erasure.
				removedOutboxIDs[event.ID] = struct{}{}
				continue
			}
			if (event.Topic == "receipt.updated" || event.Topic == "conversation.member_added") &&
				(typed.UserID == userID || typed.ActorID == userID) {
				removedOutboxIDs[event.ID] = struct{}{}
				continue
			}
			if event.Topic == "receipt.updated" || event.Topic == "conversation.member_added" {
				filtered = append(filtered, event)
				continue
			}
			authorized, err := store.AccountJSONReferencesIdentity(event.Payload, identity)
			if err != nil {
				removedOutboxIDs[event.ID] = struct{}{}
				continue
			}
			if event.Topic == "entity.updated" || event.Topic == "entity.deleted" {
				_, entityAffected := affectedEntities[typed.ConversationID.String()+"\x00"+typed.EntityKind+"\x00"+typed.EntityID.String()]
				authorized = authorized || entityAffected
			}
			if !authorized {
				filtered = append(filtered, event)
				continue
			}
			_, changed, err := store.AnonymizeAccountJSONWithAuthority(event.Payload, identity)
			if err != nil || changed {
				removedOutboxIDs[event.ID] = struct{}{}
				continue
			}
		}
		filtered = append(filtered, event)
	}
	s.outbox = filtered
	for deliveryID, delivery := range s.pushDeliveries {
		_, removedSource := removedOutboxIDs[delivery.OutboxEventID]
		_, deletedRecipient := deletedDeviceIDs[delivery.DeviceID]
		if !removedSource && !deletedRecipient {
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

func (s *Store) validateAccountDeletionJSONLocked(
	userID uuid.UUID,
	identity store.AccountIdentity,
) error {
	for conversationID, members := range s.members {
		if _, present := members[userID]; !present || len(members) < 2 {
			continue
		}
		if _, _, err := store.AnonymizeAccountJSON(
			s.conversations[conversationID].Metadata, identity,
		); err != nil {
			return err
		}
		for _, entity := range s.entities {
			if entity.ConversationID != conversationID {
				continue
			}
			referencesIdentity, err := store.AccountJSONReferencesIdentity(entity.Payload, identity)
			if err != nil {
				return err
			}
			if entity.CreatedBy != userID && !referencesIdentity {
				continue
			}
			if _, _, err := store.AnonymizeAccountJSONWithAuthority(entity.Payload, identity); err != nil {
				return err
			}
		}
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

func (s *Store) UpsertDevice(_ context.Context, device domain.Device) (domain.Device, error) {
	s.deviceDeliveryBarrier.Lock()
	defer s.deviceDeliveryBarrier.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	user, live := s.users[device.UserID]
	if !live || string(user.Profile) == `{"deleted":true}` {
		return domain.Device{}, domain.ErrNotFound
	}
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
	s.deviceDeliveryBarrier.Lock()
	defer s.deviceDeliveryBarrier.Unlock()
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
	user, live := s.users[session.UserID]
	device, deviceExists := s.devices[session.DeviceID]
	if !live || string(user.Profile) == `{"deleted":true}` || !deviceExists || device.UserID != session.UserID {
		return domain.ErrUnauthenticated
	}
	s.sessions[session.ID] = session
	return nil
}

func (s *Store) IssueSession(
	_ context.Context,
	p store.SessionIssueParams,
) (domain.User, domain.Device, error) {
	if p.UserID == uuid.Nil || p.Device.ID == uuid.Nil || p.Device.UserID != p.UserID ||
		p.Session.ID == uuid.Nil || p.Session.UserID != p.UserID ||
		p.Session.DeviceID != p.Device.ID || len(p.Session.RefreshTokenHash) == 0 {
		return domain.User{}, domain.Device{}, domain.ErrInvalid
	}
	s.deviceDeliveryBarrier.Lock()
	defer s.deviceDeliveryBarrier.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[p.UserID]
	if !ok || string(user.Profile) == `{"deleted":true}` {
		return domain.User{}, domain.Device{}, domain.ErrUnauthenticated
	}
	if p.RequirePasswordHashMatch && subtle.ConstantTimeCompare(
		[]byte(user.PasswordHash), []byte(p.ExpectedPasswordHash),
	) != 1 {
		return domain.User{}, domain.Device{}, domain.ErrUnauthenticated
	}
	device := p.Device
	device.PushToken = strings.ToLower(strings.TrimSpace(device.PushToken))
	if existing, exists := s.devices[device.ID]; exists && existing.UserID != device.UserID {
		return domain.User{}, domain.Device{}, domain.ErrConflict
	} else if exists {
		if device.PushToken == "" {
			device.PushToken = existing.PushToken
		}
		if device.IdentityKey == "" {
			device.IdentityKey = existing.IdentityKey
		}
		if len(device.SignedPreKey) == 0 {
			device.SignedPreKey = cloneJSON(existing.SignedPreKey)
		}
		device.CreatedAt = existing.CreatedAt
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}
	device.LastSeenAt = time.Now().UTC()
	if device.PushToken != "" {
		for id, existing := range s.devices {
			if id != device.ID && strings.EqualFold(existing.PushToken, device.PushToken) {
				existing.PushToken = ""
				s.devices[id] = existing
			}
		}
	}
	s.devices[device.ID] = device
	s.sessions[p.Session.ID] = p.Session
	return user, device, nil
}

func (s *Store) RotateSession(_ context.Context, id uuid.UUID, oldHash, newHash []byte, expiresAt time.Time) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	user, live := s.users[session.UserID]
	if !ok || !live || string(user.Profile) == `{"deleted":true}` ||
		session.RevokedAt != nil || session.ExpiresAt.Before(time.Now()) {
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
	user, live := s.users[userID]
	if !ok || !live || string(user.Profile) == `{"deleted":true}` {
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
	memberIDs := append([]uuid.UUID{p.CreatedBy}, p.MemberIDs...)
	for _, id := range uniqueUUIDs(memberIDs) {
		user, exists := s.users[id]
		if !exists || string(user.Profile) == `{"deleted":true}` {
			return domain.Conversation{}, domain.ErrNotFound
		}
	}
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
	s.memberLocalIDs[conversation.ID] = make(map[uuid.UUID]uuid.UUID)
	s.memberTombstones[conversation.ID] = make(map[uuid.UUID]store.ConversationMemberTombstone)
	s.invites[conversation.ID] = make(map[string]uuid.UUID)
	rollbackConversation := func() {
		delete(s.conversations, conversation.ID)
		delete(s.members, conversation.ID)
		delete(s.memberLocalIDs, conversation.ID)
		delete(s.memberTombstones, conversation.ID)
		delete(s.invites, conversation.ID)
	}
	for _, id := range uniqueUUIDs(memberIDs) {
		role := "member"
		if id == p.CreatedBy {
			role = "owner"
		}
		s.members[conversation.ID][id] = domain.ConversationMember{
			ConversationID: conversation.ID, UserID: id, Role: role, JoinedAt: now,
		}
	}
	if conversation.Kind == "group" {
		members := s.conversationMembersLocked(conversation.ID)
		localIDs, err := s.ensureConversationMemberLocalIDsLocked(conversation.ID, conversation.Metadata, members)
		if err != nil {
			rollbackConversation()
			return domain.Conversation{}, err
		}
		conversation.Metadata, err = store.ProjectConversationMembersWithLocalIDs(
			conversation.Metadata, members, localIDs,
			s.conversationMemberTombstonesLocked(conversation.ID)...,
		)
		if err != nil {
			rollbackConversation()
			return domain.Conversation{}, err
		}
		s.conversations[conversation.ID] = conversation
	} else {
		members := s.conversationMembersLocked(conversation.ID)
		if _, err := s.ensureConversationMemberLocalIDsLocked(conversation.ID, conversation.Metadata, members); err != nil {
			rollbackConversation()
			return domain.Conversation{}, err
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
	if conversation.Kind == "group" {
		members := s.conversationMembersLocked(conversationID)
		localIDs, err := s.ensureConversationMemberLocalIDsLocked(conversationID, conversation.Metadata, members)
		if err != nil {
			return domain.Conversation{}, err
		}
		conversation.Metadata, err = store.ProjectConversationMembersWithLocalIDs(
			conversation.Metadata, members, localIDs,
			s.conversationMemberTombstonesLocked(conversationID)...,
		)
		if err != nil {
			return domain.Conversation{}, err
		}
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
	delete(s.memberLocalIDs, conversationID)
	delete(s.memberTombstones, conversationID)
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
		// Do not reveal whether a high-entropy conversation identifier exists.
		return domain.Conversation{}, domain.ErrNotFound
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
	return s.conversationMembersLocked(conversationID), nil
}

func (s *Store) conversationMembersLocked(conversationID uuid.UUID) []domain.ConversationMember {
	members := s.members[conversationID]
	result := make([]domain.ConversationMember, 0, len(members))
	for _, member := range members {
		if user, ok := s.users[member.UserID]; ok {
			member = store.ConversationMemberWithPublicIdentity(member, user)
		}
		result = append(result, member)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].JoinedAt.Equal(result[j].JoinedAt) {
			return result[i].UserID.String() < result[j].UserID.String()
		}
		return result[i].JoinedAt.Before(result[j].JoinedAt)
	})
	return result
}

func (s *Store) projectConversationMembersLocked(conversationID uuid.UUID) error {
	conversation, ok := s.conversations[conversationID]
	if !ok || conversation.Kind != "group" {
		return nil
	}
	localIDs, err := s.ensureConversationMemberLocalIDsLocked(
		conversationID, conversation.Metadata, s.conversationMembersLocked(conversationID),
	)
	if err != nil {
		return err
	}
	conversation.Metadata, err = store.ProjectConversationMembersWithLocalIDs(
		conversation.Metadata, s.conversationMembersLocked(conversationID),
		localIDs,
		s.conversationMemberTombstonesLocked(conversationID)...,
	)
	if err != nil {
		return err
	}
	s.conversations[conversationID] = conversation
	return nil
}

func (s *Store) planConversationMemberLocalIDsLocked(
	conversationID uuid.UUID,
	metadata json.RawMessage,
	members []domain.ConversationMember,
) ([]store.ConversationMemberLocalID, error) {
	existing := make([]store.ConversationMemberLocalID, 0, len(s.memberLocalIDs[conversationID]))
	for userID, localID := range s.memberLocalIDs[conversationID] {
		existing = append(existing, store.ConversationMemberLocalID{UserID: userID, LocalID: localID})
	}
	derived := store.DeriveConversationMemberLocalIDs(metadata, members, existing)
	all := append([]store.ConversationMemberLocalID(nil), existing...)
	existingUsers := make(map[uuid.UUID]struct{}, len(existing))
	for _, mapping := range existing {
		existingUsers[mapping.UserID] = struct{}{}
	}
	for _, mapping := range derived {
		if _, immutable := existingUsers[mapping.UserID]; !immutable {
			all = append(all, mapping)
		}
	}
	if err := store.ValidateConversationMemberLocalIDNamespace(members, all); err != nil {
		return nil, err
	}
	allByUser := make(map[uuid.UUID]uuid.UUID, len(all))
	for _, mapping := range all {
		allByUser[mapping.UserID] = mapping.LocalID
	}
	result := make([]store.ConversationMemberLocalID, 0, len(members))
	for _, member := range members {
		localID, exists := allByUser[member.UserID]
		if !exists {
			return nil, domain.ErrConflict
		}
		result = append(result, store.ConversationMemberLocalID{
			UserID: member.UserID, LocalID: localID,
		})
	}
	return result, nil
}

func (s *Store) commitConversationMemberLocalIDsLocked(
	conversationID uuid.UUID,
	mappings []store.ConversationMemberLocalID,
) {
	if s.memberLocalIDs[conversationID] == nil {
		s.memberLocalIDs[conversationID] = make(map[uuid.UUID]uuid.UUID)
	}
	for _, mapping := range mappings {
		if _, immutable := s.memberLocalIDs[conversationID][mapping.UserID]; !immutable {
			s.memberLocalIDs[conversationID][mapping.UserID] = mapping.LocalID
		}
	}
}

func (s *Store) ensureConversationMemberLocalIDsLocked(
	conversationID uuid.UUID,
	metadata json.RawMessage,
	members []domain.ConversationMember,
) ([]store.ConversationMemberLocalID, error) {
	planned, err := s.planConversationMemberLocalIDsLocked(conversationID, metadata, members)
	if err != nil {
		return nil, err
	}
	s.commitConversationMemberLocalIDsLocked(conversationID, planned)
	return planned, nil
}

func (s *Store) conversationMemberTombstonesLocked(conversationID uuid.UUID) []store.ConversationMemberTombstone {
	byUser := s.memberTombstones[conversationID]
	result := make([]store.ConversationMemberTombstone, 0, len(byUser))
	for _, tombstone := range byUser {
		result = append(result, tombstone)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UserID.String() < result[j].UserID.String() })
	return result
}

func (s *Store) prospectiveConversationMembersLocked(
	conversationID uuid.UUID,
	candidate domain.ConversationMember,
) []domain.ConversationMember {
	members := s.conversationMembersLocked(conversationID)
	if user, ok := s.users[candidate.UserID]; ok {
		candidate = store.ConversationMemberWithPublicIdentity(candidate, user)
	}
	replaced := false
	for index := range members {
		if members[index].UserID == candidate.UserID {
			members[index] = candidate
			replaced = true
			break
		}
	}
	if !replaced {
		members = append(members, candidate)
	}
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].JoinedAt.Equal(members[j].JoinedAt) {
			return members[i].UserID.String() < members[j].UserID.String()
		}
		return members[i].JoinedAt.Before(members[j].JoinedAt)
	})
	return members
}

func (s *Store) planConversationMembershipProjectionLocked(
	conversationID uuid.UUID,
	metadata json.RawMessage,
	members []domain.ConversationMember,
	joiningUserID uuid.UUID,
) ([]store.ConversationMemberLocalID, json.RawMessage, error) {
	planned, err := s.planConversationMemberLocalIDsLocked(conversationID, metadata, members)
	if err != nil {
		return nil, nil, err
	}
	tombstones := s.conversationMemberTombstonesLocked(conversationID)
	filtered := tombstones[:0]
	for _, tombstone := range tombstones {
		if tombstone.UserID != joiningUserID {
			filtered = append(filtered, tombstone)
		}
	}
	projected, err := store.ProjectConversationMembersWithLocalIDs(metadata, members, planned, filtered...)
	if err != nil {
		return nil, nil, err
	}
	return planned, projected, nil
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
	if role != "member" && role != "admin" {
		return domain.ErrInvalid
	}
	if user, exists := s.users[userID]; !exists || string(user.Profile) == `{"deleted":true}` {
		return domain.ErrNotFound
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
	joinedAt := time.Now().UTC()
	if targetExists {
		joinedAt = target.JoinedAt
	}
	candidate := domain.ConversationMember{
		ConversationID: conversationID, UserID: userID, Role: role, JoinedAt: joinedAt,
	}
	prospective := s.prospectiveConversationMembersLocked(conversationID, candidate)
	planned, projected, err := s.planConversationMembershipProjectionLocked(
		conversationID, s.conversations[conversationID].Metadata, prospective, userID,
	)
	if err != nil {
		return err
	}
	members[userID] = candidate
	delete(s.memberTombstones[conversationID], userID)
	s.commitConversationMemberLocalIDsLocked(conversationID, planned)
	conversation := s.conversations[conversationID]
	conversation.Metadata = projected
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
	if user, exists := s.users[userID]; !exists || string(user.Profile) == `{"deleted":true}` {
		return nil, domain.ErrNotFound
	}
	type claimPlan struct {
		conversationID uuid.UUID
		candidate      domain.ConversationMember
		joined         bool
		localIDs       []store.ConversationMemberLocalID
		metadata       json.RawMessage
	}
	var conversationIDs []uuid.UUID
	for conversationID, phones := range s.invites {
		if _, ok := phones[phone]; ok {
			conversationIDs = append(conversationIDs, conversationID)
		}
	}
	sort.Slice(conversationIDs, func(i, j int) bool { return conversationIDs[i].String() < conversationIDs[j].String() })
	now := time.Now().UTC()
	plans := make([]claimPlan, 0, len(conversationIDs))
	for _, conversationID := range conversationIDs {
		conversation, exists := s.conversations[conversationID]
		if !exists {
			return nil, domain.ErrNotFound
		}
		if conversation.Kind != "group" {
			return nil, domain.ErrInvalid
		}
		candidate, alreadyMember := s.members[conversationID][userID]
		if !alreadyMember {
			if len(s.members[conversationID]) >= 1024 {
				return nil, domain.ErrInvalid
			}
			candidate = domain.ConversationMember{
				ConversationID: conversationID, UserID: userID, Role: "member", JoinedAt: now,
			}
		}
		prospective := s.prospectiveConversationMembersLocked(conversationID, candidate)
		localIDs, metadata, err := s.planConversationMembershipProjectionLocked(
			conversationID, conversation.Metadata, prospective, userID,
		)
		if err != nil {
			return nil, err
		}
		plans = append(plans, claimPlan{
			conversationID: conversationID, candidate: candidate, joined: !alreadyMember,
			localIDs: localIDs, metadata: metadata,
		})
	}
	claimed := make([]uuid.UUID, 0, len(plans))
	for _, plan := range plans {
		delete(s.invites[plan.conversationID], phone)
		if plan.joined {
			s.members[plan.conversationID][userID] = plan.candidate
			payload, _ := json.Marshal(domain.ConversationMemberAdded{
				ConversationID: plan.conversationID, ActorID: userID, UserID: userID,
			})
			s.appendOutbox("conversation.member_added", plan.conversationID, payload)
		}
		delete(s.memberTombstones[plan.conversationID], userID)
		s.commitConversationMemberLocalIDsLocked(plan.conversationID, plan.localIDs)
		conversation := s.conversations[plan.conversationID]
		conversation.Metadata = plan.metadata
		conversation.UpdatedAt = now
		s.conversations[plan.conversationID] = conversation
		claimed = append(claimed, plan.conversationID)
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
	conversation, ok := s.conversations[invite.ConversationID]
	if !ok {
		return domain.ConversationInvitePreview{}, domain.ErrNotFound
	}
	_, alreadyMember := s.members[invite.ConversationID][userID]
	if !alreadyMember {
		if err := conversationInviteActiveError(invite, time.Now()); err != nil {
			return domain.ConversationInvitePreview{}, err
		}
	}
	return domain.ConversationInvitePreview{
		InviteID: invite.ID, Kind: conversation.Kind, Title: conversation.Title,
		AvatarURL: conversation.AvatarURL, ExpiresAt: invite.ExpiresAt,
		AlreadyMember: alreadyMember,
	}, nil
}

func (s *Store) AcceptConversationInvite(_ context.Context, tokenHash []byte, userID uuid.UUID) (domain.ConversationInviteAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user, exists := s.users[userID]; !exists || string(user.Profile) == `{"deleted":true}` {
		return domain.ConversationInviteAcceptance{}, domain.ErrNotFound
	}
	tokenKey := string(tokenHash)
	invite, ok := s.inviteLinks[tokenKey]
	if !ok {
		return domain.ConversationInviteAcceptance{}, domain.ErrNotFound
	}
	now := time.Now().UTC()
	conversation, ok := s.conversations[invite.ConversationID]
	if !ok {
		return domain.ConversationInviteAcceptance{}, domain.ErrNotFound
	}
	members := s.members[invite.ConversationID]
	if _, alreadyMember := members[userID]; alreadyMember {
		activeMembers := s.conversationMembersLocked(conversation.ID)
		localIDs, err := s.ensureConversationMemberLocalIDsLocked(conversation.ID, conversation.Metadata, activeMembers)
		if err != nil {
			return domain.ConversationInviteAcceptance{}, err
		}
		projected, err := store.ProjectConversationMembersWithLocalIDs(
			conversation.Metadata, activeMembers, localIDs,
			s.conversationMemberTombstonesLocked(conversation.ID)...,
		)
		if err != nil {
			return domain.ConversationInviteAcceptance{}, err
		}
		if !store.JSONValuesEqual(projected, conversation.Metadata) {
			conversation.Metadata = projected
			conversation.UpdatedAt = now
			s.conversations[conversation.ID] = conversation
		}
		return domain.ConversationInviteAcceptance{Conversation: conversation, Joined: false}, nil
	}
	if invite.RevokedAt != nil {
		return domain.ConversationInviteAcceptance{}, domain.ErrInviteRevoked
	}
	if !invite.ExpiresAt.After(now) {
		return domain.ConversationInviteAcceptance{}, domain.ErrInviteExpired
	}
	if invite.Uses >= invite.MaxUses {
		return domain.ConversationInviteAcceptance{}, domain.ErrInviteExhausted
	}
	if conversation.Kind != "group" || len(members) >= 1024 {
		return domain.ConversationInviteAcceptance{}, domain.ErrInvalid
	}
	candidate := domain.ConversationMember{
		ConversationID: conversation.ID, UserID: userID, Role: "member", JoinedAt: now,
	}
	prospective := s.prospectiveConversationMembersLocked(conversation.ID, candidate)
	planned, projected, err := s.planConversationMembershipProjectionLocked(
		conversation.ID, conversation.Metadata, prospective, userID,
	)
	if err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	members[userID] = candidate
	delete(s.memberTombstones[conversation.ID], userID)
	s.commitConversationMemberLocalIDsLocked(conversation.ID, planned)
	invite.Uses++
	s.inviteLinks[tokenKey] = invite
	conversation.Metadata = projected
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
	conversation := s.conversations[conversationID]
	localID := s.memberLocalIDs[conversationID][userID]
	if localID == uuid.Nil {
		localID = userID
	}
	delete(members, userID)
	if s.memberTombstones[conversationID] == nil {
		s.memberTombstones[conversationID] = make(map[uuid.UUID]store.ConversationMemberTombstone)
	}
	s.memberTombstones[conversationID][userID] = store.ConversationMemberTombstone{
		UserID: userID, LocalID: localID,
	}
	conversation.UpdatedAt = time.Now().UTC()
	s.conversations[conversationID] = conversation
	s.projectConversationMembersLocked(conversationID)
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
	conversation, ok := s.conversations[entity.ConversationID]
	if !ok {
		return domain.Entity{}, domain.ErrNotFound
	}
	activeMembers := s.conversationMembersLocked(entity.ConversationID)
	localIDs, err := s.ensureConversationMemberLocalIDsLocked(entity.ConversationID, conversation.Metadata, activeMembers)
	if err != nil {
		return domain.Entity{}, err
	}
	if err := store.ValidateEntityParticipants(
		entity.Kind, entity.Payload, conversation.Metadata, activeMembers, localIDs...,
	); err != nil {
		return domain.Entity{}, err
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

func (s *Store) RotateChore(_ context.Context, p store.RotateChoreParams) (store.RotateChoreResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.OperationID == uuid.Nil {
		return store.RotateChoreResult{}, domain.ErrInvalid
	}
	// Idempotency never bypasses the current ACL. The process-wide mutex is the
	// memory store's conversation authority, matching the PostgreSQL lock order.
	if _, ok := s.members[p.ConversationID][p.ActorID]; !ok {
		return store.RotateChoreResult{}, domain.ErrForbidden
	}
	if prior, ok := s.choreRotations[p.OperationID]; ok {
		if prior.ConversationID != p.ConversationID || prior.ActorID != p.ActorID ||
			prior.ChoreID != p.ChoreID || !bytes.Equal(prior.RequestHash, p.RequestHash) {
			return store.RotateChoreResult{}, domain.ErrConflict
		}
		return cloneChoreRotationResult(prior.Result), nil
	}
	if p.Validate() != nil {
		return store.RotateChoreResult{}, domain.ErrInvalid
	}
	key := entityKey(p.ConversationID, "chore", p.ChoreID)
	chore, ok := s.entities[key]
	if !ok || chore.DeletedAt != nil {
		return store.RotateChoreResult{}, domain.ErrNotFound
	}
	if chore.Version != p.ExpectedChoreVersion {
		return store.RotateChoreResult{}, domain.ErrConflict
	}
	conversation, ok := s.conversations[p.ConversationID]
	if !ok {
		return store.RotateChoreResult{}, domain.ErrNotFound
	}
	members := s.conversationMembersLocked(p.ConversationID)
	localIDs, err := s.ensureConversationMemberLocalIDsLocked(p.ConversationID, conversation.Metadata, members)
	if err != nil {
		return store.RotateChoreResult{}, err
	}
	if err := store.ValidateEntityParticipants("chore", p.ChorePayload, conversation.Metadata, members, localIDs...); err != nil {
		return store.RotateChoreResult{}, err
	}
	if err := store.ValidateEntityParticipants("feed_item", p.FeedPayload, conversation.Metadata, members, localIDs...); err != nil {
		return store.RotateChoreResult{}, err
	}
	now := time.Now().UTC()
	chore.Payload, chore.Version, chore.UpdatedAt = cloneJSON(p.ChorePayload), chore.Version+1, now
	feed := domain.Entity{ConversationID: p.ConversationID, Kind: "feed_item", ID: p.OperationID, Version: 1,
		Payload: cloneJSON(p.FeedPayload), CreatedBy: p.ActorID, CreatedAt: now, UpdatedAt: now}
	if _, exists := s.entities[entityKey(p.ConversationID, "feed_item", p.OperationID)]; exists {
		return store.RotateChoreResult{}, domain.ErrConflict
	}
	result := store.RotateChoreResult{OperationID: p.OperationID, Chore: chore, FeedItem: feed}
	// All validation precedes this atomic critical-section commit.
	s.entities[key] = chore
	s.entities[entityKey(p.ConversationID, "feed_item", p.OperationID)] = feed
	for _, entity := range []domain.Entity{chore, feed} {
		payload, _ := json.Marshal(entity)
		s.appendOutbox("entity.updated", p.ConversationID, payload)
	}
	s.choreRotations[p.OperationID] = memoryChoreRotation{
		ConversationID: p.ConversationID, ActorID: p.ActorID, ChoreID: p.ChoreID,
		RequestHash: append([]byte(nil), p.RequestHash...), Result: cloneChoreRotationResult(result),
		ExpiresAt: now.Add(90 * 24 * time.Hour),
	}
	return cloneChoreRotationResult(result), nil
}

func (s *Store) PruneChoreRotationOperations(_ context.Context, cutoff time.Time, batchSize int) (int, error) {
	if batchSize < 1 {
		return 0, domain.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := time.Now().UTC(); cutoff.After(now) {
		cutoff = now
	}
	type expiredOperation struct {
		id uuid.UUID
		at time.Time
	}
	expired := make([]expiredOperation, 0)
	for id, operation := range s.choreRotations {
		if !operation.ExpiresAt.After(cutoff) {
			expired = append(expired, expiredOperation{id: id, at: operation.ExpiresAt})
		}
	}
	sort.Slice(expired, func(i, j int) bool {
		if expired[i].at.Equal(expired[j].at) {
			return expired[i].id.String() < expired[j].id.String()
		}
		return expired[i].at.Before(expired[j].at)
	})
	if len(expired) > batchSize {
		expired = expired[:batchSize]
	}
	for _, operation := range expired {
		delete(s.choreRotations, operation.id)
	}
	return len(expired), nil
}

func cloneChoreRotationResult(result store.RotateChoreResult) store.RotateChoreResult {
	result.Chore.Payload = cloneJSON(result.Chore.Payload)
	result.FeedItem.Payload = cloneJSON(result.FeedItem.Payload)
	return result
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

func (s *Store) DeliverRealtimeOutbox(
	ctx context.Context,
	id int64,
	attempt int,
	deliver func(context.Context, domain.OutboxEvent) error,
) error {
	if id < 1 || attempt < 1 || deliver == nil {
		return domain.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.deliveryBarrier.RLock()
	defer s.deliveryBarrier.RUnlock()

	s.mu.Lock()
	var leased domain.OutboxEvent
	found := false
	for _, event := range s.outbox {
		if event.ID == id && event.PublishedAt == nil && event.Topic != "media.delete" &&
			event.Attempts == attempt && event.LockedUntil != nil {
			if _, active := s.activeRealtimeDeliveries[id]; active {
				break
			}
			leased = event
			leased.Payload = append(json.RawMessage(nil), event.Payload...)
			s.activeRealtimeDeliveries[id] = attempt
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		return domain.ErrNotFound
	}
	defer func() {
		s.mu.Lock()
		if s.activeRealtimeDeliveries[id] == attempt {
			delete(s.activeRealtimeDeliveries, id)
		}
		s.mu.Unlock()
	}()
	if err := deliver(ctx, leased); err != nil {
		return err
	}
	return ctx.Err()
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
		if _, active := s.activeRealtimeDeliveries[event.ID]; active {
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
			if _, active := s.activePushDeliveries[id]; active {
				continue
			}
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

func (s *Store) WithPushDeliveryLease(
	ctx context.Context,
	id int64,
	leaseToken uuid.UUID,
	deliver func(context.Context, domain.PushDelivery) error,
) error {
	if id < 1 || leaseToken == uuid.Nil || deliver == nil {
		return domain.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.deliveryBarrier.RLock()
	defer s.deliveryBarrier.RUnlock()
	s.deviceDeliveryBarrier.RLock()
	defer s.deviceDeliveryBarrier.RUnlock()

	s.mu.Lock()
	leased, found := s.pushDeliveries[id]
	if found && (leased.Status != domain.PushDeliveryPending || leased.LeaseToken != leaseToken) {
		found = false
	}
	if _, active := s.activePushDeliveries[id]; active {
		found = false
	}
	if found {
		device, deviceFound := s.devices[leased.DeviceID]
		if !deviceFound {
			found = false
		} else {
			leased.UserID = device.UserID
			leased.PushToken = device.PushToken
			s.activePushDeliveries[id] = leaseToken
		}
	}
	s.mu.Unlock()
	if !found {
		return domain.ErrNotFound
	}
	defer func() {
		s.mu.Lock()
		if s.activePushDeliveries[id] == leaseToken {
			delete(s.activePushDeliveries, id)
		}
		s.mu.Unlock()
	}()
	return deliver(ctx, leased)
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
	s.deviceDeliveryBarrier.Lock()
	defer s.deviceDeliveryBarrier.Unlock()
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
