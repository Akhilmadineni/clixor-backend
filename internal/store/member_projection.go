package store

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

const defaultMemberAvatarColor = "#4A6CF7"

// JSONValuesEqual compares decoded values rather than wire formatting. This is
// important for PostgreSQL jsonb, whose canonical whitespace/key ordering can
// differ from encoding/json even when the stored projection is already healed.
func JSONValuesEqual(first, second json.RawMessage) bool {
	var firstValue, secondValue any
	if json.Unmarshal(first, &firstValue) != nil || json.Unmarshal(second, &secondValue) != nil {
		return bytes.Equal(bytes.TrimSpace(first), bytes.TrimSpace(second))
	}
	return reflect.DeepEqual(firstValue, secondValue)
}

// ConversationMemberWithPublicIdentity attaches only fields suitable for
// disclosure to another conversation member. In particular, account email,
// phone, contact_email, and contact_phone are deliberately excluded.
func ConversationMemberWithPublicIdentity(member domain.ConversationMember, user domain.User) domain.ConversationMember {
	profile := publicProfileFields(user.Profile)
	member.DisplayName = strings.TrimSpace(user.DisplayName)
	if member.DisplayName == "" {
		member.DisplayName = strings.TrimSpace(profile.DisplayName)
	}
	member.Username = strings.TrimSpace(profile.Username)
	member.Bio = strings.TrimSpace(profile.Bio)
	member.AvatarURL = strings.TrimSpace(user.AvatarURL)
	if member.AvatarURL == "" {
		member.AvatarURL = strings.TrimSpace(profile.ProfileImageURL)
	}
	member.AvatarColor = strings.TrimSpace(profile.AvatarColor)
	return member
}

// PublicUserFromUser produces a discovery-safe user object. Exact phone lookup
// may echo the already-submitted matched number for production-client
// compatibility; username lookup and prefix search must pass includePhone=false.
func PublicUserFromUser(user domain.User, includePhone bool) domain.PublicUser {
	profile := publicProfileFields(user.Profile)
	publicProfile, _ := json.Marshal(map[string]any{
		"display_name":      omitEmpty(profile.DisplayName),
		"avatar_color":      omitEmpty(profile.AvatarColor),
		"username":          omitEmpty(profile.Username),
		"bio":               omitEmpty(profile.Bio),
		"profile_image_url": omitEmpty(profile.ProfileImageURL),
	})
	publicProfile = compactJSONObject(publicProfile)
	result := domain.PublicUser{
		ID: user.ID, DisplayName: strings.TrimSpace(user.DisplayName),
		AvatarURL: strings.TrimSpace(user.AvatarURL), Profile: publicProfile,
		CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	}
	if result.DisplayName == "" {
		result.DisplayName = strings.TrimSpace(profile.DisplayName)
	}
	if result.AvatarURL == "" {
		result.AvatarURL = strings.TrimSpace(profile.ProfileImageURL)
	}
	if includePhone {
		result.MatchedPhone = user.Phone
	}
	return result
}

// ProjectConversationMembers makes the relational ACL the source of truth for
// registered group members while preserving legacy local Member UUIDs. Only
// tombstones supplied by the store's trusted history table are retained.
//
// Objects with a valid backendUserId that is absent from the ACL are removed.
// Consequently replaying stale metadata can neither grant access nor restore a
// removed registered member to the legacy projection.
func ProjectConversationMembers(
	metadata json.RawMessage,
	members []domain.ConversationMember,
	tombstones ...ConversationMemberTombstone,
) (json.RawMessage, error) {
	root := make(map[string]json.RawMessage)
	trimmed := bytes.TrimSpace(metadata)
	if len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null")) {
		if err := json.Unmarshal(trimmed, &root); err != nil {
			// Legacy deployments accepted arbitrary JSON here. Heal a non-object
			// value into an object rather than making a later ACL mutation fail
			// after it has acquired its authorization locks.
			root = make(map[string]json.RawMessage)
		}
	}

	ordered := append([]domain.ConversationMember(nil), members...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].JoinedAt.Equal(ordered[j].JoinedAt) {
			return ordered[i].UserID.String() < ordered[j].UserID.String()
		}
		return ordered[i].JoinedAt.Before(ordered[j].JoinedAt)
	})
	authoritative := make(map[uuid.UUID]domain.ConversationMember, len(ordered))
	for _, member := range ordered {
		authoritative[member.UserID] = member
	}

	var existing []json.RawMessage
	if raw, ok := root["members"]; ok {
		_ = json.Unmarshal(raw, &existing)
	}
	projected := make([]json.RawMessage, 0, len(ordered)+len(tombstones))
	seen := make(map[uuid.UUID]struct{}, len(ordered))
	for _, raw := range existing {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			continue
		}
		backendID, backendIDPresent, backendIDValid := memberBackendUserID(object)
		if !backendIDPresent {
			// Pending address-book contacts and arbitrary local objects are private
			// client state and never belong in shared group metadata.
			continue
		}
		// A present backend identity must be one unambiguous UUID. Treating a
		// malformed or aliased value as contact-only would let stale metadata
		// bypass the authoritative registered-member projection.
		if !backendIDValid {
			continue
		}
		member, authorized := authoritative[backendID]
		if !authorized {
			continue
		}
		if _, duplicate := seen[backendID]; duplicate {
			continue
		}
		projected = append(projected, marshalProjectedMember(object, member))
		seen[backendID] = struct{}{}
	}
	for _, member := range ordered {
		if _, ok := seen[member.UserID]; ok {
			continue
		}
		projected = append(projected, marshalProjectedMember(nil, member))
		seen[member.UserID] = struct{}{}
	}
	for _, tombstone := range tombstones {
		if tombstone.UserID == uuid.Nil {
			continue
		}
		if _, active := authoritative[tombstone.UserID]; active {
			continue
		}
		projected = append(projected, marshalTrustedDeletedMember(tombstone))
	}
	membersJSON, err := json.Marshal(projected)
	if err != nil {
		return nil, err
	}
	root["members"] = membersJSON
	return json.Marshal(root)
}

// ConversationMemberTombstone is store-owned history. HTTP metadata cannot
// create one; it is persisted before the relational ACL row is removed.
type ConversationMemberTombstone struct {
	UserID  uuid.UUID
	LocalID uuid.UUID
}

// NewConversationMemberTombstone preserves a valid, unambiguous legacy local
// UUID for an authoritative member. Malformed or duplicate identities fall
// back to the backend user UUID and can never smuggle raw metadata into history.
func NewConversationMemberTombstone(metadata json.RawMessage, userID uuid.UUID) ConversationMemberTombstone {
	result := ConversationMemberTombstone{UserID: userID, LocalID: userID}
	var root map[string]json.RawMessage
	if json.Unmarshal(metadata, &root) != nil {
		return result
	}
	var members []json.RawMessage
	if json.Unmarshal(root["members"], &members) != nil {
		return result
	}
	matched := false
	for _, raw := range members {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			continue
		}
		backendID, present, valid := memberBackendUserID(object)
		if !present || !valid || backendID != userID {
			continue
		}
		if matched {
			return ConversationMemberTombstone{UserID: userID, LocalID: userID}
		}
		matched = true
		if local, present, valid := uniqueStringField(object, "id"); present && valid {
			if parsed, err := uuid.Parse(local); err == nil && parsed != uuid.Nil {
				result.LocalID = parsed
			}
		}
	}
	return result
}

type publicProfile struct {
	DisplayName     string `json:"display_name"`
	AvatarColor     string `json:"avatar_color"`
	Username        string `json:"username"`
	Bio             string `json:"bio"`
	ProfileImageURL string `json:"profile_image_url"`
}

func publicProfileFields(raw json.RawMessage) publicProfile {
	var result publicProfile
	_ = json.Unmarshal(raw, &result)
	return result
}

func omitEmpty(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func compactJSONObject(raw json.RawMessage) json.RawMessage {
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return json.RawMessage(`{}`)
	}
	for key, value := range object {
		if value == nil {
			delete(object, key)
		}
	}
	result, _ := json.Marshal(object)
	return result
}

func memberBackendUserID(object map[string]json.RawMessage) (uuid.UUID, bool, bool) {
	found := false
	var result uuid.UUID
	for key, raw := range object {
		if normalizeJSONKey(key) != "backenduserid" {
			continue
		}
		if found {
			return uuid.Nil, true, false
		}
		found = true
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return uuid.Nil, true, false
		}
		id, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || id == uuid.Nil {
			return uuid.Nil, true, false
		}
		result = id
	}
	return result, found, found
}

func memberIsDeletedTombstone(object map[string]json.RawMessage) bool {
	found := false
	deleted := false
	for key, raw := range object {
		if normalizeJSONKey(key) != "isdeleted" {
			continue
		}
		if found || json.Unmarshal(raw, &deleted) != nil {
			return false
		}
		found = true
	}
	return found && deleted
}

func marshalProjectedMember(
	existing map[string]json.RawMessage,
	member domain.ConversationMember,
) json.RawMessage {
	object := make(map[string]json.RawMessage, 8)
	setJSON(object, "backendUserId", member.UserID.String())
	setJSON(object, "id", stableLocalMemberID(existing, member.UserID))
	name := boundedString(member.DisplayName, 100)
	if name == "" {
		name = boundedString(strings.TrimPrefix(strings.TrimSpace(member.Username), "@"), 100)
	}
	if name == "" {
		name = "Member"
	}
	setJSON(object, "name", name)
	color := normalizedAvatarColor(member.AvatarColor)
	setJSON(object, "avatarColor", color)
	setJSON(object, "rosterState", "active")
	if username := boundedString(member.Username, 31); username != "" {
		setJSON(object, "username", username)
	}
	if avatarURL := boundedString(member.AvatarURL, 2048); avatarURL != "" {
		setJSON(object, "profileImageURL", avatarURL)
	}
	result, _ := json.Marshal(object)
	return result
}

func marshalTrustedDeletedMember(tombstone ConversationMemberTombstone) json.RawMessage {
	object := make(map[string]json.RawMessage, 6)
	localID := tombstone.LocalID
	if localID == uuid.Nil {
		localID = tombstone.UserID
	}
	setJSON(object, "id", localID.String())
	setJSON(object, "backendUserId", tombstone.UserID.String())
	setJSON(object, "name", DeletedUserDisplayName)
	setJSON(object, "avatarColor", defaultMemberAvatarColor)
	setJSON(object, "isDeleted", true)
	setJSON(object, "rosterState", "inactiveTombstone")
	encoded, _ := json.Marshal(object)
	return encoded
}

func stableLocalMemberID(existing map[string]json.RawMessage, fallback uuid.UUID) string {
	value, present, valid := uniqueStringField(existing, "id")
	if present && valid {
		if value, safe := safeLocalMemberID(value); safe {
			return value
		}
	}
	return fallback.String()
}

func safeLocalMemberID(value string) (string, bool) {
	value = strings.TrimSpace(value)
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil {
		return "", false
	}
	return parsed.String(), true
}

func uniqueStringField(object map[string]json.RawMessage, wanted string) (string, bool, bool) {
	found := false
	value := ""
	for key, raw := range object {
		if normalizeJSONKey(key) != normalizeJSONKey(wanted) {
			continue
		}
		if found || json.Unmarshal(raw, &value) != nil {
			return "", true, false
		}
		found = true
	}
	return strings.TrimSpace(value), found, found
}

func boundedString(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return ""
	}
	return value
}

func normalizedAvatarColor(value string) string {
	value = strings.TrimSpace(value)
	if len(value) != 7 || value[0] != '#' {
		return defaultMemberAvatarColor
	}
	for _, character := range value[1:] {
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return defaultMemberAvatarColor
		}
	}
	return value
}

func setJSON(object map[string]json.RawMessage, key string, value any) {
	encoded, _ := json.Marshal(value)
	object[key] = encoded
}
