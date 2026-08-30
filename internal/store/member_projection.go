package store

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

const defaultMemberAvatarColor = "#4A6CF7"

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
// registered group members while preserving legacy local Member UUIDs and
// unknown/contact-only member objects. A deleted-account tombstone is also
// retained because shared financial history can still reference its local ID.
//
// Objects with a valid backendUserId that is absent from the ACL are removed.
// Consequently replaying stale metadata can neither grant access nor restore a
// removed registered member to the legacy projection.
func ProjectConversationMembers(
	metadata json.RawMessage,
	members []domain.ConversationMember,
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
	projected := make([]json.RawMessage, 0, len(existing)+len(ordered))
	seen := make(map[uuid.UUID]struct{}, len(ordered))
	for _, raw := range existing {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			continue
		}
		backendID, hasBackendID := memberBackendUserID(object)
		if !hasBackendID {
			// Contact-only and historical local members cannot authenticate and
			// therefore cannot affect the relational authorization boundary.
			projected = append(projected, cloneRaw(raw))
			continue
		}
		member, authorized := authoritative[backendID]
		if !authorized {
			if memberIsDeletedTombstone(object) {
				projected = append(projected, cloneRaw(raw))
			}
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
	membersJSON, err := json.Marshal(projected)
	if err != nil {
		return nil, err
	}
	root["members"] = membersJSON
	return json.Marshal(root)
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

func memberBackendUserID(object map[string]json.RawMessage) (uuid.UUID, bool) {
	for key, raw := range object {
		if normalizeJSONKey(key) != "backenduserid" {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			continue
		}
		id, err := uuid.Parse(strings.TrimSpace(value))
		if err == nil {
			return id, true
		}
	}
	return uuid.Nil, false
}

func memberIsDeletedTombstone(object map[string]json.RawMessage) bool {
	for key, raw := range object {
		if normalizeJSONKey(key) != "isdeleted" {
			continue
		}
		var deleted bool
		return json.Unmarshal(raw, &deleted) == nil && deleted
	}
	return false
}

func marshalProjectedMember(
	existing map[string]json.RawMessage,
	member domain.ConversationMember,
) json.RawMessage {
	object := make(map[string]json.RawMessage, len(existing)+7)
	for key, value := range existing {
		if normalizeJSONKey(key) == "backenduserid" {
			continue
		}
		object[key] = cloneRaw(value)
	}
	setJSON(object, "backendUserId", member.UserID.String())
	if !hasNonEmptyString(object, "id") {
		setJSON(object, "id", member.UserID.String())
	}
	if !hasNonEmptyString(object, "name") {
		name := strings.TrimSpace(member.DisplayName)
		if name == "" {
			name = strings.TrimPrefix(strings.TrimSpace(member.Username), "@")
		}
		if name == "" {
			name = "Member"
		}
		setJSON(object, "name", name)
	}
	if !hasNonEmptyString(object, "avatarColor") {
		color := strings.TrimSpace(member.AvatarColor)
		if color == "" {
			color = defaultMemberAvatarColor
		}
		setJSON(object, "avatarColor", color)
	}
	if !hasNonEmptyString(object, "username") && strings.TrimSpace(member.Username) != "" {
		setJSON(object, "username", strings.TrimSpace(member.Username))
	}
	if !hasNonEmptyString(object, "profileImageURL") && strings.TrimSpace(member.AvatarURL) != "" {
		setJSON(object, "profileImageURL", strings.TrimSpace(member.AvatarURL))
	}
	result, _ := json.Marshal(object)
	return result
}

func hasNonEmptyString(object map[string]json.RawMessage, wanted string) bool {
	for key, raw := range object {
		if normalizeJSONKey(key) != normalizeJSONKey(wanted) {
			continue
		}
		var value string
		return json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != ""
	}
	return false
}

func setJSON(object map[string]json.RawMessage, key string, value any) {
	encoded, _ := json.Marshal(value)
	object[key] = encoded
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), raw...)
}
