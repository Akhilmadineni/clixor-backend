package store

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

const DeletedUserDisplayName = "Deleted user"
const MediaDeleteBatchSize = 500

// AccountIdentity contains the identifiers which must no longer be exposed after
// an account is deleted. UserID remains as an opaque tombstone identifier so
// shared financial history can preserve referential integrity.
type AccountIdentity struct {
	UserID      uuid.UUID
	Email       string
	Phone       string
	DisplayName string
	Username    string
}

type MediaDeletePayload struct {
	ObjectKeys []string `json:"object_keys"`
}

// AnonymizeAccountJSON removes identity fields from JSON owned by the deleted
// account. Stable user/member IDs are deliberately retained because expense and
// settlement payloads use them to preserve shared financial history.
func AnonymizeAccountJSON(raw json.RawMessage, identity AccountIdentity) (json.RawMessage, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return raw, false, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false, err
	}
	changed := anonymizeJSONValue(value, identity)
	if !changed {
		return raw, false, nil
	}
	encoded, err := json.Marshal(value)
	return encoded, true, err
}

func anonymizeJSONValue(value any, identity AccountIdentity) bool {
	switch typed := value.(type) {
	case []any:
		changed := false
		for _, item := range typed {
			changed = anonymizeJSONValue(item, identity) || changed
		}
		return changed
	case map[string]any:
		changed := false
		owned := objectBelongsToAccount(typed, identity.UserID) || objectContainsIdentity(typed, identity)
		for key, item := range typed {
			changed = anonymizeJSONValue(item, identity) || changed
			normalized := normalizeJSONKey(key)
			text, isText := item.(string)
			if owned && isPersonalJSONKey(normalized) {
				delete(typed, key)
				changed = true
				continue
			}
			if owned && isText && isNameJSONKey(normalized) &&
				identity.DisplayName != "" && text == identity.DisplayName {
				typed[key] = DeletedUserDisplayName
				changed = true
				continue
			}
			if isText && isIdentifierJSONKey(normalized) && matchesIdentity(text, identity) {
				delete(typed, key)
				changed = true
			}
		}
		if owned {
			for key, item := range typed {
				if text, ok := item.(string); ok && isNameJSONKey(normalizeJSONKey(key)) &&
					text != DeletedUserDisplayName {
					typed[key] = DeletedUserDisplayName
					changed = true
				}
			}
			if deleted, ok := typed["isDeleted"].(bool); !ok || !deleted {
				typed["isDeleted"] = true
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func objectContainsIdentity(object map[string]any, identity AccountIdentity) bool {
	for key, item := range object {
		text, ok := item.(string)
		if ok && isIdentifierJSONKey(normalizeJSONKey(key)) && matchesIdentity(text, identity) {
			return true
		}
	}
	return false
}

func objectBelongsToAccount(object map[string]any, userID uuid.UUID) bool {
	wanted := userID.String()
	for key, item := range object {
		switch normalizeJSONKey(key) {
		case "backenduserid", "userid", "useruuid", "owneruserid", "createdbyuserid":
			if text, ok := item.(string); ok && strings.EqualFold(text, wanted) {
				return true
			}
		}
	}
	return false
}

func matchesIdentity(value string, identity AccountIdentity) bool {
	for _, identifier := range []string{identity.Email, identity.Phone, identity.Username} {
		if identifier != "" && strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(identifier)) {
			return true
		}
	}
	return false
}

func normalizeJSONKey(key string) string {
	replacer := strings.NewReplacer("_", "", "-", "", ".", "")
	return strings.ToLower(replacer.Replace(key))
}

func isNameJSONKey(key string) bool {
	switch key {
	case "name", "displayname", "membername", "payername", "creatorname", "creatordisplayname":
		return true
	default:
		return false
	}
}

func isIdentifierJSONKey(key string) bool {
	switch key {
	case "email", "contactemail", "phone", "phonenumber", "contactphone", "username", "handle":
		return true
	default:
		return false
	}
}

func isPersonalJSONKey(key string) bool {
	if isIdentifierJSONKey(key) {
		return true
	}
	switch key {
	case "avatar", "avatarurl", "bio", "photo", "photourl", "profileimage", "profileimagedata", "profileimageurl":
		return true
	default:
		return false
	}
}
