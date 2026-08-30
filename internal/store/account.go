package store

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const DeletedUserDisplayName = "Deleted user"
const MediaDeleteBatchSize = 500
const MediaDeleteGrace = 3 * time.Minute

// AccountSanitizableOutboxTopic is the closed set of conversation-scoped
// realtime schemas whose JSON shape is owned by this service and can therefore
// be structurally anonymized during account erasure. Unknown/future transport
// topics are never searched with raw identity substrings.
func AccountSanitizableOutboxTopic(topic string) bool {
	switch topic {
	case "conversation.created", "entity.updated", "entity.deleted":
		return true
	default:
		return false
	}
}

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
	ObjectKeys []string   `json:"object_keys"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
}

func NewMediaDeletePayload(objectKeys []string, queuedAt time.Time) MediaDeletePayload {
	return NewMediaDeletePayloadAt(objectKeys, queuedAt.UTC().Add(MediaDeleteGrace))
}

func NewMediaDeletePayloadAt(objectKeys []string, notBefore time.Time) MediaDeletePayload {
	notBefore = notBefore.UTC()
	return MediaDeletePayload{ObjectKeys: objectKeys, NotBefore: &notBefore}
}

// AnonymizeAccountJSON removes identity fields from JSON owned by the deleted
// account. Stable user/member IDs are deliberately retained because expense and
// settlement payloads use them to preserve shared financial history.
func AnonymizeAccountJSON(raw json.RawMessage, identity AccountIdentity) (json.RawMessage, bool, error) {
	return anonymizeAccountJSON(raw, identity, false)
}

// AnonymizeAccountJSONWithAuthority uses the same structural sanitizer after
// the caller has independently proven that the root aggregate/entity belongs
// to or references the account. Authority only enables explicit identity-name
// fields at that root; it never turns arbitrary descendant strings into PII.
func AnonymizeAccountJSONWithAuthority(raw json.RawMessage, identity AccountIdentity) (json.RawMessage, bool, error) {
	return anonymizeAccountJSON(raw, identity, true)
}

func anonymizeAccountJSON(raw json.RawMessage, identity AccountIdentity, authorized bool) (json.RawMessage, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return raw, false, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false, err
	}
	changed := anonymizeJSONValue(value, identity, authorized)
	if !changed {
		return raw, false, nil
	}
	encoded, err := json.Marshal(value)
	return encoded, true, err
}

// AccountJSONReferencesIdentity reports whether JSON has non-ambiguous
// authority tying it to the account: the stable user UUID, or an email, phone,
// or username. Display names are intentionally excluded because short/common
// names cannot identify an account safely.
func AccountJSONReferencesIdentity(raw json.RawMessage, identity AccountIdentity) (bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, err
	}
	return jsonValueReferencesIdentity(value, identity), nil
}

func jsonValueReferencesIdentity(value any, identity AccountIdentity) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if jsonValueReferencesIdentity(item, identity) {
				return true
			}
		}
	case map[string]any:
		if objectBelongsToAccount(typed, identity.UserID) || objectContainsIdentity(typed, identity) {
			return true
		}
		for _, item := range typed {
			if jsonValueReferencesIdentity(item, identity) {
				return true
			}
		}
	case string:
		if identity.UserID != uuid.Nil && containsBoundedIdentity(typed, identity.UserID.String()) {
			return true
		}
		for _, identifier := range []string{identity.Email, identity.Phone, identity.Username} {
			if containsBoundedIdentity(typed, identifier) {
				return true
			}
		}
	}
	return false
}

func anonymizeJSONValue(value any, identity AccountIdentity, authorized bool) bool {
	switch typed := value.(type) {
	case []any:
		changed := false
		for index, item := range typed {
			if text, ok := item.(string); ok {
				if redacted, textChanged := redactAccountIdentityText(text, identity, false); textChanged {
					typed[index] = redacted
					changed = true
				}
				continue
			}
			changed = anonymizeJSONValue(item, identity, false) || changed
		}
		return changed
	case map[string]any:
		changed := false
		owned := objectBelongsToAccount(typed, identity.UserID) || objectContainsIdentity(typed, identity)
		for key, item := range typed {
			normalized := normalizeJSONKey(key)
			childAuthorized := (owned || authorized) && isIdentityContainerJSONKey(normalized)
			changed = anonymizeJSONValue(item, identity, childAuthorized) || changed
			text, isText := item.(string)
			if owned && isPersonalJSONKey(normalized) {
				delete(typed, key)
				changed = true
				continue
			}
			if (owned || authorized) && isText && isAccountIdentityNameKey(normalized, owned) &&
				identity.DisplayName != "" && strings.EqualFold(strings.TrimSpace(text), strings.TrimSpace(identity.DisplayName)) {
				typed[key] = DeletedUserDisplayName
				changed = true
				continue
			}
			if isText && isIdentifierJSONKey(normalized) && matchesIdentity(text, identity) {
				delete(typed, key)
				changed = true
				continue
			}
			if isText {
				redacted, strongChanged := redactAccountIdentityText(text, identity, false)
				if (owned || authorized) && isIdentityProseJSONKey(normalized) {
					var nameChanged bool
					redacted, nameChanged = redactAccountIdentityText(redacted, identity, true)
					strongChanged = strongChanged || nameChanged
				}
				if strongChanged {
					typed[key] = redacted
					changed = true
				}
			}
		}
		if owned {
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

func isIdentityContainerJSONKey(key string) bool {
	switch key {
	case "payload", "metadata", "result", "choreresult", "feedresult":
		return true
	default:
		return false
	}
}

func isIdentityProseJSONKey(key string) bool {
	switch key {
	case "description":
		return true
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
		case "backenduserid", "userid", "useruuid", "owneruserid", "createdbyuserid", "createdby", "creatorid", "actorid":
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
	case "name", "displayname",
		"membername", "memberdisplayname",
		"payername", "payerdisplayname",
		"creatorname", "creatordisplayname",
		"createdbyname", "createdbydisplayname",
		"actorname", "actordisplayname",
		"ownername", "ownerdisplayname":
		return true
	default:
		return false
	}
}

func isAccountIdentityNameKey(key string, owned bool) bool {
	if key == "name" {
		return owned
	}
	return isNameJSONKey(key)
}

// redactAccountIdentityText removes bounded occurrences from human-readable
// fields (for example feed descriptions and chore titles). Identifiers embedded
// in prose are PII just as much as dedicated email/phone/name fields. A display
// name is included only after surrounding structure has proven account
// ownership; otherwise common names would corrupt unrelated data.
func redactAccountIdentityText(value string, identity AccountIdentity, includeDisplayName bool) (string, bool) {
	needles := []string{identity.Email, identity.Phone, identity.Username}
	if includeDisplayName {
		needles = append(needles, identity.DisplayName)
	}
	sort.SliceStable(needles, func(i, j int) bool { return len(needles[i]) > len(needles[j]) })
	changed := false
	for _, needle := range needles {
		needle = strings.TrimSpace(needle)
		if needle == "" || strings.EqualFold(needle, DeletedUserDisplayName) {
			continue
		}
		pattern, err := regexp.Compile(`(?i)` + regexp.QuoteMeta(needle))
		if err != nil {
			continue
		}
		matches := pattern.FindAllStringIndex(value, -1)
		if len(matches) == 0 {
			continue
		}
		var redacted strings.Builder
		redacted.Grow(len(value))
		cursor := 0
		needleChanged := false
		for _, match := range matches {
			if !identityTextBoundaryBefore(value, match[0]) ||
				!identityTextBoundaryAfter(value, match[1]) {
				continue
			}
			redacted.WriteString(value[cursor:match[0]])
			redacted.WriteString(DeletedUserDisplayName)
			cursor = match[1]
			needleChanged = true
		}
		if needleChanged {
			redacted.WriteString(value[cursor:])
			value = redacted.String()
			changed = true
		}
	}
	return value, changed
}

func containsBoundedIdentity(value, identity string) bool {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return false
	}
	pattern, err := regexp.Compile(`(?i)` + regexp.QuoteMeta(identity))
	if err != nil {
		return false
	}
	for _, match := range pattern.FindAllStringIndex(value, -1) {
		if identityTextBoundaryBefore(value, match[0]) && identityTextBoundaryAfter(value, match[1]) {
			return true
		}
	}
	return false
}

func identityTextBoundaryBefore(value string, index int) bool {
	if index == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(value[:index])
	return r != '_' && !unicode.IsLetter(r) && !unicode.IsNumber(r)
}

func identityTextBoundaryAfter(value string, index int) bool {
	if index == len(value) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(value[index:])
	return r != '_' && !unicode.IsLetter(r) && !unicode.IsNumber(r)
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
