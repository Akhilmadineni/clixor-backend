package store

import (
	"encoding/json"
	"strings"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/google/uuid"
)

var participantEntityKinds = map[string]struct{}{
	"expense": {}, "recurring_expense": {}, "task": {}, "chore": {}, "settlement": {},
}

var participantFields = map[string]struct{}{
	"paidby": {}, "defaultpaidby": {}, "splitbetween": {}, "customamounts": {},
	"assignedto": {}, "createdby": {}, "rotateorder": {}, "from": {}, "to": {},
	"payer": {}, "payerid": {}, "assignee": {}, "assigneeid": {},
	"participants": {}, "participantids": {}, "backenduserid": {},
}

// ValidateEntityParticipants rejects newly written references to users who are
// not in the current relational ACL. Both backend UUIDs and authoritative active
// legacy local UUIDs are accepted for production-client compatibility.
func ValidateEntityParticipants(kind string, payload json.RawMessage, metadata json.RawMessage, members []domain.ConversationMember) error {
	if _, relevant := participantEntityKinds[kind]; !relevant {
		return nil
	}
	allowed := make(map[uuid.UUID]struct{}, len(members)*2)
	for _, member := range members {
		allowed[member.UserID] = struct{}{}
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(metadata, &root) == nil {
		var projected []map[string]json.RawMessage
		if json.Unmarshal(root["members"], &projected) == nil {
			for _, object := range projected {
				backendID, present, valid := memberBackendUserID(object)
				if !present || !valid {
					continue
				}
				if _, active := allowed[backendID]; !active {
					continue
				}
				if local, present, valid := uniqueStringField(object, "id"); present && valid {
					if id, err := uuid.Parse(local); err == nil && id != uuid.Nil {
						allowed[id] = struct{}{}
					}
				}
			}
		}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil {
		return domain.ErrInvalid
	}
	for key, raw := range object {
		if _, participant := participantFields[normalizeJSONKey(key)]; !participant {
			continue
		}
		ids, err := participantIDs(raw)
		if err != nil {
			return domain.ErrInvalid
		}
		for _, id := range ids {
			if _, active := allowed[id]; !active {
				return domain.ErrInvalid
			}
		}
	}
	return nil
}

func participantIDs(raw json.RawMessage) ([]uuid.UUID, error) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil, domain.ErrInvalid
	}
	var result []uuid.UUID
	var walk func(any, bool) error
	walk = func(current any, mapKeysAreIDs bool) error {
		switch typed := current.(type) {
		case nil:
			return nil
		case string:
			id, err := uuid.Parse(strings.TrimSpace(typed))
			if err != nil || id == uuid.Nil {
				return domain.ErrInvalid
			}
			result = append(result, id)
		case []any:
			for _, item := range typed {
				if err := walk(item, false); err != nil {
					return err
				}
			}
		case map[string]any:
			for key, item := range typed {
				if mapKeysAreIDs {
					id, err := uuid.Parse(strings.TrimSpace(key))
					if err != nil || id == uuid.Nil {
						return domain.ErrInvalid
					}
					result = append(result, id)
					continue
				}
				normalized := normalizeJSONKey(key)
				if normalized == "id" || normalized == "backenduserid" || normalized == "userid" || normalized == "memberid" {
					if err := walk(item, false); err != nil {
						return err
					}
				}
			}
		default:
			if !mapKeysAreIDs {
				return domain.ErrInvalid
			}
		}
		return nil
	}
	var top map[string]any
	if json.Unmarshal(raw, &top) == nil {
		// UUID-keyed amount maps are the only participant objects without an ID field.
		allUUIDKeys := len(top) > 0
		for key := range top {
			if _, err := uuid.Parse(key); err != nil {
				allUUIDKeys = false
				break
			}
		}
		if allUUIDKeys {
			return result, walk(top, true)
		}
	}
	return result, walk(value, false)
}
