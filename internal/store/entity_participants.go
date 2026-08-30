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

var scalarParticipantFields = map[string]struct{}{
	"paidby": {}, "defaultpaidby": {}, "assignedto": {}, "createdby": {},
	"from": {}, "to": {}, "payerid": {}, "assigneeid": {}, "backenduserid": {},
}

var arrayParticipantFields = map[string]struct{}{
	"splitbetween": {}, "rotateorder": {}, "participantids": {},
}

// ValidateEntityParticipants rejects newly written references to users who are
// not in the current relational ACL. Both backend UUIDs and authoritative active
// legacy local UUIDs are accepted for production-client compatibility.
func ValidateEntityParticipants(
	kind string,
	payload json.RawMessage,
	metadata json.RawMessage,
	members []domain.ConversationMember,
	localIDs ...ConversationMemberLocalID,
) error {
	if _, relevant := participantEntityKinds[kind]; !relevant {
		return nil
	}
	allowed := make(map[uuid.UUID]struct{}, len(members)*2)
	for _, member := range members {
		allowed[member.UserID] = struct{}{}
	}
	if len(localIDs) > 0 {
		for _, mapping := range localIDs {
			if _, active := allowed[mapping.UserID]; active && mapping.LocalID != uuid.Nil {
				allowed[mapping.LocalID] = struct{}{}
			}
		}
	} else {
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
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil {
		return domain.ErrInvalid
	}
	seenFields := make(map[string]struct{})
	for key, raw := range object {
		normalized := normalizeJSONKey(key)
		if _, participant := participantFields[normalized]; !participant {
			continue
		}
		if _, duplicate := seenFields[normalized]; duplicate {
			return domain.ErrInvalid
		}
		seenFields[normalized] = struct{}{}
		ids, err := participantIDsForField(normalized, raw)
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

func participantIDsForField(field string, raw json.RawMessage) ([]uuid.UUID, error) {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil, domain.ErrInvalid
	}
	if field == "customamounts" {
		amounts, ok := value.(map[string]any)
		if !ok || len(amounts) == 0 {
			return nil, domain.ErrInvalid
		}
		result := make([]uuid.UUID, 0, len(amounts))
		for key, amount := range amounts {
			id, err := strictParticipantUUID(key)
			number, numeric := amount.(float64)
			if err != nil || !numeric || number < 0 {
				return nil, domain.ErrInvalid
			}
			result = append(result, id)
		}
		return result, nil
	}
	if _, scalar := scalarParticipantFields[field]; scalar {
		if value == nil {
			return nil, nil
		}
		id, err := participantScalar(value)
		if err != nil {
			return nil, err
		}
		return []uuid.UUID{id}, nil
	}
	if _, array := arrayParticipantFields[field]; array {
		items, ok := value.([]any)
		if !ok {
			return nil, domain.ErrInvalid
		}
		result := make([]uuid.UUID, 0, len(items))
		for _, item := range items {
			id, err := participantScalar(item)
			if err != nil {
				return nil, err
			}
			result = append(result, id)
		}
		return result, nil
	}
	if field == "payer" || field == "assignee" {
		if value == nil {
			return nil, nil
		}
		id, err := participantIdentityObject(value)
		if err != nil {
			return nil, err
		}
		return []uuid.UUID{id}, nil
	}
	if field == "participants" {
		items, ok := value.([]any)
		if !ok {
			return nil, domain.ErrInvalid
		}
		result := make([]uuid.UUID, 0, len(items))
		objectShape := false
		if len(items) > 0 {
			_, objectShape = items[0].(map[string]any)
			if _, scalarShape := items[0].(string); !objectShape && !scalarShape {
				return nil, domain.ErrInvalid
			}
		}
		for _, item := range items {
			var id uuid.UUID
			var err error
			if objectShape {
				id, err = participantIdentityObject(item)
			} else {
				id, err = participantScalar(item)
			}
			if err != nil {
				return nil, err
			}
			result = append(result, id)
		}
		return result, nil
	}
	return nil, domain.ErrInvalid
}

func participantScalar(value any) (uuid.UUID, error) {
	text, ok := value.(string)
	if !ok {
		return uuid.Nil, domain.ErrInvalid
	}
	return strictParticipantUUID(text)
}

func strictParticipantUUID(value string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(value)
	id, err := uuid.Parse(trimmed)
	// Foundation's UUID Codable representation is canonical but commonly uses
	// uppercase hex. Accept either case while still refusing whitespace, compact
	// hex, braces, URNs, and every other non-canonical textual shape.
	if err != nil || id == uuid.Nil || trimmed != value || !strings.EqualFold(id.String(), trimmed) {
		return uuid.Nil, domain.ErrInvalid
	}
	return id, nil
}

func participantIdentityObject(value any) (uuid.UUID, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return uuid.Nil, domain.ErrInvalid
	}
	allowedDescriptor := map[string]struct{}{
		"displayname": {}, "name": {}, "username": {}, "avatarcolor": {}, "profileimageurl": {},
		"email": {}, "phone": {},
	}
	identityFields := map[string]struct{}{
		"id": {}, "backenduserid": {}, "userid": {}, "memberid": {},
	}
	var result uuid.UUID
	found := false
	seen := make(map[string]struct{}, len(object))
	for key, item := range object {
		normalized := normalizeJSONKey(key)
		if _, duplicate := seen[normalized]; duplicate {
			return uuid.Nil, domain.ErrInvalid
		}
		seen[normalized] = struct{}{}
		if _, identity := identityFields[normalized]; identity {
			if found {
				return uuid.Nil, domain.ErrInvalid
			}
			id, err := participantScalar(item)
			if err != nil {
				return uuid.Nil, err
			}
			found, result = true, id
			continue
		}
		if _, descriptor := allowedDescriptor[normalized]; !descriptor {
			return uuid.Nil, domain.ErrInvalid
		}
		if item != nil {
			if _, ok := item.(string); !ok {
				return uuid.Nil, domain.ErrInvalid
			}
		}
	}
	if !found {
		return uuid.Nil, domain.ErrInvalid
	}
	return result, nil
}
