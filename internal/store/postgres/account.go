package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type accountConversation struct {
	id          uuid.UUID
	createdBy   uuid.UUID
	metadata    json.RawMessage
	role        string
	successorID pgtype.UUID
}

// DeleteAccount irreversibly removes every authentication and discovery
// identifier in one serializable transaction. The users/devices rows become
// non-loginable tombstones where shared messages and financial entities still
// require their foreign keys.
func (s *Store) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", userID); err != nil {
		return err
	}

	var identity store.AccountIdentity
	var profile json.RawMessage
	var deletedAt *time.Time
	identity.UserID = userID
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(email,''),COALESCE(phone,''),display_name,profile,deleted_at
		FROM users WHERE id=$1 FOR UPDATE`, userID,
	).Scan(&identity.Email, &identity.Phone, &identity.DisplayName, &profile, &deletedAt)
	if errors.Is(err, pgx.ErrNoRows) || deletedAt != nil {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	identity.Username = accountUsername(profile)

	rows, err := tx.Query(ctx, `
		SELECT c.id,c.created_by,c.metadata,m.role,successor.user_id
		FROM conversation_members m
		JOIN conversations c ON c.id=m.conversation_id
		LEFT JOIN LATERAL (
			SELECT other.user_id
			FROM conversation_members other
			WHERE other.conversation_id=m.conversation_id AND other.user_id<>m.user_id
			ORDER BY other.joined_at,other.user_id
			LIMIT 1
		) successor ON true
		WHERE m.user_id=$1
		ORDER BY c.id
		FOR UPDATE OF c,m`, userID)
	if err != nil {
		return err
	}
	var conversations []accountConversation
	for rows.Next() {
		var conversation accountConversation
		if err := rows.Scan(
			&conversation.id, &conversation.createdBy, &conversation.metadata,
			&conversation.role, &conversation.successorID,
		); err != nil {
			rows.Close()
			return err
		}
		conversations = append(conversations, conversation)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	var deletedConversationIDs []uuid.UUID
	var sharedConversationIDs []uuid.UUID
	var objectKeys []string
	deleteNotBefore := mediaDeleteNotBefore(time.Time{})
	profileMediaRows, err := tx.Query(ctx, `
		DELETE FROM profile_media_objects
		WHERE owner_id=$1 RETURNING object_key,upload_valid_until`, userID)
	if err != nil {
		return err
	}
	for profileMediaRows.Next() {
		var key string
		var uploadValidUntil time.Time
		if err := profileMediaRows.Scan(&key, &uploadValidUntil); err != nil {
			profileMediaRows.Close()
			return err
		}
		objectKeys = append(objectKeys, key)
		if candidate := mediaDeleteNotBefore(uploadValidUntil); candidate.After(deleteNotBefore) {
			deleteNotBefore = candidate
		}
	}
	if err := profileMediaRows.Err(); err != nil {
		profileMediaRows.Close()
		return err
	}
	profileMediaRows.Close()
	for _, conversation := range conversations {
		if !conversation.successorID.Valid {
			mediaRows, err := tx.Query(ctx, `
				SELECT object_key,upload_valid_until FROM media_objects
				WHERE conversation_id=$1 ORDER BY object_key`,
				conversation.id)
			if err != nil {
				return err
			}
			for mediaRows.Next() {
				var key string
				var uploadValidUntil time.Time
				if err := mediaRows.Scan(&key, &uploadValidUntil); err != nil {
					mediaRows.Close()
					return err
				}
				objectKeys = append(objectKeys, key)
				if candidate := mediaDeleteNotBefore(uploadValidUntil); candidate.After(deleteNotBefore) {
					deleteNotBefore = candidate
				}
			}
			if err := mediaRows.Err(); err != nil {
				mediaRows.Close()
				return err
			}
			mediaRows.Close()
			if _, err := tx.Exec(ctx, `DELETE FROM conversations WHERE id=$1`, conversation.id); err != nil {
				return err
			}
			deletedConversationIDs = append(deletedConversationIDs, conversation.id)
			continue
		}

		metadata := conversation.metadata
		if anonymized, changed, anonymizeErr := store.AnonymizeAccountJSON(metadata, identity); anonymizeErr != nil {
			return anonymizeErr
		} else if changed {
			metadata = anonymized
		}
		createdBy := conversation.createdBy
		if createdBy == userID {
			createdBy = conversation.successorID.Bytes
		}
		if _, err := tx.Exec(ctx, `
			UPDATE conversations SET created_by=$2,metadata=$3,updated_at=now() WHERE id=$1`,
			conversation.id, createdBy, metadata); err != nil {
			return err
		}
		if conversation.role == "owner" {
			if _, err := tx.Exec(ctx, `
				UPDATE conversation_members SET role='owner'
				WHERE conversation_id=$1 AND user_id=$2`,
				conversation.id, conversation.successorID.Bytes); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM receipts WHERE conversation_id=$1 AND user_id=$2`,
			conversation.id, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`,
			conversation.id, userID); err != nil {
			return err
		}
		metadata, err = projectConversationMetadata(ctx, tx, conversation.id, metadata)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE conversations SET metadata=$2 WHERE id=$1`,
			conversation.id, metadata); err != nil {
			return err
		}
		sharedConversationIDs = append(sharedConversationIDs, conversation.id)
	}

	var updatedEntities []domain.Entity
	if len(sharedConversationIDs) > 0 {
		entityRows, err := tx.Query(ctx, `
			SELECT conversation_id,kind,id,version,payload,created_by,created_at,updated_at,deleted_at
			FROM entities WHERE conversation_id=ANY($1) FOR UPDATE`, sharedConversationIDs)
		if err != nil {
			return err
		}
		var entities []domain.Entity
		for entityRows.Next() {
			var entity domain.Entity
			if err := entityRows.Scan(
				&entity.ConversationID, &entity.Kind, &entity.ID, &entity.Version,
				&entity.Payload, &entity.CreatedBy, &entity.CreatedAt, &entity.UpdatedAt,
				&entity.DeletedAt,
			); err != nil {
				entityRows.Close()
				return err
			}
			entities = append(entities, entity)
		}
		if err := entityRows.Err(); err != nil {
			entityRows.Close()
			return err
		}
		entityRows.Close()
		for _, entity := range entities {
			payload, changed, err := store.AnonymizeAccountJSON(entity.Payload, identity)
			if err != nil {
				return err
			}
			if !changed {
				continue
			}
			entity.Payload = payload
			entity.Version++
			entity.UpdatedAt = time.Now().UTC()
			if _, err := tx.Exec(ctx, `
				UPDATE entities SET payload=$4,version=$5,updated_at=$6
				WHERE conversation_id=$1 AND kind=$2 AND id=$3`,
				entity.ConversationID, entity.Kind, entity.ID, entity.Payload,
				entity.Version, entity.UpdatedAt); err != nil {
				return err
			}
			updatedEntities = append(updatedEntities, entity)
		}
	}

	statements := []struct {
		query string
		args  []any
	}{
		{`DELETE FROM conversation_invites
		  WHERE invited_by=$1 OR claimed_by=$1 OR ($2<>'' AND phone=$2)`, []any{userID, identity.Phone}},
		{`UPDATE conversation_invite_links SET revoked_at=COALESCE(revoked_at,now())
		  WHERE created_by=$1`, []any{userID}},
		{`DELETE FROM external_identities WHERE user_id=$1`, []any{userID}},
		{`DELETE FROM age_assurances WHERE user_id=$1`, []any{userID}},
		{`DELETE FROM password_reset_challenges WHERE user_id=$1`, []any{userID}},
		{`DELETE FROM sessions WHERE user_id=$1`, []any{userID}},
		{`DELETE FROM one_time_prekeys
		  WHERE device_id IN (SELECT id FROM devices WHERE user_id=$1)`, []any{userID}},
		{`UPDATE devices SET name='Deleted device',push_token='',identity_key='',signed_prekey=NULL
		  WHERE user_id=$1`, []any{userID}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}

	// The outbox is transport state, not an audit log. Remove stale copies of
	// identity data before enqueueing the sanitized entity updates below.
	if _, err := tx.Exec(ctx, `
		DELETE FROM outbox_events
		WHERE aggregate_id=ANY($5)
		   OR position($1 in payload::text)>0
		   OR ($2<>'' AND position(lower($2) in lower(payload::text))>0)
		   OR ($3<>'' AND position($3 in payload::text)>0)
		   OR ($4<>'' AND position(lower($4) in lower(payload::text))>0)`,
		userID.String(), identity.Email, identity.Phone, identity.Username,
		deletedConversationIDs); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE users SET email=NULL,phone=NULL,display_name=$2,avatar_url='',
			profile='{"deleted":true}'::jsonb,password_hash='',deleted_at=now(),updated_at=now()
		WHERE id=$1`, userID, store.DeletedUserDisplayName); err != nil {
		return err
	}
	for _, entity := range updatedEntities {
		payload, err := json.Marshal(entity)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO outbox_events(topic,aggregate_id,payload)
			VALUES('entity.updated',$1,$2)`, entity.ConversationID, payload); err != nil {
			return err
		}
	}
	if len(objectKeys) > 0 {
		for start := 0; start < len(objectKeys); start += store.MediaDeleteBatchSize {
			end := min(start+store.MediaDeleteBatchSize, len(objectKeys))
			if err := enqueueMediaDeletesAt(
				ctx, tx, userID, objectKeys[start:end], deleteNotBefore,
			); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func accountUsername(profile json.RawMessage) string {
	var value struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(profile, &value)
	return strings.TrimSpace(value.Username)
}
