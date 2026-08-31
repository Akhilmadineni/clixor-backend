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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type accountConversation struct {
	id          uuid.UUID
	createdBy   uuid.UUID
	metadata    json.RawMessage
	role        string
	successorID pgtype.UUID
	ownerID     pgtype.UUID
	active      bool
}

// DeleteAccount irreversibly removes every authentication and discovery
// identifier in one serializable transaction. The users/devices rows become
// non-loginable tombstones where shared messages and financial entities still
// require their foreign keys.
func (s *Store) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := s.deleteAccount(ctx, userID)
		if !isAccountDeletionRetryable(err) || attempt == maxAttempts-1 {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) deleteAccount(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.deleteAccountTx(ctx, tx, userID, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func isAccountDeletionRetryable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01")
}

func (s *Store) deleteAccountTx(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	beforeMutation store.AccountDeletionFence,
) error {
	// This must be the first lock in every account-erasure transaction. Active
	// delivery callbacks hold the shared form, so erasure cannot take user or
	// transport row locks while a callback uses another pooled Store method.
	if err := lockAccountDeliveryBarrierExclusive(ctx, tx); err != nil {
		return err
	}
	if err := lockMediaQuota(ctx, tx, "user", userID); err != nil {
		return err
	}

	var identity store.AccountIdentity
	var profile json.RawMessage
	var deletedAt *time.Time
	identity.UserID = userID
	err := tx.QueryRow(ctx, `
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
	if beforeMutation != nil {
		if err := beforeMutation(userID); err != nil {
			return err
		}
	}

	rows, err := tx.Query(ctx, `
		WITH account_conversations AS MATERIALIZED (
			SELECT conversation_id FROM conversation_members WHERE user_id=$1
			UNION
			SELECT conversation_id FROM conversation_member_tombstones WHERE user_id=$1
		)
		SELECT c.id,c.created_by,c.metadata,COALESCE(m.role,''),successor.user_id,
		       owner.user_id,(m.user_id IS NOT NULL)
		FROM account_conversations account
		JOIN conversations c ON c.id=account.conversation_id
		LEFT JOIN conversation_members m
		  ON m.conversation_id=c.id AND m.user_id=$1
		LEFT JOIN LATERAL (
			SELECT other.user_id
			FROM conversation_members other
			WHERE other.conversation_id=c.id AND other.user_id<>$1
			ORDER BY other.joined_at,other.user_id
			LIMIT 1
		) successor ON true
		LEFT JOIN LATERAL (
			SELECT current_owner.user_id
			FROM conversation_members current_owner
			WHERE current_owner.conversation_id=c.id
			  AND current_owner.user_id<>$1 AND current_owner.role='owner'
			ORDER BY current_owner.joined_at,current_owner.user_id
			LIMIT 1
		) owner ON true
		ORDER BY c.id
		FOR UPDATE OF c`, userID)
	if err != nil {
		return err
	}
	var conversations []accountConversation
	for rows.Next() {
		var conversation accountConversation
		if err := rows.Scan(
			&conversation.id, &conversation.createdBy, &conversation.metadata,
			&conversation.role, &conversation.successorID, &conversation.ownerID,
			&conversation.active,
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
	// Ready conversation ciphertext is shared history and remains available to
	// the other members. Pending uploads are private capabilities owned by the
	// departing account, so revoke them and schedule their staging objects for
	// deletion before the user tombstone is committed.
	pendingMediaRows, err := tx.Query(ctx, `
		DELETE FROM media_objects
		WHERE owner_id=$1 AND status='pending'
		RETURNING object_key,upload_valid_until`, userID)
	if err != nil {
		return err
	}
	for pendingMediaRows.Next() {
		var key string
		var uploadValidUntil time.Time
		if err := pendingMediaRows.Scan(&key, &uploadValidUntil); err != nil {
			pendingMediaRows.Close()
			return err
		}
		objectKeys = append(objectKeys, key)
		if candidate := mediaDeleteNotBefore(uploadValidUntil); candidate.After(deleteNotBefore) {
			deleteNotBefore = candidate
		}
	}
	if err := pendingMediaRows.Err(); err != nil {
		pendingMediaRows.Close()
		return err
	}
	pendingMediaRows.Close()
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
			if conversation.ownerID.Valid {
				createdBy = conversation.ownerID.Bytes
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE conversations SET created_by=$2,metadata=$3,updated_at=now() WHERE id=$1`,
			conversation.id, createdBy, metadata); err != nil {
			return err
		}
		promoteSuccessor := (conversation.active && conversation.role == "owner") ||
			(!conversation.ownerID.Valid && conversation.createdBy == userID)
		if _, err := tx.Exec(ctx, `
			DELETE FROM receipts WHERE conversation_id=$1 AND user_id=$2`,
			conversation.id, userID); err != nil {
			return err
		}
		if conversation.active {
			tombstone := store.ConversationMemberTombstone{UserID: userID}
			if err := tx.QueryRow(ctx, `
				SELECT local_id FROM conversation_member_local_ids
				WHERE conversation_id=$1 AND user_id=$2`, conversation.id, userID,
			).Scan(&tombstone.LocalID); err != nil {
				return mapError(err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO conversation_member_tombstones(conversation_id,user_id,local_id)
				VALUES($1,$2,$3) ON CONFLICT(conversation_id,user_id) DO NOTHING`,
				conversation.id, userID, tombstone.LocalID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`,
				conversation.id, userID); err != nil {
				return err
			}
		}
		// The unique owner index is immediate. Remove the departing owner before
		// promoting the successor so the invariant is never violated by two
		// simultaneously visible owner rows inside this transaction.
		if promoteSuccessor {
			if _, err := tx.Exec(ctx, `
				UPDATE conversation_members SET role='owner'
				WHERE conversation_id=$1 AND user_id=$2`,
				conversation.id, conversation.successorID.Bytes); err != nil {
				return err
			}
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

		// Idempotent chore commands retain their complete response for 90 days.
		// Those response snapshots are externally replayable and therefore need
		// the same erasure treatment as the live chore/feed entities.
		rotationRows, err := tx.Query(ctx, `
			SELECT operation_id,chore_result,feed_result
			FROM chore_rotation_operations
			WHERE conversation_id=ANY($1)
			FOR UPDATE`, sharedConversationIDs)
		if err != nil {
			return err
		}
		type rotationSnapshot struct {
			operationID uuid.UUID
			choreResult json.RawMessage
			feedResult  json.RawMessage
		}
		var snapshots []rotationSnapshot
		for rotationRows.Next() {
			var snapshot rotationSnapshot
			if err := rotationRows.Scan(
				&snapshot.operationID, &snapshot.choreResult, &snapshot.feedResult,
			); err != nil {
				rotationRows.Close()
				return err
			}
			snapshots = append(snapshots, snapshot)
		}
		if err := rotationRows.Err(); err != nil {
			rotationRows.Close()
			return err
		}
		rotationRows.Close()
		for _, snapshot := range snapshots {
			choreResult, choreChanged, err := store.AnonymizeAccountJSON(
				snapshot.choreResult, identity,
			)
			if err != nil {
				return err
			}
			feedResult, feedChanged, err := store.AnonymizeAccountJSON(
				snapshot.feedResult, identity,
			)
			if err != nil {
				return err
			}
			if !choreChanged && !feedChanged {
				continue
			}
			if !choreChanged {
				choreResult = snapshot.choreResult
			}
			if !feedChanged {
				feedResult = snapshot.feedResult
			}
			if _, err := tx.Exec(ctx, `
				UPDATE chore_rotation_operations
				SET chore_result=$2,feed_result=$3
				WHERE operation_id=$1`,
				snapshot.operationID, choreResult, feedResult); err != nil {
				return err
			}
		}
	}

	// Establish transport-row ownership before clearing device credentials.
	// Realtime/APNs delivery leases hold row-share locks while their external
	// callback runs. These exact deletes/updates therefore serialize erasure:
	// publication first is allowed to finish, while erasure first makes the
	// later callback re-fetch observe no deliverable row.
	if err := sanitizeAccountOutbox(
		ctx, tx, identity, deletedConversationIDs, sharedConversationIDs, updatedEntities,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM push_deliveries
		WHERE device_id IN (SELECT id FROM devices WHERE user_id=$1)`, userID); err != nil {
		return err
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
	return nil
}

func sanitizeAccountOutbox(
	ctx context.Context,
	tx pgx.Tx,
	identity store.AccountIdentity,
	deletedConversationIDs, sharedConversationIDs []uuid.UUID,
	updatedEntities []domain.Entity,
) error {
	if len(deletedConversationIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			DELETE FROM outbox_events WHERE aggregate_id=ANY($1)`, deletedConversationIDs); err != nil {
			return err
		}
	}
	if len(sharedConversationIDs) == 0 {
		return nil
	}
	topics := []string{
		"conversation.created", "conversation.updated", "conversation.member_added", "receipt.updated",
		"entity.updated", "entity.deleted",
	}
	rows, err := tx.Query(ctx, `
		SELECT id,topic,aggregate_id,payload
		FROM outbox_events
		WHERE aggregate_id=ANY($1) AND topic=ANY($2)
		ORDER BY id
		FOR UPDATE`, sharedConversationIDs, topics)
	if err != nil {
		return err
	}
	type affectedEvent struct {
		id          int64
		topic       string
		aggregateID uuid.UUID
		payload     json.RawMessage
	}
	var events []affectedEvent
	for rows.Next() {
		var event affectedEvent
		if err := rows.Scan(&event.id, &event.topic, &event.aggregateID, &event.payload); err != nil {
			rows.Close()
			return err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	affectedEntities := make(map[string]struct{}, len(updatedEntities))
	for _, entity := range updatedEntities {
		affectedEntities[entity.ConversationID.String()+"\x00"+entity.Kind+"\x00"+entity.ID.String()] = struct{}{}
	}
	for _, event := range events {
		if !store.AccountErasureOutboxTopic(event.topic) {
			return domain.ErrInvalid
		}
		typed, schemaErr := store.DecodeAccountOutboxPayload(
			event.topic, event.aggregateID, event.payload,
		)
		if schemaErr != nil {
			// Known-topic transport state is disposable. A row outside the exact
			// service-owned schema cannot safely be replayed after erasure.
			if _, err := tx.Exec(ctx, `DELETE FROM outbox_events WHERE id=$1`, event.id); err != nil {
				return err
			}
			continue
		}
		if (event.topic == "receipt.updated" || event.topic == "conversation.member_added") &&
			(typed.UserID == identity.UserID || typed.ActorID == identity.UserID) {
			if _, err := tx.Exec(ctx, `DELETE FROM outbox_events WHERE id=$1`, event.id); err != nil {
				return err
			}
			continue
		}
		if event.topic == "receipt.updated" || event.topic == "conversation.member_added" {
			continue
		}
		authorized, err := store.AccountJSONReferencesIdentity(event.payload, identity)
		if err != nil {
			if _, deleteErr := tx.Exec(ctx, `DELETE FROM outbox_events WHERE id=$1`, event.id); deleteErr != nil {
				return deleteErr
			}
			continue
		}
		if event.topic == "entity.updated" || event.topic == "entity.deleted" {
			_, entityAffected := affectedEntities[typed.ConversationID.String()+"\x00"+typed.EntityKind+"\x00"+typed.EntityID.String()]
			authorized = authorized || entityAffected
		}
		if !authorized {
			continue
		}
		_, changed, err := store.AnonymizeAccountJSONWithAuthority(event.payload, identity)
		if err != nil {
			// JSONB itself is valid, but a structurally unsupported value must not
			// retain erased identity in disposable transport state.
			if _, deleteErr := tx.Exec(ctx, `DELETE FROM outbox_events WHERE id=$1`, event.id); deleteErr != nil {
				return deleteErr
			}
			continue
		}
		if !changed {
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM outbox_events WHERE id=$1`, event.id); err != nil {
			return err
		}
	}
	return nil
}

func accountUsername(profile json.RawMessage) string {
	var value struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(profile, &value)
	return strings.TrimSpace(value.Username)
}
