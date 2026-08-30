package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateConversationInvite(ctx context.Context, p store.CreateConversationInviteParams) (domain.ConversationInvite, error) {
	if len(p.TokenHash) != 32 || p.MaxUses < 1 || p.MaxUses > 1000 || !p.ExpiresAt.After(time.Now()) {
		return domain.ConversationInvite{}, domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ConversationInvite{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockLiveUser(ctx, tx, p.ActorID); err != nil {
		return domain.ConversationInvite{}, err
	}
	var kind, role string
	err = tx.QueryRow(ctx, `
		SELECT c.kind,m.role FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1 FOR UPDATE OF c`, p.ConversationID, p.ActorID).Scan(&kind, &role)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && role != "owner" && role != "admin") {
		return domain.ConversationInvite{}, domain.ErrForbidden
	}
	if err != nil {
		return domain.ConversationInvite{}, err
	}
	if kind != "group" {
		return domain.ConversationInvite{}, domain.ErrInvalid
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now().UTC()
	invite := domain.ConversationInvite{
		ID: p.ID, ConversationID: p.ConversationID, CreatedBy: p.ActorID,
		MaxUses: p.MaxUses, ExpiresAt: p.ExpiresAt.UTC(), CreatedAt: now,
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO conversation_invite_links(
			id,conversation_id,token_hash,created_by,max_uses,uses,expires_at,created_at
		) VALUES($1,$2,$3,$4,$5,0,$6,$7)
		RETURNING id,conversation_id,created_by,max_uses,uses,expires_at,revoked_at,created_at`,
		invite.ID, invite.ConversationID, p.TokenHash, invite.CreatedBy,
		invite.MaxUses, invite.ExpiresAt, invite.CreatedAt,
	).Scan(&invite.ID, &invite.ConversationID, &invite.CreatedBy, &invite.MaxUses,
		&invite.Uses, &invite.ExpiresAt, &invite.RevokedAt, &invite.CreatedAt)
	if err != nil {
		return domain.ConversationInvite{}, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ConversationInvite{}, err
	}
	return invite, nil
}

func (s *Store) ConversationInvitePreview(ctx context.Context, tokenHash []byte, userID uuid.UUID) (domain.ConversationInvitePreview, error) {
	var invite domain.ConversationInvite
	var preview domain.ConversationInvitePreview
	err := s.pool.QueryRow(ctx, `
		SELECT i.id,i.conversation_id,i.created_by,i.max_uses,i.uses,i.expires_at,i.revoked_at,i.created_at,
		       c.kind,c.title,c.avatar_url,
		       EXISTS(SELECT 1 FROM conversation_members m WHERE m.conversation_id=i.conversation_id AND m.user_id=$2)
		FROM conversation_invite_links i
		JOIN conversations c ON c.id=i.conversation_id
		WHERE i.token_hash=$1`, tokenHash, userID,
	).Scan(&invite.ID, &invite.ConversationID, &invite.CreatedBy, &invite.MaxUses, &invite.Uses,
		&invite.ExpiresAt, &invite.RevokedAt, &invite.CreatedAt,
		&preview.Kind, &preview.Title, &preview.AvatarURL, &preview.AlreadyMember)
	if err != nil {
		return domain.ConversationInvitePreview{}, mapError(err)
	}
	if err := postgresConversationInviteActiveError(invite, time.Now()); err != nil {
		return domain.ConversationInvitePreview{}, err
	}
	preview.InviteID = invite.ID
	preview.ExpiresAt = invite.ExpiresAt
	return preview, nil
}

func (s *Store) AcceptConversationInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID) (domain.ConversationInviteAcceptance, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockLiveUser(ctx, tx, userID); err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	// Resolve the immutable relationship without a row lock, then acquire locks
	// in the same user -> conversation -> invite order used by account deletion.
	// A combined FOR UPDATE join leaves relation lock order to the planner and can
	// deadlock with the legacy tombstone trigger (conversation -> invite).
	var inviteID, conversationID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id,conversation_id FROM conversation_invite_links
		WHERE token_hash=$1`, tokenHash,
	).Scan(&inviteID, &conversationID); err != nil {
		return domain.ConversationInviteAcceptance{}, mapError(err)
	}
	var invite domain.ConversationInvite
	var conversation domain.Conversation
	err = tx.QueryRow(ctx, `
		SELECT id,kind,title,avatar_url,metadata,created_by,last_seq,created_at,updated_at
		FROM conversations WHERE id=$1 FOR UPDATE`, conversationID,
	).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
		&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
		&conversation.CreatedAt, &conversation.UpdatedAt)
	if err != nil {
		return domain.ConversationInviteAcceptance{}, mapError(err)
	}
	err = tx.QueryRow(ctx, `
		SELECT id,conversation_id,created_by,max_uses,uses,expires_at,revoked_at,created_at
		FROM conversation_invite_links
		WHERE id=$1 AND conversation_id=$2 AND token_hash=$3
		FOR UPDATE`, inviteID, conversationID, tokenHash,
	).Scan(&invite.ID, &invite.ConversationID, &invite.CreatedBy, &invite.MaxUses, &invite.Uses,
		&invite.ExpiresAt, &invite.RevokedAt, &invite.CreatedAt)
	if err != nil {
		return domain.ConversationInviteAcceptance{}, mapError(err)
	}
	now := time.Now().UTC()
	var alreadyMember bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2)`,
		invite.ConversationID, userID).Scan(&alreadyMember); err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	if alreadyMember {
		projected, projectionErr := projectConversationMetadata(
			ctx, tx, conversation.ID, conversation.Metadata,
		)
		if projectionErr != nil {
			return domain.ConversationInviteAcceptance{}, projectionErr
		}
		if !store.JSONValuesEqual(projected, conversation.Metadata) {
			conversation.Metadata = projected
			err = tx.QueryRow(ctx, `
				UPDATE conversations SET metadata=$2,updated_at=$3 WHERE id=$1
				RETURNING updated_at`, conversation.ID, conversation.Metadata, now,
			).Scan(&conversation.UpdatedAt)
			if err != nil {
				return domain.ConversationInviteAcceptance{}, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.ConversationInviteAcceptance{}, err
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
	if conversation.Kind != "group" {
		return domain.ConversationInviteAcceptance{}, domain.ErrInvalid
	}
	var memberCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM conversation_members WHERE conversation_id=$1`,
		invite.ConversationID).Scan(&memberCount); err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	if memberCount >= 1024 {
		return domain.ConversationInviteAcceptance{}, domain.ErrInvalid
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO conversation_members(conversation_id,user_id,role,joined_at)
		VALUES($1,$2,'member',$3)`, invite.ConversationID, userID, now); err != nil {
		return domain.ConversationInviteAcceptance{}, mapError(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM conversation_member_tombstones WHERE conversation_id=$1 AND user_id=$2`, invite.ConversationID, userID); err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE conversation_invite_links SET uses=uses+1 WHERE id=$1`, invite.ID); err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	conversation.Metadata, err = projectConversationMetadata(
		ctx, tx, conversation.ID, conversation.Metadata,
	)
	if err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	err = tx.QueryRow(ctx, `
		UPDATE conversations SET metadata=$2,updated_at=$3 WHERE id=$1
		RETURNING id,kind,title,avatar_url,metadata,created_by,last_seq,created_at,updated_at`,
		conversation.ID, conversation.Metadata, now,
	).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
		&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
		&conversation.CreatedAt, &conversation.UpdatedAt)
	if err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	payload, _ := json.Marshal(domain.ConversationMemberAdded{
		ConversationID: conversation.ID, ActorID: userID, UserID: userID,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload)
		VALUES('conversation.member_added',$1,$2)`, conversation.ID, payload); err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.ConversationInviteAcceptance{}, err
	}
	return domain.ConversationInviteAcceptance{Conversation: conversation, Joined: true}, nil
}

func (s *Store) RevokeConversationInvite(ctx context.Context, conversationID, actorID, inviteID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var role string
	err = tx.QueryRow(ctx, `
		SELECT role FROM conversation_members
		WHERE conversation_id=$1 AND user_id=$2`, conversationID, actorID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && role != "owner" && role != "admin") {
		return domain.ErrForbidden
	}
	if err != nil {
		return err
	}
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT revoked_at FROM conversation_invite_links
		WHERE id=$1 AND conversation_id=$2 FOR UPDATE`, inviteID, conversationID).Scan(&revokedAt)
	if err != nil {
		return mapError(err)
	}
	if revokedAt == nil {
		if _, err := tx.Exec(ctx, `
			UPDATE conversation_invite_links SET revoked_at=now() WHERE id=$1`, inviteID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func postgresConversationInviteActiveError(invite domain.ConversationInvite, now time.Time) error {
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
