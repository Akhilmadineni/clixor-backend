package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/domain"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, databaseURL string, autoMigrate bool) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	config.MaxConns = 50
	config.MinConns = 5
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if autoMigrate {
		if err := Migrate(ctx, pool); err != nil {
			pool.Close()
			return nil, err
		}
	}
	if err := ValidateMigrations(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close()                         { s.pool.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) CreateUser(ctx context.Context, p store.CreateUserParams) (domain.User, error) {
	now := time.Now().UTC()
	user := domain.User{
		ID: uuid.New(), Email: nullableString(strings.ToLower(strings.TrimSpace(p.Email))),
		Phone: nullableString(p.Phone), DisplayName: p.DisplayName, PasswordHash: p.PasswordHash,
		Profile: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now,
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (id,email,phone,display_name,password_hash,created_at,updated_at)
		VALUES ($1,NULLIF($2,''),NULLIF($3,''),$4,$5,$6,$6)
		RETURNING id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at`,
		user.ID, user.Email, user.Phone, user.DisplayName, user.PasswordHash, now,
	).Scan(&user.ID, &user.Email, &user.Phone, &user.DisplayName, &user.AvatarURL, &user.Profile,
		&user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	return user, mapError(err)
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users WHERE id=$1`, id))
}

func (s *Store) UserByEmail(ctx context.Context, email string) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)))
}

func (s *Store) UserByPhone(ctx context.Context, phone string) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users WHERE phone=$1`, phone))
}

func (s *Store) UsersByPhones(ctx context.Context, phones []string) ([]domain.User, error) {
	if len(phones) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users WHERE phone = ANY($1) ORDER BY phone`, phones)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, user)
	}
	return result, rows.Err()
}

func (s *Store) UserByExternalIdentity(ctx context.Context, provider, subject string) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT u.id,COALESCE(u.email,''),COALESCE(u.phone,''),u.display_name,u.avatar_url,
		       u.profile,u.password_hash,u.created_at,u.updated_at
		FROM users u JOIN external_identities i ON i.user_id=u.id
		WHERE i.provider=$1 AND i.subject=$2`, provider, subject))
}

func (s *Store) LinkExternalIdentity(ctx context.Context, provider, subject string, userID uuid.UUID, email string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO external_identities(provider,subject,user_id,email)
		VALUES($1,$2,$3,NULLIF($4,''))
		ON CONFLICT(provider,subject) DO UPDATE SET
		  email=COALESCE(EXCLUDED.email,external_identities.email)
		WHERE external_identities.user_id=EXCLUDED.user_id`,
		provider, subject, userID, email)
	return mapError(err)
}

func (s *Store) UpdateUserProfile(ctx context.Context, id uuid.UUID, profile json.RawMessage) (domain.User, error) {
	var p struct {
		DisplayName string `json:"display_name"`
		AvatarURL   string `json:"avatar_url"`
	}
	_ = json.Unmarshal(profile, &p)
	return scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET
			profile=$2,
			display_name=COALESCE(NULLIF($3,''),display_name),
			avatar_url=COALESCE(NULLIF($4,''),avatar_url),
			updated_at=now()
		WHERE id=$1
		RETURNING id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at`,
		id, profile, p.DisplayName, p.AvatarURL))
}

func (s *Store) UpsertDevice(ctx context.Context, device domain.Device) (domain.Device, error) {
	if device.ID == uuid.Nil {
		device.ID = uuid.New()
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO devices (id,user_id,name,platform,push_token,identity_key,signed_prekey,last_seen_at,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now(),$8)
		ON CONFLICT (id) DO UPDATE SET
			name=EXCLUDED.name,platform=EXCLUDED.platform,
			push_token=CASE WHEN EXCLUDED.push_token='' THEN devices.push_token ELSE EXCLUDED.push_token END,
			identity_key=CASE WHEN EXCLUDED.identity_key='' THEN devices.identity_key ELSE EXCLUDED.identity_key END,
			signed_prekey=COALESCE(EXCLUDED.signed_prekey,devices.signed_prekey),last_seen_at=now()
		WHERE devices.user_id=EXCLUDED.user_id
		RETURNING id,user_id,name,platform,push_token,identity_key,COALESCE(signed_prekey,'null'::jsonb),last_seen_at,created_at`,
		device.ID, device.UserID, device.Name, device.Platform, device.PushToken,
		device.IdentityKey, nullableJSON(device.SignedPreKey), device.CreatedAt,
	).Scan(&device.ID, &device.UserID, &device.Name, &device.Platform, &device.PushToken,
		&device.IdentityKey, &device.SignedPreKey, &device.LastSeenAt, &device.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT intentionally refuses to reassign a device identity to a
		// different account. That is a conflict, not a missing resource.
		return domain.Device{}, domain.ErrConflict
	}
	return device, mapError(err)
}

func (s *Store) Device(ctx context.Context, userID, deviceID uuid.UUID) (domain.Device, error) {
	return scanDevice(s.pool.QueryRow(ctx, `
		SELECT id,user_id,name,platform,push_token,identity_key,COALESCE(signed_prekey,'null'::jsonb),last_seen_at,created_at
		FROM devices WHERE id=$1 AND user_id=$2`, deviceID, userID))
}

func (s *Store) ListDevices(ctx context.Context, userID uuid.UUID) ([]domain.Device, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id,user_id,name,platform,push_token,identity_key,COALESCE(signed_prekey,'null'::jsonb),last_seen_at,created_at
		FROM devices WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, device)
	}
	return result, rows.Err()
}

func (s *Store) ClearDevicePushToken(ctx context.Context, userID, deviceID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices SET push_token='' WHERE id=$1 AND user_id=$2`, deviceID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) PutOneTimePreKeys(ctx context.Context, deviceID uuid.UUID, keys []domain.OneTimePreKey) error {
	batch := &pgx.Batch{}
	for _, key := range keys {
		batch.Queue(`
			INSERT INTO one_time_prekeys(device_id,key_id,public_key)
			VALUES($1,$2,$3) ON CONFLICT(device_id,key_id) DO NOTHING`,
			deviceID, key.KeyID, key.PublicKey)
	}
	results := s.pool.SendBatch(ctx, batch)
	defer results.Close()
	for range keys {
		if _, err := results.Exec(); err != nil {
			return mapError(err)
		}
	}
	return results.Close()
}

func (s *Store) ClaimPreKeys(ctx context.Context, targetUserID uuid.UUID) ([]domain.PreKeyBundle, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT id,user_id,name,platform,push_token,identity_key,COALESCE(signed_prekey,'null'::jsonb),last_seen_at,created_at
		FROM devices WHERE user_id=$1 AND identity_key<>'' ORDER BY created_at`, targetUserID)
	if err != nil {
		return nil, err
	}
	var devices []domain.Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		devices = append(devices, device)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, domain.ErrNotFound
	}
	bundles := make([]domain.PreKeyBundle, 0, len(devices))
	for _, device := range devices {
		bundle := domain.PreKeyBundle{
			DeviceID: device.ID, IdentityKey: device.IdentityKey, SignedPreKey: device.SignedPreKey,
		}
		var preKey domain.OneTimePreKey
		err := tx.QueryRow(ctx, `
			WITH selected AS (
				SELECT id FROM one_time_prekeys
				WHERE device_id=$1 AND claimed_at IS NULL
				ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1
			)
			UPDATE one_time_prekeys p SET claimed_at=now()
			FROM selected WHERE p.id=selected.id
			RETURNING p.id,p.device_id,p.key_id,p.public_key,p.claimed_at`, device.ID,
		).Scan(&preKey.ID, &preKey.DeviceID, &preKey.KeyID, &preKey.PublicKey, &preKey.ClaimedAt)
		if err == nil {
			bundle.OneTimePreKey = &preKey
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return bundles, nil
}

func (s *Store) CreateSession(ctx context.Context, session domain.Session) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions(id,user_id,device_id,refresh_token_hash,expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6)`,
		session.ID, session.UserID, session.DeviceID, session.RefreshTokenHash,
		session.ExpiresAt, session.CreatedAt)
	return mapError(err)
}

func (s *Store) RotateSession(ctx context.Context, id uuid.UUID, oldHash, newHash []byte, expiresAt time.Time) (domain.Session, error) {
	var session domain.Session
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Session{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		SELECT id,user_id,device_id,refresh_token_hash,previous_refresh_token_hash,
		       expires_at,revoked_at,created_at
		FROM sessions WHERE id=$1 FOR UPDATE`, id,
	).Scan(&session.ID, &session.UserID, &session.DeviceID, &session.RefreshTokenHash,
		&session.PreviousRefreshTokenHash, &session.ExpiresAt, &session.RevokedAt,
		&session.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return domain.Session{}, err
	}
	if session.RevokedAt != nil || session.ExpiresAt.Before(time.Now()) {
		return domain.Session{}, domain.ErrUnauthenticated
	}
	if !equalTokenHash(session.RefreshTokenHash, oldHash) {
		if equalTokenHash(session.PreviousRefreshTokenHash, oldHash) {
			if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1`, id); err != nil {
				return domain.Session{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return domain.Session{}, err
			}
		}
		return domain.Session{}, domain.ErrUnauthenticated
	}
	session.PreviousRefreshTokenHash = append([]byte(nil), session.RefreshTokenHash...)
	session.RefreshTokenHash = append([]byte(nil), newHash...)
	session.ExpiresAt = expiresAt
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET previous_refresh_token_hash=refresh_token_hash,
			refresh_token_hash=$2,expires_at=$3 WHERE id=$1`,
		id, newHash, expiresAt); err != nil {
		return domain.Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Session{}, err
	}
	return session, nil
}

func (s *Store) RevokeSession(ctx context.Context, id, userID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) SessionActive(ctx context.Context, id, userID, deviceID uuid.UUID) (bool, error) {
	var active bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM sessions
			WHERE id=$1 AND user_id=$2 AND device_id=$3
			  AND revoked_at IS NULL AND expires_at>now()
		)`, id, userID, deviceID).Scan(&active)
	return active, err
}

func (s *Store) CreateConversation(ctx context.Context, p store.CreateConversationParams) (domain.Conversation, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Conversation{}, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	conversationID := p.ID
	if conversationID == uuid.Nil {
		conversationID = uuid.New()
	}
	conversation := domain.Conversation{
		ID: conversationID, Kind: p.Kind, Title: p.Title, Metadata: jsonOrObject(p.Metadata),
		CreatedBy: p.CreatedBy, CreatedAt: now, UpdatedAt: now,
	}
	directKey := ""
	if p.Kind == "direct" {
		directKey = conversationDirectKey(append([]uuid.UUID{p.CreatedBy}, p.MemberIDs...))
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO conversations(id,kind,direct_key,title,metadata,created_by,created_at,updated_at)
		VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,$7)
		ON CONFLICT DO NOTHING`,
		conversation.ID, conversation.Kind, directKey, conversation.Title, conversation.Metadata,
		conversation.CreatedBy, now)
	if err != nil {
		return domain.Conversation{}, mapError(err)
	}
	if tag.RowsAffected() == 0 {
		err := tx.QueryRow(ctx, `
			SELECT id,kind,title,avatar_url,metadata,created_by,last_seq,created_at,updated_at
			FROM conversations WHERE id=$1 AND created_by=$2`, conversation.ID, p.CreatedBy,
		).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
			&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
			&conversation.CreatedAt, &conversation.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) && directKey != "" {
			err = tx.QueryRow(ctx, `
			SELECT id,kind,title,avatar_url,metadata,created_by,last_seq,created_at,updated_at
			FROM conversations WHERE direct_key=$1`, directKey,
			).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
				&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
				&conversation.CreatedAt, &conversation.UpdatedAt)
		}
		if err != nil {
			return domain.Conversation{}, mapError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.Conversation{}, err
		}
		return conversation, nil
	}
	members := uniqueUUIDs(append([]uuid.UUID{p.CreatedBy}, p.MemberIDs...))
	for _, userID := range members {
		role := "member"
		if userID == p.CreatedBy {
			role = "owner"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO conversation_members(conversation_id,user_id,role,joined_at)
			VALUES($1,$2,$3,$4)`, conversation.ID, userID, role, now); err != nil {
			return domain.Conversation{}, mapError(err)
		}
	}
	for _, phone := range p.InvitePhones {
		if _, err := tx.Exec(ctx, `
			INSERT INTO conversation_invites(conversation_id,phone,invited_by)
			VALUES($1,$2,$3)
			ON CONFLICT(conversation_id,phone) DO UPDATE SET
			  invited_by=EXCLUDED.invited_by,invited_at=now(),claimed_by=NULL,claimed_at=NULL`,
			conversation.ID, phone, p.CreatedBy); err != nil {
			return domain.Conversation{}, mapError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Conversation{}, err
	}
	return conversation, nil
}

func (s *Store) Conversation(ctx context.Context, id, userID uuid.UUID) (domain.Conversation, error) {
	var conversation domain.Conversation
	err := s.pool.QueryRow(ctx, `
		SELECT c.id,c.kind,c.title,c.avatar_url,c.metadata,c.created_by,c.last_seq,c.created_at,c.updated_at
		FROM conversations c JOIN conversation_members m ON m.conversation_id=c.id
		WHERE c.id=$1 AND m.user_id=$2`, id, userID,
	).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
		&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
		&conversation.CreatedAt, &conversation.UpdatedAt)
	return conversation, mapError(err)
}

func (s *Store) ListConversations(ctx context.Context, userID uuid.UUID, before time.Time, limit int) ([]domain.Conversation, error) {
	if before.IsZero() {
		before = time.Now().UTC().Add(time.Hour)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT c.id,c.kind,c.title,c.avatar_url,c.metadata,c.created_by,c.last_seq,c.created_at,c.updated_at
		FROM conversations c JOIN conversation_members m ON m.conversation_id=c.id
		WHERE m.user_id=$1 AND c.updated_at<$2
		ORDER BY c.updated_at DESC,c.id LIMIT $3`, userID, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.Conversation
	for rows.Next() {
		var conversation domain.Conversation
		if err := rows.Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
			&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
			&conversation.CreatedAt, &conversation.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, conversation)
	}
	return result, rows.Err()
}

func (s *Store) UpdateConversation(ctx context.Context, conversationID, actorID uuid.UUID, p store.UpdateConversationParams) (domain.Conversation, error) {
	var conversation domain.Conversation
	var title, avatarURL any
	if p.Title != nil {
		title = *p.Title
	}
	if p.AvatarURL != nil {
		avatarURL = *p.AvatarURL
	}
	var metadata any
	if p.Metadata != nil {
		metadata = *p.Metadata
	}
	err := s.pool.QueryRow(ctx, `
		UPDATE conversations c SET
		  title=CASE WHEN $3::boolean THEN $4 ELSE c.title END,
		  avatar_url=CASE WHEN $5::boolean THEN $6 ELSE c.avatar_url END,
		  metadata=CASE WHEN $7::boolean THEN $8::jsonb ELSE c.metadata END,
		  updated_at=now()
		FROM conversation_members m
		WHERE c.id=$1 AND m.conversation_id=c.id AND m.user_id=$2
		  AND m.role IN ('owner','admin')
		RETURNING c.id,c.kind,c.title,c.avatar_url,c.metadata,c.created_by,c.last_seq,c.created_at,c.updated_at`,
		conversationID, actorID,
		p.Title != nil, title, p.AvatarURL != nil, avatarURL, p.Metadata != nil, metadata,
	).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
		&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
		&conversation.CreatedAt, &conversation.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Conversation{}, domain.ErrForbidden
	}
	return conversation, mapError(err)
}

func (s *Store) DeleteConversation(ctx context.Context, conversationID, actorID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM conversations c USING conversation_members m
		WHERE c.id=$1 AND m.conversation_id=c.id AND m.user_id=$2
		  AND m.role='owner' AND c.created_by=$2`, conversationID, actorID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrForbidden
	}
	return nil
}

func (s *Store) ListConversationMembers(ctx context.Context, conversationID, actorID uuid.UUID) ([]domain.ConversationMember, error) {
	if err := s.requireMember(ctx, s.pool, conversationID, actorID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT conversation_id,user_id,role,joined_at,muted_until
		FROM conversation_members WHERE conversation_id=$1 ORDER BY joined_at`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.ConversationMember
	for rows.Next() {
		var member domain.ConversationMember
		if err := rows.Scan(&member.ConversationID, &member.UserID, &member.Role, &member.JoinedAt, &member.MutedUntil); err != nil {
			return nil, err
		}
		result = append(result, member)
	}
	return result, rows.Err()
}

func (s *Store) ConversationMemberIDs(ctx context.Context, conversationID uuid.UUID) ([]uuid.UUID, error) {
	return conversationMemberIDs(ctx, s.pool, conversationID)
}

func (s *Store) UsersShareConversation(ctx context.Context, first, second uuid.UUID) (bool, error) {
	var shared bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM conversation_members a
			JOIN conversation_members b ON b.conversation_id=a.conversation_id
			WHERE a.user_id=$1 AND b.user_id=$2
		)`, first, second).Scan(&shared)
	return shared, err
}

func (s *Store) AddConversationMember(ctx context.Context, conversationID, actorID, userID uuid.UUID, role string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var kind, actorRole string
	err = tx.QueryRow(ctx, `
		SELECT c.kind,m.role FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1 FOR UPDATE OF c`, conversationID, actorID).Scan(&kind, &actorRole)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrForbidden
	}
	if err != nil {
		return err
	}
	if kind != "group" || (role != "member" && role != "admin") {
		return domain.ErrInvalid
	}
	if actorRole != "owner" && actorRole != "admin" {
		return domain.ErrForbidden
	}
	var targetRole string
	targetErr := tx.QueryRow(ctx, `
		SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`,
		conversationID, userID).Scan(&targetRole)
	if targetErr == nil && targetRole == "owner" {
		return domain.ErrForbidden
	}
	if targetErr != nil && !errors.Is(targetErr, pgx.ErrNoRows) {
		return targetErr
	}
	if errors.Is(targetErr, pgx.ErrNoRows) {
		var memberCount int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM conversation_members WHERE conversation_id=$1`,
			conversationID).Scan(&memberCount); err != nil {
			return err
		}
		if memberCount >= 1024 {
			return domain.ErrInvalid
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO conversation_members(conversation_id,user_id,role,joined_at)
		VALUES($1,$2,$3,now()) ON CONFLICT(conversation_id,user_id) DO UPDATE SET role=EXCLUDED.role`,
		conversationID, userID, role); err != nil {
		return mapError(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE conversations SET updated_at=now() WHERE id=$1`, conversationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateConversationInvites(ctx context.Context, conversationID, actorID uuid.UUID, phones []string) error {
	if len(phones) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var allowed bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(
		  SELECT 1 FROM conversation_members
		  WHERE conversation_id=$1 AND user_id=$2 AND role IN ('owner','admin')
		)`, conversationID, actorID).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return domain.ErrForbidden
	}
	for _, phone := range phones {
		if _, err := tx.Exec(ctx, `
			INSERT INTO conversation_invites(conversation_id,phone,invited_by)
			VALUES($1,$2,$3)
			ON CONFLICT(conversation_id,phone) DO UPDATE SET
			  invited_by=EXCLUDED.invited_by,invited_at=now(),claimed_by=NULL,claimed_at=NULL`,
			conversationID, phone, actorID); err != nil {
			return mapError(err)
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ClaimConversationInvites(ctx context.Context, userID uuid.UUID, phone string) ([]uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT conversation_id FROM conversation_invites
		WHERE phone=$1 AND claimed_at IS NULL
		FOR UPDATE`, phone)
	if err != nil {
		return nil, err
	}
	var conversationIDs []uuid.UUID
	for rows.Next() {
		var conversationID uuid.UUID
		if err := rows.Scan(&conversationID); err != nil {
			rows.Close()
			return nil, err
		}
		conversationIDs = append(conversationIDs, conversationID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, conversationID := range conversationIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO conversation_members(conversation_id,user_id,role,joined_at)
			VALUES($1,$2,'member',now())
			ON CONFLICT(conversation_id,user_id) DO NOTHING`, conversationID, userID); err != nil {
			return nil, mapError(err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE conversation_invites SET claimed_by=$2,claimed_at=now()
			WHERE conversation_id=$1 AND phone=$3`, conversationID, userID, phone); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE conversations SET updated_at=now() WHERE id=$1`, conversationID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return conversationIDs, nil
}

func (s *Store) RemoveConversationMember(ctx context.Context, conversationID, actorID, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var kind, actorRole string
	err = tx.QueryRow(ctx, `
		SELECT c.kind,m.role FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1 FOR UPDATE OF c`, conversationID, actorID).Scan(&kind, &actorRole)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrForbidden
	}
	if err != nil {
		return err
	}
	if kind != "group" {
		return domain.ErrInvalid
	}
	var targetRole string
	if err := tx.QueryRow(ctx, `
		SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`,
		conversationID, userID).Scan(&targetRole); errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	} else if err != nil {
		return err
	}
	if targetRole == "owner" {
		return domain.ErrForbidden
	}
	if actorID != userID && actorRole != "owner" && actorRole != "admin" {
		return domain.ErrForbidden
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`, conversationID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE conversations SET updated_at=now() WHERE id=$1`, conversationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) TransferConversationOwnership(ctx context.Context, conversationID, actorID, targetID uuid.UUID) error {
	if actorID == targetID {
		return domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var kind, actorRole string
	err = tx.QueryRow(ctx, `
		SELECT c.kind,m.role FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1 FOR UPDATE OF c`, conversationID, actorID).Scan(&kind, &actorRole)
	if errors.Is(err, pgx.ErrNoRows) || actorRole != "owner" {
		return domain.ErrForbidden
	}
	if err != nil {
		return err
	}
	if kind != "group" {
		return domain.ErrInvalid
	}
	var targetRole string
	if err := tx.QueryRow(ctx, `
		SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`,
		conversationID, targetID).Scan(&targetRole); errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrInvalid
	} else if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE conversation_members
		SET role=CASE WHEN user_id=$2 THEN 'admin' ELSE 'owner' END
		WHERE conversation_id=$1 AND user_id IN ($2,$3)`,
		conversationID, actorID, targetID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE conversations SET updated_at=now() WHERE id=$1`, conversationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateMessage(ctx context.Context, p store.CreateMessageParams) (domain.Message, []uuid.UUID, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.Message{}, nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireMember(ctx, tx, p.ConversationID, p.SenderID); err != nil {
		return domain.Message{}, nil, err
	}
	existing, err := scanMessage(tx.QueryRow(ctx, `
		SELECT id,client_message_id,conversation_id,sender_id,sender_device_id,seq,content_type,
		       ciphertext,COALESCE(envelope,'null'::jsonb),reply_to_id,created_at,server_received_at
		FROM messages WHERE conversation_id=$1 AND sender_id=$2 AND client_message_id=$3`,
		p.ConversationID, p.SenderID, p.ClientMessageID))
	if err == nil {
		recipients, memberErr := conversationMemberIDs(ctx, tx, p.ConversationID)
		return existing, recipients, memberErr
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return domain.Message{}, nil, err
	}
	var seq int64
	now := time.Now().UTC()
	if err := tx.QueryRow(ctx, `
		UPDATE conversations SET last_seq=last_seq+1,updated_at=$2 WHERE id=$1 RETURNING last_seq`,
		p.ConversationID, now).Scan(&seq); err != nil {
		return domain.Message{}, nil, mapError(err)
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	message := domain.Message{
		ID: p.ID, ClientMessageID: p.ClientMessageID, ConversationID: p.ConversationID,
		SenderID: p.SenderID, SenderDeviceID: p.SenderDeviceID, Seq: seq,
		ContentType: p.ContentType, Ciphertext: p.Ciphertext, Envelope: p.Envelope,
		ReplyToID: p.ReplyToID, CreatedAt: now, ServerReceivedAt: now,
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO messages(conversation_id,id,client_message_id,sender_id,sender_device_id,seq,
			content_type,ciphertext,envelope,reply_to_id,created_at,server_received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`,
		message.ConversationID, message.ID, message.ClientMessageID, message.SenderID,
		message.SenderDeviceID, message.Seq, message.ContentType, message.Ciphertext,
		nullableJSON(message.Envelope), message.ReplyToID, now)
	if err != nil {
		return domain.Message{}, nil, mapError(err)
	}
	payload, _ := json.Marshal(message)
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES('message.created',$1,$2)`,
		message.ConversationID, payload); err != nil {
		return domain.Message{}, nil, err
	}
	recipients, err := conversationMemberIDs(ctx, tx, p.ConversationID)
	if err != nil {
		return domain.Message{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Message{}, nil, err
	}
	return message, recipients, nil
}

func (s *Store) ListMessages(ctx context.Context, conversationID, userID uuid.UUID, afterSeq int64, limit int) ([]domain.Message, error) {
	if err := s.requireMember(ctx, s.pool, conversationID, userID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,client_message_id,conversation_id,sender_id,sender_device_id,seq,content_type,
		       ciphertext,COALESCE(envelope,'null'::jsonb),reply_to_id,created_at,server_received_at
		FROM messages WHERE conversation_id=$1 AND seq>$2 ORDER BY seq LIMIT $3`,
		conversationID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.Message
	for rows.Next() {
		message, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, message)
	}
	return result, rows.Err()
}

func (s *Store) UpsertReceipt(ctx context.Context, receipt domain.Receipt) (domain.Receipt, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Receipt{}, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireMember(ctx, tx, receipt.ConversationID, receipt.UserID); err != nil {
		return domain.Receipt{}, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO receipts(conversation_id,user_id,delivered_seq,read_seq,updated_at)
		VALUES($1,$2,$3,$4,now())
		ON CONFLICT(conversation_id,user_id) DO UPDATE SET
			delivered_seq=EXCLUDED.delivered_seq,read_seq=EXCLUDED.read_seq,updated_at=now()
		WHERE receipts.delivered_seq<=EXCLUDED.delivered_seq AND receipts.read_seq<=EXCLUDED.read_seq
		RETURNING conversation_id,user_id,delivered_seq,read_seq,updated_at`,
		receipt.ConversationID, receipt.UserID, receipt.DeliveredSeq, receipt.ReadSeq,
	).Scan(&receipt.ConversationID, &receipt.UserID, &receipt.DeliveredSeq, &receipt.ReadSeq, &receipt.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Receipt{}, domain.ErrConflict
	}
	if err != nil {
		return domain.Receipt{}, err
	}
	payload, _ := json.Marshal(receipt)
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES('receipt.updated',$1,$2)`,
		receipt.ConversationID, payload); err != nil {
		return domain.Receipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Receipt{}, err
	}
	return receipt, nil
}

func (s *Store) ListReceipts(ctx context.Context, conversationID, actorID uuid.UUID) ([]domain.Receipt, error) {
	if err := s.requireMember(ctx, s.pool, conversationID, actorID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT conversation_id,user_id,delivered_seq,read_seq,updated_at
		FROM receipts WHERE conversation_id=$1 ORDER BY user_id`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.Receipt
	for rows.Next() {
		var receipt domain.Receipt
		if err := rows.Scan(&receipt.ConversationID, &receipt.UserID, &receipt.DeliveredSeq,
			&receipt.ReadSeq, &receipt.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, receipt)
	}
	return result, rows.Err()
}

func (s *Store) PutEntity(ctx context.Context, entity domain.Entity, expectedVersion *int64) (domain.Entity, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Entity{}, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireMember(ctx, tx, entity.ConversationID, entity.CreatedBy); err != nil {
		return domain.Entity{}, err
	}
	var expected any
	if expectedVersion != nil {
		expected = *expectedVersion
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO entities(conversation_id,kind,id,version,payload,created_by,created_at,updated_at)
		SELECT $1,$2,$3,1,$4,$5,now(),now()
		WHERE $6::bigint IS NULL OR $6=0 OR EXISTS (
			SELECT 1 FROM entities current
			WHERE current.conversation_id=$1 AND current.kind=$2 AND current.id=$3
				AND current.version=$6
		)
		ON CONFLICT(conversation_id,kind,id) DO UPDATE SET
			version=entities.version+1,payload=EXCLUDED.payload,updated_at=now(),deleted_at=NULL
		WHERE $6::bigint IS NULL OR entities.version=$6
		RETURNING conversation_id,kind,id,version,payload,created_by,created_at,updated_at,deleted_at`,
		entity.ConversationID, entity.Kind, entity.ID, entity.Payload, entity.CreatedBy, expected,
	).Scan(&entity.ConversationID, &entity.Kind, &entity.ID, &entity.Version, &entity.Payload,
		&entity.CreatedBy, &entity.CreatedAt, &entity.UpdatedAt, &entity.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Entity{}, domain.ErrConflict
	}
	if err != nil {
		return domain.Entity{}, mapError(err)
	}
	payload, _ := json.Marshal(entity)
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES('entity.updated',$1,$2)`,
		entity.ConversationID, payload); err != nil {
		return domain.Entity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Entity{}, err
	}
	return entity, nil
}

func (s *Store) ListEntities(ctx context.Context, conversationID, userID uuid.UUID, kind string, since time.Time, limit int) ([]domain.Entity, error) {
	if err := s.requireMember(ctx, s.pool, conversationID, userID); err != nil {
		return nil, err
	}
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	rows, err := s.pool.Query(ctx, `
		SELECT conversation_id,kind,id,version,payload,created_by,created_at,updated_at,deleted_at
		FROM entities WHERE conversation_id=$1 AND kind=$2 AND updated_at>$3
		ORDER BY updated_at,id LIMIT $4`, conversationID, kind, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.Entity
	for rows.Next() {
		var entity domain.Entity
		if err := rows.Scan(&entity.ConversationID, &entity.Kind, &entity.ID, &entity.Version,
			&entity.Payload, &entity.CreatedBy, &entity.CreatedAt, &entity.UpdatedAt,
			&entity.DeletedAt); err != nil {
			return nil, err
		}
		result = append(result, entity)
	}
	return result, rows.Err()
}

func (s *Store) DeleteEntity(ctx context.Context, conversationID, actorID uuid.UUID, kind string, id uuid.UUID, expectedVersion *int64) (domain.Entity, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Entity{}, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireMember(ctx, tx, conversationID, actorID); err != nil {
		return domain.Entity{}, err
	}
	var currentVersion int64
	err = tx.QueryRow(ctx, `
		SELECT version FROM entities
		WHERE conversation_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL
		FOR UPDATE`, conversationID, kind, id).Scan(&currentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Entity{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Entity{}, err
	}
	if expectedVersion != nil && currentVersion != *expectedVersion {
		return domain.Entity{}, domain.ErrConflict
	}
	var entity domain.Entity
	err = tx.QueryRow(ctx, `
		UPDATE entities SET deleted_at=now(),updated_at=now(),version=version+1
		WHERE conversation_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL
		RETURNING conversation_id,kind,id,version,payload,created_by,created_at,updated_at,deleted_at`,
		conversationID, kind, id,
	).Scan(&entity.ConversationID, &entity.Kind, &entity.ID, &entity.Version, &entity.Payload,
		&entity.CreatedBy, &entity.CreatedAt, &entity.UpdatedAt, &entity.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Entity{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Entity{}, err
	}
	payload, _ := json.Marshal(entity)
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES('entity.deleted',$1,$2)`,
		conversationID, payload); err != nil {
		return domain.Entity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Entity{}, err
	}
	return entity, nil
}

func (s *Store) CreateMedia(ctx context.Context, media domain.MediaObject) (domain.MediaObject, error) {
	if err := s.requireMember(ctx, s.pool, media.ConversationID, media.OwnerID); err != nil {
		return domain.MediaObject{}, err
	}
	now := time.Now().UTC()
	media.CreatedAt, media.UpdatedAt, media.Status = now, now, "pending"
	err := s.pool.QueryRow(ctx, `
		INSERT INTO media_objects(id,owner_id,conversation_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$8)
		RETURNING id,owner_id,conversation_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,created_at,updated_at`,
		media.ID, media.OwnerID, media.ConversationID, media.ObjectKey, media.ContentType,
		media.ByteSize, media.CiphertextSHA256, now,
	).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
		&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.CreatedAt, &media.UpdatedAt)
	return media, mapError(err)
}

func (s *Store) Media(ctx context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	var media domain.MediaObject
	err := s.pool.QueryRow(ctx, `
		SELECT o.id,o.owner_id,o.conversation_id,o.object_key,o.content_type,o.byte_size,
			o.ciphertext_sha256,o.status,o.created_at,o.updated_at
		FROM media_objects o
		JOIN conversation_members m ON m.conversation_id=o.conversation_id
		WHERE o.id=$1 AND m.user_id=$2`, id, actorID,
	).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
		&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.CreatedAt, &media.UpdatedAt)
	return media, mapError(err)
}

func (s *Store) MarkMediaReady(ctx context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	var media domain.MediaObject
	err := s.pool.QueryRow(ctx, `
		UPDATE media_objects SET status='ready',updated_at=now()
		WHERE id=$1 AND owner_id=$2 AND status='pending'
		RETURNING id,owner_id,conversation_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,created_at,updated_at`, id, actorID,
	).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
		&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.CreatedAt, &media.UpdatedAt)
	return media, mapError(err)
}

func (s *Store) LockOutboxBatch(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	rows, err := s.pool.Query(ctx, `
		WITH selected AS (
			SELECT id FROM outbox_events
			WHERE published_at IS NULL AND (locked_until IS NULL OR locked_until<now())
			ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1
		)
		UPDATE outbox_events o SET locked_until=now()+interval '30 seconds',attempts=attempts+1
		FROM selected WHERE o.id=selected.id
		RETURNING o.id,o.topic,o.aggregate_id,o.payload,o.created_at`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.OutboxEvent
	for rows.Next() {
		var event domain.OutboxEvent
		if err := rows.Scan(&event.ID, &event.Topic, &event.AggregateID, &event.Payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) MarkOutboxPublished(ctx context.Context, ids []int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_events SET published_at=now(),locked_until=NULL WHERE id=ANY($1)`, ids)
	return err
}

type rowScanner interface {
	Scan(...any) error
}

type memberQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func scanUser(row rowScanner) (domain.User, error) {
	var user domain.User
	err := row.Scan(&user.ID, &user.Email, &user.Phone, &user.DisplayName, &user.AvatarURL,
		&user.Profile, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	return user, mapError(err)
}

func scanDevice(row rowScanner) (domain.Device, error) {
	var device domain.Device
	err := row.Scan(&device.ID, &device.UserID, &device.Name, &device.Platform, &device.PushToken,
		&device.IdentityKey, &device.SignedPreKey, &device.LastSeenAt, &device.CreatedAt)
	return device, mapError(err)
}

func scanMessage(row rowScanner) (domain.Message, error) {
	var message domain.Message
	err := row.Scan(&message.ID, &message.ClientMessageID, &message.ConversationID, &message.SenderID,
		&message.SenderDeviceID, &message.Seq, &message.ContentType, &message.Ciphertext,
		&message.Envelope, &message.ReplyToID, &message.CreatedAt, &message.ServerReceivedAt)
	return message, mapError(err)
}

func (s *Store) requireMember(ctx context.Context, query memberQuerier, conversationID, userID uuid.UUID) error {
	var exists bool
	if err := query.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2)`,
		conversationID, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return domain.ErrForbidden
	}
	return nil
}

func (s *Store) requireAdmin(ctx context.Context, conversationID, userID uuid.UUID) error {
	var role string
	err := s.pool.QueryRow(ctx, `
		SELECT role FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`,
		conversationID, userID).Scan(&role)
	if err != nil {
		return mapError(err)
	}
	if role != "owner" && role != "admin" {
		return domain.ErrForbidden
	}
	return nil
}

func conversationMemberIDs(ctx context.Context, query interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, conversationID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := query.Query(ctx, `SELECT user_id FROM conversation_members WHERE conversation_id=$1`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return domain.ErrConflict
		case "23503":
			return domain.ErrInvalid
		}
	}
	return err
}

func nullableString(value string) string { return strings.TrimSpace(value) }

func nullableJSON(value json.RawMessage) any {
	if len(value) == 0 || string(value) == "null" {
		return nil
	}
	return value
}

func jsonOrObject(value json.RawMessage) json.RawMessage {
	if len(value) == 0 || string(value) == "null" {
		return json.RawMessage(`{}`)
	}
	return value
}

func uniqueUUIDs(values []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(values))
	result := make([]uuid.UUID, 0, len(values))
	for _, value := range values {
		if value == uuid.Nil {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func conversationDirectKey(values []uuid.UUID) string {
	unique := uniqueUUIDs(values)
	sort.Slice(unique, func(i, j int) bool { return unique[i].String() < unique[j].String() })
	joined := make([]string, 0, len(unique))
	for _, value := range unique {
		joined = append(joined, value.String())
	}
	sum := sha256.Sum256([]byte(strings.Join(joined, ":")))
	return hex.EncodeToString(sum[:])
}

func equalTokenHash(first, second []byte) bool {
	return len(first) == len(second) && len(first) > 0 &&
		subtle.ConstantTimeCompare(first, second) == 1
}
