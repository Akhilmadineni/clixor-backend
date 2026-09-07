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
	"github.com/Akhilmadineni/clixor-backend/internal/mediakey"
	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

// accountDeliveryBarrierKey is a process-independent transaction advisory
// lock used as an RW barrier between external delivery callbacks and account
// erasure. Delivery leases take the shared form before touching transport
// rows. Account erasure takes the exclusive form before touching any user,
// conversation, outbox, or push row. This fixed ordering prevents a callback
// that uses another pooled Store method from forming a row-lock cycle with an
// erasure transaction.
const accountDeliveryBarrierKey int64 = 0x436c69786f724552

func lockAccountDeliveryBarrierShared(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock_shared($1)`, accountDeliveryBarrierKey)
	return err
}

func lockAccountDeliveryBarrierExclusive(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock($1)`, accountDeliveryBarrierKey)
	return err
}

func Open(ctx context.Context, databaseURL string, autoMigrate bool) (*Store, error) {
	return OpenWithPool(ctx, databaseURL, autoMigrate, 35, 5)
}

func OpenWithPool(
	ctx context.Context,
	databaseURL string,
	autoMigrate bool,
	maxConns int,
	minConns int,
) (*Store, error) {
	if maxConns < 1 || minConns < 0 || minConns > maxConns {
		return nil, fmt.Errorf("invalid PostgreSQL pool limits: min=%d max=%d", minConns, maxConns)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	// Two production API replicas share a PostgreSQL server capped at 100
	// connections. Keep 30 connections available for migrations, backups,
	// monitoring, and operator access instead of allowing the API pools to
	// consume the entire server limit.
	config.MaxConns = int32(maxConns)
	config.MinConns = int32(minConns)
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
		FROM users WHERE id=$1 AND deleted_at IS NULL`, id))
}

func (s *Store) UserByEmail(ctx context.Context, email string) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users WHERE lower(email)=lower($1) AND deleted_at IS NULL`, strings.TrimSpace(email)))
}

func (s *Store) UserByPhone(ctx context.Context, phone string) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users WHERE phone=$1 AND deleted_at IS NULL`, phone))
}

func (s *Store) UsersByPhones(ctx context.Context, phones []string) ([]domain.User, error) {
	if len(phones) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users WHERE phone = ANY($1) AND deleted_at IS NULL ORDER BY phone`, phones)
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

func (s *Store) UsersByUsernames(ctx context.Context, usernames []string) ([]domain.User, error) {
	normalized := normalizeUsernameList(usernames)
	if len(normalized) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users
		WHERE deleted_at IS NULL
		  AND lower(regexp_replace(COALESCE(profile->>'username', ''), '^@+', '')) = ANY($1)
		ORDER BY lower(regexp_replace(COALESCE(profile->>'username', ''), '^@+', ''))`, normalized)
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

func (s *Store) SearchUsersByUsername(ctx context.Context, query string, limit int) ([]domain.User, error) {
	q := normalizeUsername(query)
	if q == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	// LIKE metacharacters are valid persisted legacy username characters. Escape
	// them so PostgreSQL has the same literal-prefix semantics as memory.
	q = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
	rows, err := s.pool.Query(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at
		FROM users
		WHERE deleted_at IS NULL
		  AND lower(regexp_replace(COALESCE(profile->>'username', ''), '^@+', '')) LIKE $1 || '%' ESCAPE '\'
		ORDER BY lower(regexp_replace(COALESCE(profile->>'username', ''), '^@+', ''))
		LIMIT $2`, q, limit)
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

func (s *Store) UpdateUserProfile(ctx context.Context, id uuid.UUID, profile json.RawMessage) (domain.User, error) {
	var patch map[string]any
	if err := json.Unmarshal(profile, &patch); err != nil || patch == nil {
		return domain.User{}, domain.ErrInvalid
	}
	if rawUsername, present := patch["username"]; present && rawUsername != nil {
		username, ok := rawUsername.(string)
		if !ok {
			return domain.User{}, domain.ErrInvalid
		}
		if strings.TrimSpace(username) != "" {
			normalized, ok := validateUsername(username)
			if !ok {
				return domain.User{}, domain.ErrInvalid
			}
			patch["username"] = "@" + normalized
		}
	}
	profile, err := json.Marshal(patch)
	if err != nil {
		return domain.User{}, err
	}
	displayName, _ := patch["display_name"].(string)
	return scanUser(s.pool.QueryRow(ctx, `
			UPDATE users SET
				profile=COALESCE(profile,'{}'::jsonb) || $2::jsonb,
				display_name=COALESCE(NULLIF($3,''),display_name),
				updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL
			RETURNING id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at`,
		id, profile, displayName))
}

func (s *Store) UserByExternalIdentity(ctx context.Context, provider, subject string) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT u.id,COALESCE(u.email,''),COALESCE(u.phone,''),u.display_name,u.avatar_url,
		       u.profile,u.password_hash,u.created_at,u.updated_at
		FROM users u JOIN external_identities i ON i.user_id=u.id
		WHERE i.provider=$1 AND i.subject=$2 AND u.deleted_at IS NULL`, provider, subject))
}

func (s *Store) LinkExternalIdentity(ctx context.Context, provider, subject string, userID uuid.UUID, email string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize identity material with deletion. A bare INSERT .. SELECT can
	// retain its pre-delete MVCC candidate while waiting on the foreign-key row
	// and recreate PII after the deletion transaction has cleaned this table.
	if err := lockLiveUser(ctx, tx, userID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO external_identities(provider,subject,user_id,email)
		VALUES($1,$2,$3,NULLIF($4,''))
		ON CONFLICT(provider,subject) DO UPDATE SET
		  email=COALESCE(EXCLUDED.email,external_identities.email)
		WHERE external_identities.user_id=EXCLUDED.user_id`,
		provider, subject, userID, email)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrConflict
	}
	return tx.Commit(ctx)
}

// UpdateUserPhone attaches a verified phone number to an existing account (as opposed to
// CreateUser, which sets phone at signup). The partial unique index on phone causes this to
// return domain.ErrConflict if the number is already linked to a different user.
func (s *Store) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) (domain.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET phone=$2, updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL
		RETURNING id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,password_hash,created_at,updated_at`,
		id, phone))
}

func (s *Store) UpsertDevice(ctx context.Context, device domain.Device) (domain.Device, error) {
	device.PushToken = strings.ToLower(strings.TrimSpace(device.PushToken))
	if device.ID == uuid.Nil {
		device.ID = uuid.New()
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		stored, err := s.upsertDeviceOnce(ctx, device)
		if !isAccountDeletionRetryable(err) || attempt == maxAttempts-1 {
			return stored, err
		}
		if err := ctx.Err(); err != nil {
			return domain.Device{}, err
		}
	}
	return domain.Device{}, nil
}

func (s *Store) upsertDeviceOnce(ctx context.Context, device domain.Device) (domain.Device, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.Device{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockLiveUser(ctx, tx, device.UserID); err != nil {
		return domain.Device{}, err
	}
	if device.PushToken != "" {
		// Serialize ownership transfers for this exact token, then clear its old
		// owner in the same transaction as the authenticated device upsert. A
		// cross-account device-ID conflict rolls the entire transfer back.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, device.PushToken); err != nil {
			return domain.Device{}, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE devices SET push_token=''
			WHERE push_token=$1 AND id<>$2`, device.PushToken, device.ID); err != nil {
			return domain.Device{}, err
		}
	}
	err = tx.QueryRow(ctx, `
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
	if err != nil {
		return domain.Device{}, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Device{}, mapError(err)
	}
	return device, nil
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT user_id FROM devices WHERE id=$1`, deviceID).Scan(&userID); err != nil {
		return mapError(err)
	}
	if err := lockLiveUser(ctx, tx, userID); err != nil {
		return err
	}
	var lockedDeviceID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM devices WHERE id=$1 AND user_id=$2 FOR UPDATE`, deviceID, userID,
	).Scan(&lockedDeviceID); err != nil {
		return mapError(err)
	}
	batch := &pgx.Batch{}
	for _, key := range keys {
		batch.Queue(`
			INSERT INTO one_time_prekeys(device_id,key_id,public_key)
			VALUES($1,$2,$3) ON CONFLICT(device_id,key_id) DO NOTHING`,
			deviceID, key.KeyID, key.PublicKey)
	}
	results := tx.SendBatch(ctx, batch)
	defer results.Close()
	for range keys {
		if _, err := results.Exec(); err != nil {
			return mapError(err)
		}
	}
	if err := results.Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ClaimPreKeys(ctx context.Context, targetUserID uuid.UUID) ([]domain.PreKeyBundle, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := lockLiveUser(ctx, tx, targetUserID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id,user_id,name,platform,push_token,identity_key,COALESCE(signed_prekey,'null'::jsonb),last_seen_at,created_at
		FROM devices
		WHERE user_id=$1 AND identity_key<>''
			AND signed_prekey IS NOT NULL AND signed_prekey<>'null'::jsonb
		ORDER BY created_at`, targetUserID)
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
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockLiveUser(ctx, tx, session.UserID); err != nil {
		return domain.ErrUnauthenticated
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO sessions(id,user_id,device_id,refresh_token_hash,expires_at,created_at)
		SELECT $1,$2,$3,$4,$5,$6 FROM devices d
		WHERE d.user_id=$2 AND d.id=$3`,
		session.ID, session.UserID, session.DeviceID, session.RefreshTokenHash,
		session.ExpiresAt, session.CreatedAt)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() != 1 {
		return domain.ErrUnauthenticated
	}
	return tx.Commit(ctx)
}

func (s *Store) IssueSession(
	ctx context.Context,
	p store.SessionIssueParams,
) (domain.User, domain.Device, error) {
	if p.UserID == uuid.Nil || p.Device.ID == uuid.Nil || p.Device.UserID != p.UserID ||
		p.Session.ID == uuid.Nil || p.Session.UserID != p.UserID ||
		p.Session.DeviceID != p.Device.ID || len(p.Session.RefreshTokenHash) == 0 {
		return domain.User{}, domain.Device{}, domain.ErrInvalid
	}
	p.Device.PushToken = strings.ToLower(strings.TrimSpace(p.Device.PushToken))
	if p.Device.CreatedAt.IsZero() {
		p.Device.CreatedAt = time.Now().UTC()
	}
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		user, device, err := s.issueSessionOnce(ctx, p)
		if !isAccountDeletionRetryable(err) || attempt == maxAttempts-1 {
			return user, device, err
		}
		if err := ctx.Err(); err != nil {
			return domain.User{}, domain.Device{}, err
		}
	}
	return domain.User{}, domain.Device{}, nil
}

func (s *Store) issueSessionOnce(
	ctx context.Context,
	p store.SessionIssueParams,
) (domain.User, domain.Device, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.User{}, domain.Device{}, err
	}
	defer tx.Rollback(ctx)
	user, err := scanUser(tx.QueryRow(ctx, `
		SELECT id,COALESCE(email,''),COALESCE(phone,''),display_name,avatar_url,profile,
		       password_hash,created_at,updated_at
		FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, p.UserID))
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, domain.ErrNotFound) {
		return domain.User{}, domain.Device{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return domain.User{}, domain.Device{}, err
	}
	if p.RequirePasswordHashMatch && subtle.ConstantTimeCompare(
		[]byte(user.PasswordHash), []byte(p.ExpectedPasswordHash),
	) != 1 {
		return domain.User{}, domain.Device{}, domain.ErrUnauthenticated
	}
	device := p.Device
	if device.PushToken != "" {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, device.PushToken); err != nil {
			return domain.User{}, domain.Device{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET push_token='' WHERE push_token=$1 AND id<>$2`,
			device.PushToken, device.ID); err != nil {
			return domain.User{}, domain.Device{}, err
		}
	}
	err = tx.QueryRow(ctx, `
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
		return domain.User{}, domain.Device{}, domain.ErrConflict
	}
	if err != nil {
		return domain.User{}, domain.Device{}, mapError(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sessions(id,user_id,device_id,refresh_token_hash,expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6)`, p.Session.ID, p.Session.UserID, p.Session.DeviceID,
		p.Session.RefreshTokenHash, p.Session.ExpiresAt, p.Session.CreatedAt); err != nil {
		return domain.User{}, domain.Device{}, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, domain.Device{}, mapError(err)
	}
	return user, device, nil
}

func (s *Store) RotateSession(ctx context.Context, id uuid.UUID, oldHash, newHash []byte, expiresAt time.Time) (domain.Session, error) {
	var session domain.Session
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Session{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		SELECT s.id,s.user_id,s.device_id,s.refresh_token_hash,s.previous_refresh_token_hash,
		       s.expires_at,s.revoked_at,s.created_at
		FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.id=$1 AND u.deleted_at IS NULL FOR UPDATE OF s,u`, id,
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
			SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id
			WHERE s.id=$1 AND s.user_id=$2 AND s.device_id=$3
			  AND s.revoked_at IS NULL AND s.expires_at>now() AND u.deleted_at IS NULL
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
	members := uniqueUUIDs(append([]uuid.UUID{p.CreatedBy}, p.MemberIDs...))
	sort.Slice(members, func(i, j int) bool { return members[i].String() < members[j].String() })
	for _, userID := range members {
		if err := lockLiveUser(ctx, tx, userID); err != nil {
			return domain.Conversation{}, err
		}
	}
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
	if conversation.Kind == "group" {
		conversation.Metadata, err = projectConversationMetadata(
			ctx, tx, conversation.ID, conversation.Metadata,
		)
		if err != nil {
			return domain.Conversation{}, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE conversations SET metadata=$2 WHERE id=$1`,
			conversation.ID, conversation.Metadata); err != nil {
			return domain.Conversation{}, err
		}
	} else {
		members, memberErr := listConversationMembers(ctx, tx, conversation.ID)
		if memberErr != nil {
			return domain.Conversation{}, memberErr
		}
		if _, err := ensureConversationMemberLocalIDs(
			ctx, tx, conversation.ID, conversation.Metadata, members,
		); err != nil {
			return domain.Conversation{}, err
		}
	}
	payload, _ := json.Marshal(conversation)
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES('conversation.created',$1,$2)`,
		conversation.ID, payload); err != nil {
		return domain.Conversation{}, err
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
		FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1`, id, userID,
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.Conversation{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return domain.Conversation{}, err
	}
	var conversation domain.Conversation
	var actorRole string
	err = tx.QueryRow(ctx, `
		SELECT c.id,c.kind,c.title,c.avatar_url,c.metadata,c.created_by,c.last_seq,
		       c.created_at,c.updated_at,m.role
		FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1
		FOR UPDATE OF c`, conversationID, actorID,
	).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
		&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
		&conversation.CreatedAt, &conversation.UpdatedAt, &actorRole)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && actorRole != "owner" && actorRole != "admin") {
		return domain.Conversation{}, domain.ErrForbidden
	}
	if err != nil {
		return domain.Conversation{}, err
	}
	if p.Title != nil {
		conversation.Title = *p.Title
	}
	if p.AvatarURL != nil {
		conversation.AvatarURL = *p.AvatarURL
	}
	if p.Metadata != nil {
		conversation.Metadata = *p.Metadata
	}
	if conversation.Kind == "group" {
		conversation.Metadata, err = projectConversationMetadata(
			ctx, tx, conversationID, conversation.Metadata,
		)
		if err != nil {
			return domain.Conversation{}, err
		}
	}
	err = tx.QueryRow(ctx, `
		UPDATE conversations SET title=$2,avatar_url=$3,metadata=$4,updated_at=now()
		WHERE id=$1
		RETURNING id,kind,title,avatar_url,metadata,created_by,last_seq,created_at,updated_at`,
		conversationID, conversation.Title, conversation.AvatarURL, conversation.Metadata,
	).Scan(&conversation.ID, &conversation.Kind, &conversation.Title, &conversation.AvatarURL,
		&conversation.Metadata, &conversation.CreatedBy, &conversation.LastSeq,
		&conversation.CreatedAt, &conversation.UpdatedAt)
	if err != nil {
		return domain.Conversation{}, mapError(err)
	}
	payload, _ := json.Marshal(conversation)
	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_events(topic,aggregate_id,payload)
		VALUES('conversation.updated',$1,$2)`, conversation.ID, payload); err != nil {
		return domain.Conversation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Conversation{}, err
	}
	return conversation, nil
}

func (s *Store) DeleteConversation(ctx context.Context, conversationID, actorID uuid.UUID) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return err
	}
	if err := lockMediaQuota(ctx, tx, "conversation", conversationID); err != nil {
		return err
	}
	var lockedConversationID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT c.id FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id
		WHERE c.id=$1 AND c.created_by=$2 AND m.user_id=$2 AND m.role='owner'
		FOR UPDATE OF c,m`, conversationID, actorID).Scan(&lockedConversationID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrForbidden
		}
		return err
	}
	rows, err := tx.Query(ctx, `
		SELECT object_key,upload_valid_until FROM media_objects
		WHERE conversation_id=$1
		ORDER BY object_key FOR UPDATE`, conversationID)
	if err != nil {
		return err
	}
	var objectKeys []string
	deleteNotBefore := mediaDeleteNotBefore(time.Time{})
	for rows.Next() {
		var objectKey string
		var uploadValidUntil time.Time
		if err := rows.Scan(&objectKey, &uploadValidUntil); err != nil {
			rows.Close()
			return err
		}
		objectKeys = append(objectKeys, objectKey)
		if candidate := mediaDeleteNotBefore(uploadValidUntil); candidate.After(deleteNotBefore) {
			deleteNotBefore = candidate
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	// Realtime events for a deleted conversation can no longer be translated.
	// Remove only unpublished transport state before inserting the durable
	// object-deletion work in this same transaction.
	if _, err := tx.Exec(ctx, `
		DELETE FROM outbox_events WHERE aggregate_id=$1 AND published_at IS NULL`,
		conversationID); err != nil {
		return err
	}
	if len(objectKeys) > 0 {
		for start := 0; start < len(objectKeys); start += store.MediaDeleteBatchSize {
			end := min(start+store.MediaDeleteBatchSize, len(objectKeys))
			if err := enqueueMediaDeletesAt(
				ctx, tx, conversationID, objectKeys[start:end], deleteNotBefore,
			); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM conversations WHERE id=$1`, conversationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListConversationMembers(ctx context.Context, conversationID, actorID uuid.UUID) ([]domain.ConversationMember, error) {
	if err := s.requireMember(ctx, s.pool, conversationID, actorID); err != nil {
		return nil, err
	}
	return listConversationMembers(ctx, s.pool, conversationID)
}

func listConversationMembers(ctx context.Context, query interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, conversationID uuid.UUID) ([]domain.ConversationMember, error) {
	rows, err := query.Query(ctx, `
		SELECT m.conversation_id,m.user_id,m.role,m.joined_at,m.muted_until,
		       u.display_name,u.avatar_url,u.profile
		FROM conversation_members m
		JOIN users u ON u.id=m.user_id
		WHERE m.conversation_id=$1
		ORDER BY m.joined_at,m.user_id`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.ConversationMember
	for rows.Next() {
		var member domain.ConversationMember
		var user domain.User
		if err := rows.Scan(
			&member.ConversationID, &member.UserID, &member.Role, &member.JoinedAt,
			&member.MutedUntil, &user.DisplayName, &user.AvatarURL, &user.Profile,
		); err != nil {
			return nil, err
		}
		result = append(result, store.ConversationMemberWithPublicIdentity(member, user))
	}
	return result, rows.Err()
}

func projectConversationMetadata(
	ctx context.Context,
	query interface {
		Query(context.Context, string, ...any) (pgx.Rows, error)
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	conversationID uuid.UUID,
	metadata json.RawMessage,
) (json.RawMessage, error) {
	members, err := listConversationMembers(ctx, query, conversationID)
	if err != nil {
		return nil, err
	}
	localIDs, err := ensureConversationMemberLocalIDs(ctx, query, conversationID, metadata, members)
	if err != nil {
		return nil, err
	}
	rows, err := query.Query(ctx, `
		SELECT user_id,local_id FROM conversation_member_tombstones
		WHERE conversation_id=$1 ORDER BY user_id`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tombstones []store.ConversationMemberTombstone
	for rows.Next() {
		var tombstone store.ConversationMemberTombstone
		if err := rows.Scan(&tombstone.UserID, &tombstone.LocalID); err != nil {
			return nil, err
		}
		tombstones = append(tombstones, tombstone)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return store.ProjectConversationMembersWithLocalIDs(metadata, members, localIDs, tombstones...)
}

func ensureConversationMemberLocalIDs(
	ctx context.Context,
	query interface {
		Query(context.Context, string, ...any) (pgx.Rows, error)
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	conversationID uuid.UUID,
	metadata json.RawMessage,
	members []domain.ConversationMember,
) ([]store.ConversationMemberLocalID, error) {
	load := func() ([]store.ConversationMemberLocalID, error) {
		rows, err := query.Query(ctx, `
			SELECT user_id,local_id FROM conversation_member_local_ids
			WHERE conversation_id=$1 ORDER BY user_id`, conversationID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var result []store.ConversationMemberLocalID
		for rows.Next() {
			var mapping store.ConversationMemberLocalID
			if err := rows.Scan(&mapping.UserID, &mapping.LocalID); err != nil {
				return nil, err
			}
			result = append(result, mapping)
		}
		return result, rows.Err()
	}
	existing, err := load()
	if err != nil {
		return nil, err
	}
	derived := store.DeriveConversationMemberLocalIDs(metadata, members, existing)
	for _, mapping := range derived {
		if _, err := query.Exec(ctx, `
			INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)
			VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
			conversationID, mapping.UserID, mapping.LocalID); err != nil {
			return nil, err
		}
	}
	all, err := load()
	if err != nil {
		return nil, err
	}
	if err := store.ValidateConversationMemberLocalIDNamespace(members, all); err != nil {
		return nil, err
	}
	wanted := make(map[uuid.UUID]struct{}, len(members))
	for _, member := range members {
		wanted[member.UserID] = struct{}{}
	}
	filtered := make([]store.ConversationMemberLocalID, 0, len(members))
	for _, mapping := range all {
		if _, active := wanted[mapping.UserID]; active {
			filtered = append(filtered, mapping)
		}
	}
	if len(filtered) != len(wanted) {
		return nil, fmt.Errorf("conversation member local-ID mapping incomplete")
	}
	return filtered, nil
}

// validateConversationMemberAdmission runs while the conversation row is
// locked. It protects both collision directions before membership mutation:
// the joining backend UUID cannot be another identity's reserved local UUID,
// and the joiner's immutable local UUID cannot already be an active backend
// identity. Historical mappings remain reserved after removal.
func validateConversationMemberAdmission(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, conversationID, userID uuid.UUID) error {
	var collision bool
	err := query.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM conversation_member_local_ids reserved
			WHERE reserved.conversation_id=$1
			  AND reserved.local_id=$2
			  AND reserved.user_id<>$2
			UNION ALL
			SELECT 1
			FROM conversation_member_local_ids own
			JOIN conversation_members active
			  ON active.conversation_id=own.conversation_id
			 AND active.user_id=own.local_id
			WHERE own.conversation_id=$1
			  AND own.user_id=$2
			  AND active.user_id<>own.user_id
		)`, conversationID, userID).Scan(&collision)
	if err != nil {
		return err
	}
	if collision {
		return domain.ErrConflict
	}
	return nil
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
	if err := lockLiveUsers(ctx, tx, actorID, userID); err != nil {
		return err
	}
	var kind, actorRole string
	var metadata json.RawMessage
	err = tx.QueryRow(ctx, `
		SELECT c.kind,m.role,c.metadata FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1 FOR UPDATE OF c`, conversationID, actorID).Scan(&kind, &actorRole, &metadata)
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
	if err := validateConversationMemberAdmission(ctx, tx, conversationID, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO conversation_members(conversation_id,user_id,role,joined_at)
		VALUES($1,$2,$3,now()) ON CONFLICT(conversation_id,user_id) DO UPDATE SET role=EXCLUDED.role`,
		conversationID, userID, role); err != nil {
		return mapError(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM conversation_member_tombstones WHERE conversation_id=$1 AND user_id=$2`, conversationID, userID); err != nil {
		return err
	}
	metadata, err = projectConversationMetadata(ctx, tx, conversationID, metadata)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE conversations SET metadata=$2,updated_at=now() WHERE id=$1`,
		conversationID, metadata); err != nil {
		return err
	}
	if errors.Is(targetErr, pgx.ErrNoRows) {
		payload, _ := json.Marshal(domain.ConversationMemberAdded{
			ConversationID: conversationID, ActorID: actorID, UserID: userID,
		})
		if _, err := tx.Exec(ctx, `
			INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES('conversation.member_added',$1,$2)`,
			conversationID, payload); err != nil {
			return err
		}
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
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return err
	}
	if err := lockConversation(ctx, tx, conversationID); err != nil {
		return err
	}
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
	if err := lockLiveUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT conversation_id FROM conversation_invites
		WHERE phone=$1 AND claimed_at IS NULL
		ORDER BY conversation_id`, phone)
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
		var kind string
		var metadata json.RawMessage
		if err := tx.QueryRow(ctx, `
			SELECT kind,metadata FROM conversations WHERE id=$1 FOR UPDATE`,
			conversationID).Scan(&kind, &metadata); err != nil {
			return nil, mapError(err)
		}
		if kind != "group" {
			return nil, domain.ErrInvalid
		}
		var inviteStillPending bool
		if err := tx.QueryRow(ctx, `
			SELECT true FROM conversation_invites
			WHERE conversation_id=$1 AND phone=$2 AND claimed_at IS NULL
			FOR UPDATE`, conversationID, phone).Scan(&inviteStillPending); errors.Is(err, pgx.ErrNoRows) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := validateConversationMemberAdmission(ctx, tx, conversationID, userID); err != nil {
			return nil, err
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO conversation_members(conversation_id,user_id,role,joined_at)
			VALUES($1,$2,'member',now())
			ON CONFLICT(conversation_id,user_id) DO NOTHING`, conversationID, userID)
		if err != nil {
			return nil, mapError(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM conversation_member_tombstones WHERE conversation_id=$1 AND user_id=$2`, conversationID, userID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE conversation_invites SET claimed_by=$2,claimed_at=now()
			WHERE conversation_id=$1 AND phone=$3`, conversationID, userID, phone); err != nil {
			return nil, err
		}
		metadata, err = projectConversationMetadata(ctx, tx, conversationID, metadata)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE conversations SET metadata=$2,updated_at=now() WHERE id=$1`,
			conversationID, metadata); err != nil {
			return nil, err
		}
		if tag.RowsAffected() > 0 {
			payload, _ := json.Marshal(domain.ConversationMemberAdded{
				ConversationID: conversationID, ActorID: userID, UserID: userID,
			})
			if _, err := tx.Exec(ctx, `
				INSERT INTO outbox_events(topic,aggregate_id,payload)
				VALUES('conversation.member_added',$1,$2)`, conversationID, payload); err != nil {
				return nil, err
			}
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
	if err := lockLiveUsers(ctx, tx, actorID, userID); err != nil {
		return err
	}
	var kind, actorRole string
	var metadata json.RawMessage
	err = tx.QueryRow(ctx, `
		SELECT c.kind,m.role,c.metadata FROM conversations c
		JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=$2
		WHERE c.id=$1 FOR UPDATE OF c`, conversationID, actorID).Scan(&kind, &actorRole, &metadata)
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
	var tombstone store.ConversationMemberTombstone
	tombstone.UserID = userID
	if err := tx.QueryRow(ctx, `
		SELECT local_id FROM conversation_member_local_ids
		WHERE conversation_id=$1 AND user_id=$2`, conversationID, userID).Scan(&tombstone.LocalID); err != nil {
		return mapError(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO conversation_member_tombstones(conversation_id,user_id,local_id)
		VALUES($1,$2,$3) ON CONFLICT(conversation_id,user_id) DO NOTHING`,
		conversationID, userID, tombstone.LocalID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM conversation_members WHERE conversation_id=$1 AND user_id=$2`, conversationID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	metadata, err = projectConversationMetadata(ctx, tx, conversationID, metadata)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE conversations SET metadata=$2,updated_at=now() WHERE id=$1`,
		conversationID, metadata); err != nil {
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
	if err := lockLiveUsers(ctx, tx, actorID, targetID); err != nil {
		return err
	}
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
	demoted, err := tx.Exec(ctx, `
		UPDATE conversation_members SET role='admin'
		WHERE conversation_id=$1 AND user_id=$2 AND role='owner'`,
		conversationID, actorID)
	if err != nil {
		return err
	}
	if demoted.RowsAffected() != 1 {
		return domain.ErrConflict
	}
	promoted, err := tx.Exec(ctx, `
		UPDATE conversation_members SET role='owner'
		WHERE conversation_id=$1 AND user_id=$2 AND role=$3`,
		conversationID, targetID, targetRole)
	if err != nil {
		return err
	}
	if promoted.RowsAffected() != 1 {
		return domain.ErrConflict
	}
	// created_by is the conversation authority pointer used by deletion. Keep it
	// synchronized with the sole owner so an ownership transfer cannot leave a
	// group with no principal authorized to delete it.
	if _, err := tx.Exec(ctx, `
		UPDATE conversations SET created_by=$2,updated_at=now() WHERE id=$1`,
		conversationID, targetID); err != nil {
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
	if err := lockLiveUser(ctx, tx, p.SenderID); err != nil {
		return domain.Message{}, nil, err
	}
	if err := lockConversation(ctx, tx, p.ConversationID); err != nil {
		return domain.Message{}, nil, err
	}
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

func (s *Store) ListMessages(ctx context.Context, p store.ListMessagesParams) ([]domain.Message, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := s.requireMember(ctx, s.pool, p.ConversationID, p.UserID); err != nil {
		return nil, err
	}
	var rows pgx.Rows
	var err error
	switch {
	case p.AfterSeq != nil:
		rows, err = s.pool.Query(ctx, `
			SELECT id,client_message_id,conversation_id,sender_id,sender_device_id,seq,content_type,
			       ciphertext,COALESCE(envelope,'null'::jsonb),reply_to_id,created_at,server_received_at
			FROM messages WHERE conversation_id=$1 AND seq>$2 ORDER BY seq ASC LIMIT $3`,
			p.ConversationID, *p.AfterSeq, p.Limit)
	case p.BeforeSeq != nil:
		rows, err = s.pool.Query(ctx, `
			SELECT id,client_message_id,conversation_id,sender_id,sender_device_id,seq,content_type,
			       ciphertext,envelope,reply_to_id,created_at,server_received_at
			FROM (
				SELECT id,client_message_id,conversation_id,sender_id,sender_device_id,seq,content_type,
				       ciphertext,COALESCE(envelope,'null'::jsonb) AS envelope,reply_to_id,
				       created_at,server_received_at
				FROM messages WHERE conversation_id=$1 AND seq<$2 ORDER BY seq DESC LIMIT $3
			) AS message_page ORDER BY seq ASC`, p.ConversationID, *p.BeforeSeq, p.Limit)
	default:
		rows, err = s.pool.Query(ctx, `
			SELECT id,client_message_id,conversation_id,sender_id,sender_device_id,seq,content_type,
			       ciphertext,envelope,reply_to_id,created_at,server_received_at
			FROM (
				SELECT id,client_message_id,conversation_id,sender_id,sender_device_id,seq,content_type,
				       ciphertext,COALESCE(envelope,'null'::jsonb) AS envelope,reply_to_id,
				       created_at,server_received_at
				FROM messages WHERE conversation_id=$1 ORDER BY seq DESC LIMIT $2
			) AS message_page ORDER BY seq ASC`, p.ConversationID, p.Limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.Message, 0, p.Limit)
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
	if err := lockLiveUser(ctx, tx, receipt.UserID); err != nil {
		return domain.Receipt{}, err
	}
	if err := lockConversation(ctx, tx, receipt.ConversationID); err != nil {
		return domain.Receipt{}, err
	}
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
	if err := lockLiveUser(ctx, tx, entity.CreatedBy); err != nil {
		return domain.Entity{}, err
	}
	var conversationMetadata json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT metadata FROM conversations WHERE id=$1 FOR SHARE`, entity.ConversationID).Scan(&conversationMetadata); err != nil {
		return domain.Entity{}, mapError(err)
	}
	if err := s.requireMember(ctx, tx, entity.ConversationID, entity.CreatedBy); err != nil {
		return domain.Entity{}, err
	}
	activeMembers, err := listConversationMembers(ctx, tx, entity.ConversationID)
	if err != nil {
		return domain.Entity{}, err
	}
	localIDs, err := ensureConversationMemberLocalIDs(
		ctx, tx, entity.ConversationID, conversationMetadata, activeMembers,
	)
	if err != nil {
		return domain.Entity{}, err
	}
	if err := store.ValidateEntityParticipants(
		entity.Kind, entity.Payload, conversationMetadata, activeMembers, localIDs...,
	); err != nil {
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
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return domain.Entity{}, err
	}
	if err := lockConversation(ctx, tx, conversationID); err != nil {
		return domain.Entity{}, err
	}
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

func (s *Store) RotateChore(ctx context.Context, p store.RotateChoreParams) (store.RotateChoreResult, error) {
	if p.OperationID == uuid.Nil {
		return store.RotateChoreResult{}, domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.RotateChoreResult{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockLiveUser(ctx, tx, p.ActorID); err != nil {
		return store.RotateChoreResult{}, err
	}
	// The conversation row is the membership authority. Take its update lock
	// before observing membership or a replay result so a concurrent removal
	// has one unambiguous serialization point: a removal that owns the lock
	// first commits before this membership recheck, while a command that owns it
	// first remains authorized through its complete atomic commit.
	var metadata json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT metadata FROM conversations WHERE id=$1 FOR UPDATE`, p.ConversationID).Scan(&metadata); err != nil {
		return store.RotateChoreResult{}, mapError(err)
	}
	if err := s.requireMember(ctx, tx, p.ConversationID, p.ActorID); err != nil {
		return store.RotateChoreResult{}, err
	}
	// Serialize both the first execution and concurrent replays before looking
	// up the durable result. The lock key is scoped to this database.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, p.OperationID); err != nil {
		return store.RotateChoreResult{}, err
	}
	var priorConversation, priorActor, priorChore uuid.UUID
	var priorHash []byte
	var choreJSON, feedJSON []byte
	err = tx.QueryRow(ctx, `SELECT conversation_id,actor_id,chore_id,request_hash,chore_result,feed_result FROM chore_rotation_operations WHERE operation_id=$1`, p.OperationID).
		Scan(&priorConversation, &priorActor, &priorChore, &priorHash, &choreJSON, &feedJSON)
	if err == nil {
		if priorConversation != p.ConversationID || priorActor != p.ActorID || priorChore != p.ChoreID || subtle.ConstantTimeCompare(priorHash, p.RequestHash) != 1 {
			return store.RotateChoreResult{}, domain.ErrConflict
		}
		var result store.RotateChoreResult
		result.OperationID = p.OperationID
		if json.Unmarshal(choreJSON, &result.Chore) != nil || json.Unmarshal(feedJSON, &result.FeedItem) != nil {
			return store.RotateChoreResult{}, fmt.Errorf("decode chore rotation result")
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return store.RotateChoreResult{}, err
	}
	if p.Validate() != nil {
		return store.RotateChoreResult{}, domain.ErrInvalid
	}
	var chore domain.Entity
	err = tx.QueryRow(ctx, `SELECT conversation_id,kind,id,version,payload,created_by,created_at,updated_at,deleted_at FROM entities WHERE conversation_id=$1 AND kind='chore' AND id=$2 AND deleted_at IS NULL FOR UPDATE`, p.ConversationID, p.ChoreID).
		Scan(&chore.ConversationID, &chore.Kind, &chore.ID, &chore.Version, &chore.Payload, &chore.CreatedBy, &chore.CreatedAt, &chore.UpdatedAt, &chore.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.RotateChoreResult{}, domain.ErrNotFound
	}
	if err != nil {
		return store.RotateChoreResult{}, err
	}
	if chore.Version != p.ExpectedChoreVersion {
		return store.RotateChoreResult{}, domain.ErrConflict
	}
	members, err := listConversationMembers(ctx, tx, p.ConversationID)
	if err != nil {
		return store.RotateChoreResult{}, err
	}
	localIDs, err := ensureConversationMemberLocalIDs(ctx, tx, p.ConversationID, metadata, members)
	if err != nil {
		return store.RotateChoreResult{}, err
	}
	if err = store.ValidateEntityParticipants("chore", p.ChorePayload, metadata, members, localIDs...); err != nil {
		return store.RotateChoreResult{}, err
	}
	if err = store.ValidateEntityParticipants("feed_item", p.FeedPayload, metadata, members, localIDs...); err != nil {
		return store.RotateChoreResult{}, err
	}
	err = tx.QueryRow(ctx, `UPDATE entities SET version=version+1,payload=$3,updated_at=now() WHERE conversation_id=$1 AND kind='chore' AND id=$2 AND deleted_at IS NULL RETURNING conversation_id,kind,id,version,payload,created_by,created_at,updated_at,deleted_at`, p.ConversationID, p.ChoreID, p.ChorePayload).
		Scan(&chore.ConversationID, &chore.Kind, &chore.ID, &chore.Version, &chore.Payload, &chore.CreatedBy, &chore.CreatedAt, &chore.UpdatedAt, &chore.DeletedAt)
	if err != nil {
		return store.RotateChoreResult{}, mapError(err)
	}
	var feed domain.Entity
	err = tx.QueryRow(ctx, `INSERT INTO entities(conversation_id,kind,id,version,payload,created_by,created_at,updated_at) VALUES($1,'feed_item',$2,1,$3,$4,now(),now()) RETURNING conversation_id,kind,id,version,payload,created_by,created_at,updated_at,deleted_at`, p.ConversationID, p.OperationID, p.FeedPayload, p.ActorID).
		Scan(&feed.ConversationID, &feed.Kind, &feed.ID, &feed.Version, &feed.Payload, &feed.CreatedBy, &feed.CreatedAt, &feed.UpdatedAt, &feed.DeletedAt)
	if err != nil {
		return store.RotateChoreResult{}, mapError(err)
	}
	for _, entity := range []domain.Entity{chore, feed} {
		payload, _ := json.Marshal(entity)
		if _, err = tx.Exec(ctx, `INSERT INTO outbox_events(topic,aggregate_id,payload) VALUES('entity.updated',$1,$2)`, p.ConversationID, payload); err != nil {
			return store.RotateChoreResult{}, err
		}
	}
	choreJSON, _ = json.Marshal(chore)
	feedJSON, _ = json.Marshal(feed)
	if _, err = tx.Exec(ctx, `INSERT INTO chore_rotation_operations(operation_id,conversation_id,actor_id,chore_id,request_hash,chore_result,feed_result) VALUES($1,$2,$3,$4,$5,$6,$7)`, p.OperationID, p.ConversationID, p.ActorID, p.ChoreID, p.RequestHash, choreJSON, feedJSON); err != nil {
		return store.RotateChoreResult{}, mapError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return store.RotateChoreResult{}, err
	}
	return store.RotateChoreResult{OperationID: p.OperationID, Chore: chore, FeedItem: feed}, nil
}

func (s *Store) PruneChoreRotationOperations(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	if batchSize < 1 {
		return 0, domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// Retention maintenance must never turn a slow delete into an unbounded API
	// outage. This timeout is transaction-local and cannot leak to pooled sessions.
	if _, err = tx.Exec(ctx, `SELECT set_config('statement_timeout','5s',true)`); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `
		WITH expired AS (
			SELECT operation_id FROM chore_rotation_operations
			WHERE expires_at <= LEAST($1,now())
			ORDER BY expires_at,operation_id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM chore_rotation_operations operations
		USING expired WHERE operations.operation_id=expired.operation_id`, cutoff, batchSize)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) CreateMedia(ctx context.Context, media domain.MediaObject, limits store.MediaReservationLimits) (domain.MediaObject, error) {
	if err := limits.Validate(); err != nil {
		return domain.MediaObject{}, err
	}
	if media.ID == uuid.Nil || media.OwnerID == uuid.Nil || media.ConversationID == uuid.Nil ||
		media.ByteSize < 1 || strings.TrimSpace(media.ObjectKey) == "" || strings.TrimSpace(media.ContentType) == "" {
		return domain.MediaObject{}, domain.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.MediaObject{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", media.OwnerID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockLiveUser(ctx, tx, media.OwnerID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockMediaQuota(ctx, tx, "conversation", media.ConversationID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockConversation(ctx, tx, media.ConversationID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := s.requireMember(ctx, tx, media.ConversationID, media.OwnerID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := checkUserMediaQuota(ctx, tx, media.OwnerID, media.ByteSize, limits); err != nil {
		return domain.MediaObject{}, err
	}
	if err := checkConversationMediaQuota(ctx, tx, media.ConversationID, media.ByteSize, limits); err != nil {
		return domain.MediaObject{}, err
	}
	now := time.Now().UTC()
	media.CreatedAt, media.UpdatedAt, media.Status = now, now, "pending"
	expiresAt := now.Add(limits.PendingTTL)
	media.ExpiresAt = &expiresAt
	media.UploadValidUntil = expiresAt
	err = tx.QueryRow(ctx, `
		INSERT INTO media_objects(id,owner_id,conversation_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,expires_at,upload_valid_until,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$8,$9,$9)
		RETURNING id,owner_id,conversation_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,expires_at,upload_valid_until,
			verification_lease_token,verification_locked_until,created_at,updated_at`,
		media.ID, media.OwnerID, media.ConversationID, media.ObjectKey, media.ContentType,
		media.ByteSize, media.CiphertextSHA256, expiresAt, now,
	).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
		&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	if err != nil {
		return domain.MediaObject{}, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.MediaObject{}, err
	}
	media.Scope = domain.MediaScopeConversation
	return media, nil
}

func (s *Store) CreateProfileMedia(ctx context.Context, media domain.MediaObject, limits store.MediaReservationLimits) (domain.MediaObject, error) {
	if err := limits.Validate(); err != nil {
		return domain.MediaObject{}, err
	}
	if media.ID == uuid.Nil || media.OwnerID == uuid.Nil || media.ByteSize < 1 ||
		strings.TrimSpace(media.ObjectKey) == "" || strings.TrimSpace(media.ContentType) == "" {
		return domain.MediaObject{}, domain.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.MediaObject{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", media.OwnerID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockLiveUser(ctx, tx, media.OwnerID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := checkUserMediaQuota(ctx, tx, media.OwnerID, media.ByteSize, limits); err != nil {
		return domain.MediaObject{}, err
	}
	now := time.Now().UTC()
	media.CreatedAt, media.UpdatedAt, media.Status = now, now, "pending"
	expiresAt := now.Add(limits.PendingTTL)
	media.ExpiresAt = &expiresAt
	media.UploadValidUntil = expiresAt
	err = tx.QueryRow(ctx, `
		INSERT INTO profile_media_objects(id,owner_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,expires_at,upload_valid_until,created_at,updated_at)
		SELECT $1,$2,$3,$4,$5,$6,'pending',$7,$7,$8,$8
		FROM users WHERE id=$2 AND deleted_at IS NULL
		RETURNING id,owner_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,expires_at,upload_valid_until,
			verification_lease_token,verification_locked_until,created_at,updated_at`,
		media.ID, media.OwnerID, media.ObjectKey, media.ContentType,
		media.ByteSize, media.CiphertextSHA256, expiresAt, now,
	).Scan(&media.ID, &media.OwnerID, &media.ObjectKey, &media.ContentType,
		&media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	if err != nil {
		return domain.MediaObject{}, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.MediaObject{}, err
	}
	media.ConversationID = uuid.Nil
	media.Scope = domain.MediaScopeProfile
	return media, nil
}

func (s *Store) PersistMediaUploadCapability(
	ctx context.Context,
	id, actorID uuid.UUID,
	revocationToken string,
) error {
	revocationToken = strings.TrimSpace(revocationToken)
	if id == uuid.Nil || actorID == uuid.Nil || revocationToken == "" || len(revocationToken) > 1024 {
		return domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return err
	}
	_, conversationMedia, err := s.lockConversationMediaMutation(ctx, tx, id, actorID)
	if err != nil {
		return err
	}
	var tag pgconn.CommandTag
	if conversationMedia {
		tag, err = tx.Exec(ctx, `
			UPDATE media_objects SET upload_capability_id=$3
			WHERE id=$1 AND owner_id=$2 AND status='pending'
			  AND (upload_capability_id IS NULL OR upload_capability_id=$3)`,
			id, actorID, revocationToken)
	} else {
		tag, err = tx.Exec(ctx, `
			UPDATE profile_media_objects SET upload_capability_id=$3
			WHERE id=$1 AND owner_id=$2 AND status='pending'
			  AND (upload_capability_id IS NULL OR upload_capability_id=$3)`,
			id, actorID, revocationToken)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM media_objects WHERE id=$1 AND owner_id=$2
				UNION ALL
				SELECT 1 FROM profile_media_objects WHERE id=$1 AND owner_id=$2
			)`, id, actorID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return domain.ErrNotFound
		}
		return domain.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s *Store) MediaUploadCapability(
	ctx context.Context,
	id, actorID uuid.UUID,
) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return "", err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return "", err
	}
	_, conversationMedia, err := s.lockConversationMediaMutation(ctx, tx, id, actorID)
	if err != nil {
		return "", err
	}
	var token string
	if conversationMedia {
		err = tx.QueryRow(ctx, `
			SELECT COALESCE(upload_capability_id,'') FROM media_objects
			WHERE id=$1 AND owner_id=$2 AND status<>'deleted'`, id, actorID).Scan(&token)
	} else {
		err = tx.QueryRow(ctx, `
			SELECT COALESCE(upload_capability_id,'') FROM profile_media_objects
			WHERE id=$1 AND owner_id=$2 AND status<>'deleted'`, id, actorID).Scan(&token)
	}
	if err != nil {
		return "", mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return token, nil
}

func lockMediaQuota(ctx context.Context, tx pgx.Tx, scope string, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "media:"+scope+":"+id.String())
	return err
}

// lockConversationMediaMutation resolves a conversation-media child without
// locking it, then takes every parent lock in the global order before the
// caller touches that child row. The unlocked lookup is only a routing hint;
// callers must still qualify the eventual child mutation by id and owner.
func (s *Store) lockConversationMediaMutation(
	ctx context.Context,
	tx pgx.Tx,
	id, actorID uuid.UUID,
) (uuid.UUID, bool, error) {
	var conversationID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT conversation_id FROM media_objects
		WHERE id=$1 AND owner_id=$2 AND status<>'deleted'`, id, actorID,
	).Scan(&conversationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	if err := lockMediaQuota(ctx, tx, "conversation", conversationID); err != nil {
		return uuid.Nil, false, err
	}
	if err := lockConversation(ctx, tx, conversationID); err != nil {
		return uuid.Nil, false, err
	}
	if err := s.requireMember(ctx, tx, conversationID, actorID); err != nil {
		return uuid.Nil, false, err
	}
	return conversationID, true, nil
}

func checkUserMediaQuota(
	ctx context.Context,
	tx pgx.Tx,
	ownerID uuid.UUID,
	requestedBytes int64,
	limits store.MediaReservationLimits,
) error {
	if requestedBytes < 1 || requestedBytes > limits.MaxPendingBytesPerUser ||
		requestedBytes > limits.MaxStoredBytesPerUser {
		return domain.ErrQuotaExceeded
	}
	var pendingCount, storedCount int
	var pendingBytes, storedBytes int64
	err := tx.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status='pending'),
			COALESCE(sum(byte_size) FILTER (WHERE status='pending'),0)::bigint,
			count(*),COALESCE(sum(byte_size),0)::bigint
		FROM (
			SELECT byte_size,status FROM media_objects WHERE owner_id=$1 AND status<>'deleted'
			UNION ALL
			SELECT byte_size,status FROM profile_media_objects WHERE owner_id=$1 AND status<>'deleted'
		) stored`, ownerID).Scan(&pendingCount, &pendingBytes, &storedCount, &storedBytes)
	if err != nil {
		return err
	}
	if pendingCount+1 > limits.MaxPendingCountPerUser ||
		pendingBytes+requestedBytes > limits.MaxPendingBytesPerUser ||
		storedCount+1 > limits.MaxStoredCountPerUser ||
		storedBytes+requestedBytes > limits.MaxStoredBytesPerUser {
		return domain.ErrQuotaExceeded
	}
	return nil
}

func checkConversationMediaQuota(
	ctx context.Context,
	tx pgx.Tx,
	conversationID uuid.UUID,
	requestedBytes int64,
	limits store.MediaReservationLimits,
) error {
	if requestedBytes < 1 || requestedBytes > limits.MaxPendingBytesConversation ||
		requestedBytes > limits.MaxStoredBytesConversation {
		return domain.ErrQuotaExceeded
	}
	var pendingCount, storedCount int
	var pendingBytes, storedBytes int64
	err := tx.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status='pending'),
			COALESCE(sum(byte_size) FILTER (WHERE status='pending'),0)::bigint,
			count(*),COALESCE(sum(byte_size),0)::bigint
		FROM media_objects WHERE conversation_id=$1 AND status<>'deleted'`,
		conversationID).Scan(&pendingCount, &pendingBytes, &storedCount, &storedBytes)
	if err != nil {
		return err
	}
	if pendingCount+1 > limits.MaxPendingCountConversation ||
		pendingBytes+requestedBytes > limits.MaxPendingBytesConversation ||
		storedCount+1 > limits.MaxStoredCountConversation ||
		storedBytes+requestedBytes > limits.MaxStoredBytesConversation {
		return domain.ErrQuotaExceeded
	}
	return nil
}

func (s *Store) Media(ctx context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	var media domain.MediaObject
	err := s.pool.QueryRow(ctx, `
		SELECT o.id,o.owner_id,o.conversation_id,o.object_key,o.content_type,o.byte_size,
			o.ciphertext_sha256,o.status,o.expires_at,o.upload_valid_until,
			o.verification_lease_token,o.verification_locked_until,o.created_at,o.updated_at
		FROM media_objects o
		JOIN conversation_members m ON m.conversation_id=o.conversation_id
		WHERE o.id=$1 AND m.user_id=$2 AND o.status<>'deleted'`, id, actorID,
	).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
		&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	if err == nil {
		media.Scope = domain.MediaScopeConversation
		return media, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.MediaObject{}, mapError(err)
	}
	err = s.pool.QueryRow(ctx, `
		SELECT id,owner_id,object_key,content_type,byte_size,ciphertext_sha256,
			status,expires_at,upload_valid_until,verification_lease_token,
			verification_locked_until,created_at,updated_at
		FROM profile_media_objects
		WHERE id=$1 AND status<>'deleted' AND (owner_id=$2 OR status='ready')`, id, actorID,
	).Scan(&media.ID, &media.OwnerID, &media.ObjectKey, &media.ContentType,
		&media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	media.ConversationID = uuid.Nil
	media.Scope = domain.MediaScopeProfile
	return media, mapError(err)
}

func (s *Store) ClaimMediaVerification(
	ctx context.Context,
	id, actorID uuid.UUID,
	leaseDuration time.Duration,
) (domain.MediaObject, error) {
	if id == uuid.Nil || actorID == uuid.Nil || leaseDuration < time.Second || leaseDuration > 5*time.Minute {
		return domain.MediaObject{}, domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.MediaObject{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return domain.MediaObject{}, err
	}
	_, conversationMedia, err := s.lockConversationMediaMutation(ctx, tx, id, actorID)
	if err != nil {
		return domain.MediaObject{}, err
	}
	leaseToken := uuid.New()
	leaseMilliseconds := leaseDuration.Milliseconds()
	var media domain.MediaObject
	if conversationMedia {
		err = tx.QueryRow(ctx, `
			UPDATE media_objects
			SET verification_lease_token=$3,
				verification_locked_until=now()+($4 * interval '1 millisecond'),updated_at=now()
			WHERE id=$1 AND owner_id=$2 AND status='pending' AND expires_at>now()
			  AND (verification_locked_until IS NULL OR verification_locked_until<= now())
			RETURNING id,owner_id,conversation_id,object_key,content_type,byte_size,
				ciphertext_sha256,status,expires_at,upload_valid_until,
				verification_lease_token,verification_locked_until,created_at,updated_at`,
			id, actorID, leaseToken, leaseMilliseconds,
		).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
			&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
			&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
			&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
		if err == nil {
			media.Scope = domain.MediaScopeConversation
			if err := tx.Commit(ctx); err != nil {
				return domain.MediaObject{}, err
			}
			return media, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return domain.MediaObject{}, mapError(err)
		}
	} else {
		err = tx.QueryRow(ctx, `
		UPDATE profile_media_objects
		SET verification_lease_token=$3,
			verification_locked_until=now()+($4 * interval '1 millisecond'),updated_at=now()
		WHERE id=$1 AND owner_id=$2 AND status='pending' AND expires_at>now()
		  AND (verification_locked_until IS NULL OR verification_locked_until<=now())
		RETURNING id,owner_id,object_key,content_type,byte_size,ciphertext_sha256,
			status,expires_at,upload_valid_until,verification_lease_token,
			verification_locked_until,created_at,updated_at`,
			id, actorID, leaseToken, leaseMilliseconds,
		).Scan(&media.ID, &media.OwnerID, &media.ObjectKey, &media.ContentType,
			&media.ByteSize, &media.CiphertextSHA256, &media.Status, &media.ExpiresAt,
			&media.UploadValidUntil, &media.VerificationLeaseToken,
			&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
		if err == nil {
			media.Scope = domain.MediaScopeProfile
			if err := tx.Commit(ctx); err != nil {
				return domain.MediaObject{}, err
			}
			return media, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return domain.MediaObject{}, mapError(err)
		}
	}
	var status string
	var expired bool
	err = tx.QueryRow(ctx, `
		SELECT status,(expires_at IS NULL OR expires_at<=now()) FROM media_objects
		WHERE id=$1 AND owner_id=$2
		UNION ALL
		SELECT status,(expires_at IS NULL OR expires_at<=now()) FROM profile_media_objects
		WHERE id=$1 AND owner_id=$2
		LIMIT 1`, id, actorID).Scan(&status, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.MediaObject{}, err
	}
	if status == "ready" {
		if err := tx.Commit(ctx); err != nil {
			return domain.MediaObject{}, err
		}
		return s.mediaForOwner(ctx, id, actorID)
	}
	if status == "pending" && expired {
		return domain.MediaObject{}, domain.ErrMediaExpired
	}
	return domain.MediaObject{}, domain.ErrConflict
}

func (s *Store) mediaForOwner(ctx context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	var media domain.MediaObject
	err := s.pool.QueryRow(ctx, `
		SELECT id,owner_id,conversation_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,expires_at,upload_valid_until,
			verification_lease_token,verification_locked_until,created_at,updated_at
		FROM media_objects WHERE id=$1 AND owner_id=$2 AND status<>'deleted'`, id, actorID,
	).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
		&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	if err == nil {
		media.Scope = domain.MediaScopeConversation
		return media, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.MediaObject{}, mapError(err)
	}
	err = s.pool.QueryRow(ctx, `
		SELECT id,owner_id,object_key,content_type,byte_size,ciphertext_sha256,
			status,expires_at,upload_valid_until,verification_lease_token,
			verification_locked_until,created_at,updated_at
		FROM profile_media_objects WHERE id=$1 AND owner_id=$2 AND status<>'deleted'`, id, actorID,
	).Scan(&media.ID, &media.OwnerID, &media.ObjectKey, &media.ContentType,
		&media.ByteSize, &media.CiphertextSHA256, &media.Status, &media.ExpiresAt,
		&media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	media.Scope = domain.MediaScopeProfile
	media.ConversationID = uuid.Nil
	return media, mapError(err)
}

func (s *Store) MarkMediaReady(
	ctx context.Context,
	id, actorID, leaseToken uuid.UUID,
	publishedObjectKey string,
) (domain.MediaObject, error) {
	if leaseToken == uuid.Nil {
		return domain.MediaObject{}, domain.ErrConflict
	}
	if err := mediakey.Validate(publishedObjectKey); err != nil {
		return domain.MediaObject{}, domain.ErrInvalid
	}
	ready, err := s.markConversationMediaReady(
		ctx, id, actorID, leaseToken, publishedObjectKey,
	)
	if err == nil || !errors.Is(err, domain.ErrNotFound) {
		return ready, err
	}
	ready, err = s.markProfileMediaReady(ctx, id, actorID, leaseToken, publishedObjectKey)
	if err == nil || !errors.Is(err, domain.ErrNotFound) {
		return ready, err
	}
	latest, lookupErr := s.mediaForOwner(ctx, id, actorID)
	if lookupErr != nil {
		return domain.MediaObject{}, lookupErr
	}
	if latest.Status == "ready" {
		return latest, nil
	}
	if latest.Status == "pending" &&
		(latest.ExpiresAt == nil || !latest.ExpiresAt.After(time.Now().UTC())) {
		return domain.MediaObject{}, domain.ErrMediaExpired
	}
	return domain.MediaObject{}, domain.ErrConflict
}

func (s *Store) markConversationMediaReady(
	ctx context.Context,
	id, actorID, leaseToken uuid.UUID,
	publishedObjectKey string,
) (domain.MediaObject, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.MediaObject{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return domain.MediaObject{}, err
	}
	if _, conversationMedia, err := s.lockConversationMediaMutation(ctx, tx, id, actorID); err != nil {
		return domain.MediaObject{}, err
	} else if !conversationMedia {
		return domain.MediaObject{}, domain.ErrNotFound
	}
	var media domain.MediaObject
	err = tx.QueryRow(ctx, `
		SELECT id,owner_id,conversation_id,object_key,content_type,byte_size,
			ciphertext_sha256,status,expires_at,upload_valid_until,
			verification_lease_token,verification_locked_until,created_at,updated_at
		FROM media_objects
		WHERE id=$1 AND owner_id=$2 AND status='pending' AND expires_at>now()
		  AND verification_lease_token=$3 AND verification_locked_until>now()
		FOR UPDATE`, id, actorID, leaseToken,
	).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
		&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	if err != nil {
		return domain.MediaObject{}, mapError(err)
	}
	stagingObjectKey := media.ObjectKey
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `
		UPDATE media_objects
		SET object_key=$4,status='ready',expires_at=NULL,upload_capability_id=NULL,
			verification_lease_token=NULL,verification_locked_until=NULL,updated_at=$5
		WHERE id=$1 AND owner_id=$2 AND verification_lease_token=$3
		  AND verification_locked_until>now()`,
		id, actorID, leaseToken, publishedObjectKey, now)
	if err != nil {
		return domain.MediaObject{}, err
	}
	if tag.RowsAffected() != 1 {
		return domain.MediaObject{}, domain.ErrConflict
	}
	if stagingObjectKey != publishedObjectKey {
		if err := enqueueExactMediaDeletesAt(
			ctx, tx, actorID, []string{stagingObjectKey}, mediaDeleteNotBefore(media.UploadValidUntil),
		); err != nil {
			return domain.MediaObject{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.MediaObject{}, err
	}
	media.ObjectKey = publishedObjectKey
	media.Status = "ready"
	media.ExpiresAt = nil
	media.VerificationLeaseToken = nil
	media.VerificationLockedUntil = nil
	media.UpdatedAt = now
	media.Scope = domain.MediaScopeConversation
	return media, nil
}

func (s *Store) markProfileMediaReady(
	ctx context.Context,
	id, actorID, leaseToken uuid.UUID,
	publishedObjectKey string,
) (domain.MediaObject, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.MediaObject{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return domain.MediaObject{}, err
	}

	var media domain.MediaObject
	err = tx.QueryRow(ctx, `
		SELECT id,owner_id,object_key,content_type,byte_size,ciphertext_sha256,
			status,expires_at,upload_valid_until,verification_lease_token,
			verification_locked_until,created_at,updated_at
		FROM profile_media_objects
		WHERE id=$1 AND owner_id=$2 AND status='pending' AND expires_at>now()
		  AND verification_lease_token=$3 AND verification_locked_until>now()
		FOR UPDATE`, id, actorID, leaseToken,
	).Scan(&media.ID, &media.OwnerID, &media.ObjectKey, &media.ContentType,
		&media.ByteSize, &media.CiphertextSHA256, &media.Status,
		&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
		&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	if err != nil {
		return domain.MediaObject{}, mapError(err)
	}
	var oldReference string
	if err := tx.QueryRow(ctx, `SELECT avatar_url FROM users WHERE id=$1`, actorID).
		Scan(&oldReference); err != nil {
		return domain.MediaObject{}, mapError(err)
	}
	now := time.Now().UTC()
	stagingObjectKey := media.ObjectKey
	readyTag, err := tx.Exec(ctx, `
		UPDATE profile_media_objects
		SET object_key=$4,status='ready',expires_at=NULL,upload_capability_id=NULL,
			verification_lease_token=NULL,verification_locked_until=NULL,updated_at=$2
		WHERE id=$1 AND verification_lease_token=$3 AND verification_locked_until>now()`,
		id, now, leaseToken, publishedObjectKey)
	if err != nil {
		return domain.MediaObject{}, err
	}
	if readyTag.RowsAffected() != 1 {
		return domain.MediaObject{}, domain.ErrConflict
	}
	if stagingObjectKey != publishedObjectKey {
		if err := enqueueExactMediaDeletesAt(
			ctx, tx, actorID, []string{stagingObjectKey}, mediaDeleteNotBefore(media.UploadValidUntil),
		); err != nil {
			return domain.MediaObject{}, err
		}
	}
	reference := "clustr-media://" + id.String()
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET avatar_url=$2,
			profile=(profile - 'profileImageURL') || jsonb_build_object('profile_image_url',$2::text),
			updated_at=$3
		WHERE id=$1`, actorID, reference, now); err != nil {
		return domain.MediaObject{}, err
	}
	if oldID := parseProfileMediaID(oldReference); oldID != uuid.Nil && oldID != id {
		var oldObjectKey string
		var oldUploadValidUntil time.Time
		err := tx.QueryRow(ctx, `
			UPDATE profile_media_objects
			SET status='deleted',expires_at=NULL,verification_lease_token=NULL,
				verification_locked_until=NULL,updated_at=$3
			WHERE id=$1 AND owner_id=$2 AND status<>'deleted'
			RETURNING object_key,upload_valid_until`, oldID, actorID, now).
			Scan(&oldObjectKey, &oldUploadValidUntil)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return domain.MediaObject{}, err
		}
		if err == nil {
			if err := enqueueMediaDeleteAt(
				ctx, tx, actorID, oldObjectKey, mediaDeleteNotBefore(oldUploadValidUntil),
			); err != nil {
				return domain.MediaObject{}, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.MediaObject{}, err
	}
	media.Status = "ready"
	media.ObjectKey = publishedObjectKey
	media.ExpiresAt = nil
	media.VerificationLeaseToken = nil
	media.VerificationLockedUntil = nil
	media.UpdatedAt = now
	media.ConversationID = uuid.Nil
	media.Scope = domain.MediaScopeProfile
	return media, nil
}

func (s *Store) ReleaseMediaVerification(
	ctx context.Context,
	id, actorID, leaseToken uuid.UUID,
) error {
	if leaseToken == uuid.Nil {
		return domain.ErrConflict
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return err
	}
	_, conversationMedia, err := s.lockConversationMediaMutation(ctx, tx, id, actorID)
	if err != nil {
		return err
	}
	var tag pgconn.CommandTag
	if conversationMedia {
		tag, err = tx.Exec(ctx, `
			UPDATE media_objects
			SET verification_lease_token=NULL,verification_locked_until=NULL,updated_at=now()
			WHERE id=$1 AND owner_id=$2 AND status='pending' AND verification_lease_token=$3`,
			id, actorID, leaseToken)
	} else {
		tag, err = tx.Exec(ctx, `
			UPDATE profile_media_objects
			SET verification_lease_token=NULL,verification_locked_until=NULL,updated_at=now()
			WHERE id=$1 AND owner_id=$2 AND status='pending' AND verification_lease_token=$3`,
			id, actorID, leaseToken)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s *Store) RejectMediaVerification(
	ctx context.Context,
	id, actorID, leaseToken uuid.UUID,
) (domain.MediaObject, error) {
	if leaseToken == uuid.Nil {
		return domain.MediaObject{}, domain.ErrConflict
	}
	return s.rejectPendingMedia(ctx, id, actorID, leaseToken)
}

func (s *Store) DeleteMedia(ctx context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.MediaObject{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return domain.MediaObject{}, err
	}
	_, conversationMedia, err := s.lockConversationMediaMutation(ctx, tx, id, actorID)
	if err != nil {
		return domain.MediaObject{}, err
	}
	var media domain.MediaObject
	if conversationMedia {
		err = tx.QueryRow(ctx, `
		WITH selected AS (
			SELECT id,upload_valid_until FROM media_objects
			WHERE id=$1 AND owner_id=$2 AND status<>'deleted' FOR UPDATE
		)
		UPDATE media_objects objects
		SET status='deleted',expires_at=NULL,verification_lease_token=NULL,
			verification_locked_until=NULL,updated_at=now()
		FROM selected WHERE objects.id=selected.id
		RETURNING objects.id,objects.owner_id,objects.conversation_id,objects.object_key,
			objects.content_type,objects.byte_size,objects.ciphertext_sha256,objects.status,
			objects.expires_at,objects.upload_valid_until,objects.verification_lease_token,
			objects.verification_locked_until,objects.created_at,objects.updated_at`, id, actorID,
		).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
			&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
			&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
			&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	} else {
		err = pgx.ErrNoRows
	}
	if err == nil {
		media.Scope = domain.MediaScopeConversation
	} else if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			WITH selected AS (
				SELECT id,upload_valid_until FROM profile_media_objects
				WHERE id=$1 AND owner_id=$2 AND status<>'deleted' FOR UPDATE
			)
			UPDATE profile_media_objects objects
			SET status='deleted',expires_at=NULL,verification_lease_token=NULL,
				verification_locked_until=NULL,updated_at=now()
			FROM selected WHERE objects.id=selected.id
			RETURNING objects.id,objects.owner_id,objects.object_key,objects.content_type,
				objects.byte_size,objects.ciphertext_sha256,objects.status,objects.expires_at,
				objects.upload_valid_until,objects.verification_lease_token,
				objects.verification_locked_until,objects.created_at,objects.updated_at`, id, actorID,
		).Scan(&media.ID, &media.OwnerID, &media.ObjectKey, &media.ContentType,
			&media.ByteSize, &media.CiphertextSHA256, &media.Status,
			&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
			&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
		if err == nil {
			media.Scope = domain.MediaScopeProfile
			media.ConversationID = uuid.Nil
			if _, err := tx.Exec(ctx, `
				UPDATE users
				SET avatar_url='',profile=profile - 'profile_image_url' - 'profileImageURL',updated_at=now()
				WHERE id=$1 AND avatar_url=$2`, actorID, "clustr-media://"+id.String()); err != nil {
				return domain.MediaObject{}, err
			}
		}
	}
	if err != nil {
		return domain.MediaObject{}, mapError(err)
	}
	if err := enqueueMediaDeleteAt(
		ctx, tx, actorID, media.ObjectKey, mediaDeleteNotBefore(media.UploadValidUntil),
	); err != nil {
		return domain.MediaObject{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.MediaObject{}, err
	}
	return media, nil
}

func (s *Store) RejectPendingMedia(ctx context.Context, id, actorID uuid.UUID) (domain.MediaObject, error) {
	return s.rejectPendingMedia(ctx, id, actorID, uuid.Nil)
}

func (s *Store) rejectPendingMedia(
	ctx context.Context,
	id, actorID, leaseToken uuid.UUID,
) (domain.MediaObject, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.MediaObject{}, err
	}
	defer tx.Rollback(ctx)
	if err := lockMediaQuota(ctx, tx, "user", actorID); err != nil {
		return domain.MediaObject{}, err
	}
	if err := lockLiveUser(ctx, tx, actorID); err != nil {
		return domain.MediaObject{}, err
	}
	_, conversationMedia, err := s.lockConversationMediaMutation(ctx, tx, id, actorID)
	if err != nil {
		return domain.MediaObject{}, err
	}
	var media domain.MediaObject
	if conversationMedia {
		err = tx.QueryRow(ctx, `
		WITH selected AS (
			SELECT id,upload_valid_until FROM media_objects
			WHERE id=$1 AND owner_id=$2 AND status='pending'
			  AND ($3::uuid='00000000-0000-0000-0000-000000000000' OR
				(verification_lease_token=$3 AND verification_locked_until>now()))
			FOR UPDATE
		)
		UPDATE media_objects objects
		SET status='deleted',expires_at=NULL,verification_lease_token=NULL,
			verification_locked_until=NULL,updated_at=now()
		FROM selected WHERE objects.id=selected.id
		RETURNING objects.id,objects.owner_id,objects.conversation_id,objects.object_key,
			objects.content_type,objects.byte_size,objects.ciphertext_sha256,objects.status,
			objects.expires_at,objects.upload_valid_until,objects.verification_lease_token,
			objects.verification_locked_until,objects.created_at,objects.updated_at`, id, actorID, leaseToken,
		).Scan(&media.ID, &media.OwnerID, &media.ConversationID, &media.ObjectKey,
			&media.ContentType, &media.ByteSize, &media.CiphertextSHA256, &media.Status,
			&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
			&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
	} else {
		err = pgx.ErrNoRows
	}
	if err == nil {
		media.Scope = domain.MediaScopeConversation
	} else if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			WITH selected AS (
				SELECT id,upload_valid_until FROM profile_media_objects
				WHERE id=$1 AND owner_id=$2 AND status='pending'
				  AND ($3::uuid='00000000-0000-0000-0000-000000000000' OR
					(verification_lease_token=$3 AND verification_locked_until>now()))
				FOR UPDATE
			)
			UPDATE profile_media_objects objects
			SET status='deleted',expires_at=NULL,verification_lease_token=NULL,
				verification_locked_until=NULL,updated_at=now()
			FROM selected WHERE objects.id=selected.id
			RETURNING objects.id,objects.owner_id,objects.object_key,objects.content_type,
				objects.byte_size,objects.ciphertext_sha256,objects.status,objects.expires_at,
				objects.upload_valid_until,objects.verification_lease_token,
				objects.verification_locked_until,objects.created_at,objects.updated_at`, id, actorID, leaseToken,
		).Scan(&media.ID, &media.OwnerID, &media.ObjectKey, &media.ContentType,
			&media.ByteSize, &media.CiphertextSHA256, &media.Status,
			&media.ExpiresAt, &media.UploadValidUntil, &media.VerificationLeaseToken,
			&media.VerificationLockedUntil, &media.CreatedAt, &media.UpdatedAt)
		if err == nil {
			media.Scope = domain.MediaScopeProfile
			media.ConversationID = uuid.Nil
		}
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var status string
			lookupErr := tx.QueryRow(ctx, `
				SELECT status FROM media_objects WHERE id=$1 AND owner_id=$2
				UNION ALL
				SELECT status FROM profile_media_objects WHERE id=$1 AND owner_id=$2
				LIMIT 1`, id, actorID).Scan(&status)
			if lookupErr == nil {
				return domain.MediaObject{}, domain.ErrConflict
			}
		}
		return domain.MediaObject{}, mapError(err)
	}
	if err := enqueueMediaDeleteAt(
		ctx, tx, actorID, media.ObjectKey, mediaDeleteNotBefore(media.UploadValidUntil),
	); err != nil {
		return domain.MediaObject{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.MediaObject{}, err
	}
	return media, nil
}

func (s *Store) ExpirePendingMedia(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	if limit < 1 || limit > store.MediaDeleteBatchSize {
		return 0, domain.ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	expiredObjects, err := expirePendingTable(ctx, tx, "media_objects", cutoff, limit)
	if err != nil {
		return 0, err
	}
	remaining := limit - len(expiredObjects)
	if remaining > 0 {
		profileKeys, err := expirePendingTable(ctx, tx, "profile_media_objects", cutoff, remaining)
		if err != nil {
			return 0, err
		}
		expiredObjects = append(expiredObjects, profileKeys...)
	}
	if len(expiredObjects) > 0 {
		sort.Slice(expiredObjects, func(i, j int) bool {
			return expiredObjects[i].objectKey < expiredObjects[j].objectKey
		})
		objectKeys := make([]string, 0, len(expiredObjects))
		deleteNotBefore := mediaDeleteNotBefore(time.Time{})
		for _, object := range expiredObjects {
			objectKeys = append(objectKeys, object.objectKey)
			if candidate := mediaDeleteNotBefore(object.uploadValidUntil); candidate.After(deleteNotBefore) {
				deleteNotBefore = candidate
			}
		}
		if err := enqueueMediaDeletesAt(ctx, tx, uuid.Nil, objectKeys, deleteNotBefore); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(expiredObjects), nil
}

type expiredMediaObject struct {
	objectKey        string
	uploadValidUntil time.Time
}

func expirePendingTable(
	ctx context.Context,
	tx pgx.Tx,
	table string,
	cutoff time.Time,
	limit int,
) ([]expiredMediaObject, error) {
	if table != "media_objects" && table != "profile_media_objects" {
		return nil, domain.ErrInvalid
	}
	query := fmt.Sprintf(`
		WITH selected AS (
			SELECT id FROM %s
			WHERE status='pending' AND expires_at<=$1
			ORDER BY expires_at,id
			FOR UPDATE SKIP LOCKED LIMIT $2
		)
		UPDATE %s objects
		SET status='deleted',expires_at=NULL,verification_lease_token=NULL,
			verification_locked_until=NULL,updated_at=$1
		FROM selected WHERE objects.id=selected.id
		RETURNING objects.object_key,objects.upload_valid_until`, table, table)
	rows, err := tx.Query(ctx, query, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var objects []expiredMediaObject
	for rows.Next() {
		var object expiredMediaObject
		if err := rows.Scan(&object.objectKey, &object.uploadValidUntil); err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	return objects, rows.Err()
}

func enqueueMediaDeleteAt(
	ctx context.Context,
	tx pgx.Tx,
	aggregateID uuid.UUID,
	objectKey string,
	notBefore time.Time,
) error {
	return enqueueMediaDeletesAt(ctx, tx, aggregateID, []string{objectKey}, notBefore)
}

func enqueueMediaDeletesAt(
	ctx context.Context,
	tx pgx.Tx,
	aggregateID uuid.UUID,
	objectKeys []string,
	notBefore time.Time,
) error {
	if len(objectKeys) < 1 || len(objectKeys) > store.MediaDeleteBatchSize {
		return domain.ErrInvalid
	}
	seen := make(map[string]struct{}, len(objectKeys)*2)
	expanded := make([]string, 0, len(objectKeys)*2)
	for _, objectKey := range objectKeys {
		keys, err := mediakey.DeletionKeys(objectKey)
		if err != nil {
			return domain.ErrInvalid
		}
		for _, key := range keys {
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			expanded = append(expanded, key)
		}
	}
	return enqueueExactMediaDeletesAt(ctx, tx, aggregateID, expanded, notBefore)
}

func enqueueExactMediaDeletesAt(
	ctx context.Context,
	tx pgx.Tx,
	aggregateID uuid.UUID,
	objectKeys []string,
	notBefore time.Time,
) error {
	if len(objectKeys) < 1 {
		return domain.ErrInvalid
	}
	if notBefore.IsZero() {
		return domain.ErrInvalid
	}
	notBefore = notBefore.UTC()
	for _, objectKey := range objectKeys {
		if err := mediakey.Validate(objectKey); err != nil {
			return domain.ErrInvalid
		}
	}
	for start := 0; start < len(objectKeys); start += store.MediaDeleteBatchSize {
		end := min(start+store.MediaDeleteBatchSize, len(objectKeys))
		payload, err := json.Marshal(store.NewMediaDeletePayloadAt(objectKeys[start:end], notBefore))
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `
			INSERT INTO outbox_events(topic,aggregate_id,payload,available_at)
			VALUES('media.delete',$1,$2,$3)`, aggregateID, payload, notBefore); err != nil {
			return err
		}
	}
	return nil
}

func mediaDeleteNotBefore(uploadValidUntil time.Time) time.Time {
	notBefore := time.Now().UTC().Add(store.MediaDeleteGrace)
	if candidate := uploadValidUntil.UTC().Add(store.MediaDeleteGrace); candidate.After(notBefore) {
		notBefore = candidate
	}
	return notBefore
}

func parseProfileMediaID(reference string) uuid.UUID {
	const prefix = "clustr-media://"
	if !strings.HasPrefix(reference, prefix) {
		return uuid.Nil
	}
	id, _ := uuid.Parse(strings.TrimPrefix(reference, prefix))
	return id
}

func (s *Store) LockOutboxBatch(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	return s.lockOutboxBatch(ctx, limit, "")
}

func (s *Store) LockRealtimeOutboxBatch(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	return s.lockOutboxBatch(ctx, limit, "realtime")
}

func (s *Store) LockMediaDeleteOutboxBatch(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	return s.lockOutboxBatch(ctx, limit, "media.delete")
}

func (s *Store) DeliverRealtimeOutbox(
	ctx context.Context,
	id int64,
	attempt int,
	deliver func(context.Context, domain.OutboxEvent) error,
) error {
	if id < 1 || attempt < 1 || deliver == nil {
		return domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockAccountDeliveryBarrierShared(ctx, tx); err != nil {
		return err
	}
	var event domain.OutboxEvent
	err = tx.QueryRow(ctx, `
		SELECT id,topic,aggregate_id,payload,created_at,published_at,
		       available_at,locked_until,attempts
		FROM outbox_events
		WHERE id=$1 AND attempts=$2 AND published_at IS NULL
		  AND topic<>'media.delete' AND locked_until IS NOT NULL
		FOR SHARE`, id, attempt).Scan(
		&event.ID, &event.Topic, &event.AggregateID, &event.Payload, &event.CreatedAt,
		&event.PublishedAt, &event.AvailableAt, &event.LockedUntil, &event.Attempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := deliver(ctx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) lockOutboxBatch(
	ctx context.Context,
	limit int,
	claim string,
) ([]domain.OutboxEvent, error) {
	if limit < 1 {
		return nil, domain.ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `
		WITH selected AS (
			SELECT id FROM outbox_events
			WHERE published_at IS NULL AND available_at<=now()
			  AND (locked_until IS NULL OR locked_until<now())
			  AND ($2='' OR ($2='realtime' AND topic<>'media.delete') OR topic=$2)
			ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1
		)
		UPDATE outbox_events o
		SET locked_until=now()+CASE WHEN $2='media.delete' THEN interval '30 minutes' ELSE interval '30 seconds' END,
			attempts=attempts+1
		FROM selected WHERE o.id=selected.id
		RETURNING o.id,o.topic,o.aggregate_id,o.payload,o.created_at,o.published_at,
			o.available_at,o.locked_until,o.attempts`, limit, claim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.OutboxEvent
	for rows.Next() {
		var event domain.OutboxEvent
		if err := rows.Scan(
			&event.ID, &event.Topic, &event.AggregateID, &event.Payload, &event.CreatedAt,
			&event.PublishedAt, &event.AvailableAt, &event.LockedUntil, &event.Attempts,
		); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) ReleaseOutboxEvent(ctx context.Context, id int64, availableAt time.Time) error {
	if id < 1 || availableAt.IsZero() {
		return domain.ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE outbox_events
		SET available_at=$2,locked_until=NULL
		WHERE id=$1 AND published_at IS NULL`, id, availableAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) MarkOutboxPublished(ctx context.Context, ids []int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE outbox_events SET published_at=now(),locked_until=NULL WHERE id=ANY($1)`, ids)
	return err
}

func (s *Store) EnqueuePushDeliveries(
	ctx context.Context,
	delivery domain.PushDelivery,
	recipientIDs []uuid.UUID,
) (int, error) {
	if len(recipientIDs) == 0 {
		return 0, nil
	}
	if delivery.OutboxEventID < 1 || delivery.ConversationID == uuid.Nil ||
		delivery.EntityID == uuid.Nil || strings.TrimSpace(delivery.NotificationID) == "" {
		return 0, domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// Account deletion locks the user row FOR UPDATE before it removes device
	// deliveries. Holding these live-recipient rows FOR SHARE makes creation of
	// new delivery rows use the same serialization point: enqueue first is
	// purged by deletion, while deletion first makes the recipient ineligible.
	rows, err := tx.Query(ctx, `
		SELECT id FROM users
		WHERE id=ANY($1) AND deleted_at IS NULL
		ORDER BY id
		FOR SHARE`, recipientIDs)
	if err != nil {
		return 0, err
	}
	var liveRecipientIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		liveRecipientIDs = append(liveRecipientIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	if len(liveRecipientIDs) == 0 {
		return 0, tx.Commit(ctx)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO push_deliveries(
			outbox_event_id,device_id,title,body,kind,conversation_id,entity_id,notification_id
		)
		SELECT $1,device.id,$2,$3,$4,$5,$6,$7
		FROM devices AS device
		WHERE device.user_id=ANY($8)
		  AND device.platform='ios'
		  AND device.push_token<>''
		ON CONFLICT(outbox_event_id,device_id) DO NOTHING`,
		delivery.OutboxEventID, delivery.Title, delivery.Body, delivery.Kind,
		delivery.ConversationID, delivery.EntityID, delivery.NotificationID, liveRecipientIDs)
	if err != nil {
		return 0, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) LockPushDeliveryBatch(
	ctx context.Context,
	limit int,
) ([]domain.PushDelivery, error) {
	if limit < 1 {
		return nil, domain.ErrInvalid
	}
	leaseToken := uuid.New()
	rows, err := s.pool.Query(ctx, `
		WITH selected AS (
			SELECT id
			FROM push_deliveries
			WHERE status='pending'
			  AND next_attempt_at<=now()
			  AND (locked_until IS NULL OR locked_until<now())
			ORDER BY next_attempt_at,id
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		), claimed AS (
			UPDATE push_deliveries AS delivery
			SET locked_until=now()+interval '2 minutes',lease_token=$2,
				attempts=attempts+1,updated_at=now()
			FROM selected
			WHERE delivery.id=selected.id
			  AND delivery.status='pending'
			  AND delivery.next_attempt_at<=now()
			  AND (delivery.locked_until IS NULL OR delivery.locked_until<now())
			RETURNING delivery.*
		)
		SELECT claimed.id,claimed.outbox_event_id,claimed.device_id,
			device.user_id,COALESCE(device.push_token,''),
			claimed.title,claimed.body,claimed.kind,claimed.conversation_id,
			claimed.entity_id,claimed.notification_id,claimed.status,
			claimed.attempts,claimed.next_attempt_at,claimed.lease_token,
			claimed.locked_until,claimed.created_at,claimed.delivered_at,
			claimed.dead_lettered_at,claimed.last_error_class
		FROM claimed
		JOIN devices AS device ON device.id=claimed.device_id
		ORDER BY claimed.next_attempt_at,claimed.id`, limit, leaseToken)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := make([]domain.PushDelivery, 0, limit)
	for rows.Next() {
		var delivery domain.PushDelivery
		if err := rows.Scan(
			&delivery.ID, &delivery.OutboxEventID, &delivery.DeviceID,
			&delivery.UserID, &delivery.PushToken, &delivery.Title, &delivery.Body,
			&delivery.Kind, &delivery.ConversationID, &delivery.EntityID,
			&delivery.NotificationID, &delivery.Status, &delivery.Attempts,
			&delivery.NextAttemptAt, &delivery.LeaseToken, &delivery.LockedUntil,
			&delivery.CreatedAt, &delivery.DeliveredAt, &delivery.DeadLetteredAt,
			&delivery.LastErrorClass,
		); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

func (s *Store) WithPushDeliveryLease(
	ctx context.Context,
	id int64,
	leaseToken uuid.UUID,
	deliver func(context.Context, domain.PushDelivery) error,
) error {
	if id < 1 || leaseToken == uuid.Nil || deliver == nil {
		return domain.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockAccountDeliveryBarrierShared(ctx, tx); err != nil {
		return err
	}
	var delivery domain.PushDelivery
	err = tx.QueryRow(ctx, `
		SELECT delivery.id,delivery.outbox_event_id,delivery.device_id,
		       device.user_id,COALESCE(device.push_token,''),
		       delivery.title,delivery.body,delivery.kind,delivery.conversation_id,
		       delivery.entity_id,delivery.notification_id,delivery.status,
		       delivery.attempts,delivery.next_attempt_at,delivery.lease_token,
		       delivery.locked_until,delivery.created_at,delivery.delivered_at,
		       delivery.dead_lettered_at,delivery.last_error_class
		FROM push_deliveries AS delivery
		JOIN devices AS device ON device.id=delivery.device_id
		WHERE delivery.id=$1 AND delivery.status='pending' AND delivery.lease_token=$2
		FOR SHARE OF delivery,device`, id, leaseToken).Scan(
		&delivery.ID, &delivery.OutboxEventID, &delivery.DeviceID,
		&delivery.UserID, &delivery.PushToken, &delivery.Title, &delivery.Body,
		&delivery.Kind, &delivery.ConversationID, &delivery.EntityID,
		&delivery.NotificationID, &delivery.Status, &delivery.Attempts,
		&delivery.NextAttemptAt, &delivery.LeaseToken, &delivery.LockedUntil,
		&delivery.CreatedAt, &delivery.DeliveredAt, &delivery.DeadLetteredAt,
		&delivery.LastErrorClass,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := deliver(ctx, delivery); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishPushDelivery(
	ctx context.Context,
	id int64,
	leaseToken uuid.UUID,
	result string,
	nextAttemptAt time.Time,
	errorClass string,
) error {
	switch result {
	case domain.PushDeliveryPending, domain.PushDeliveryDelivered,
		domain.PushDeliveryInvalidToken, domain.PushDeliveryDeadLetter,
		domain.PushDeliveryCanceled:
	default:
		return domain.ErrInvalid
	}
	if nextAttemptAt.IsZero() {
		nextAttemptAt = time.Now().UTC()
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE push_deliveries
		SET status=$3,
			next_attempt_at=CASE WHEN $3='pending' THEN $4 ELSE next_attempt_at END,
			locked_until=NULL,lease_token=NULL,last_error_class=$5,updated_at=now(),
			delivered_at=CASE
				WHEN $3 IN ('delivered','invalid_token','canceled') THEN now()
				ELSE delivered_at
			END,
			dead_lettered_at=CASE WHEN $3='dead_letter' THEN now() ELSE dead_lettered_at END
		WHERE id=$1 AND status='pending' AND lease_token=$2`,
		id, leaseToken, result, nextAttemptAt, errorClass)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrConflict
	}
	return nil
}

func (s *Store) InvalidatePushDelivery(
	ctx context.Context,
	id int64,
	leaseToken, userID, deviceID uuid.UUID,
	pushToken string,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var claimedDeviceID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT device_id FROM push_deliveries
		WHERE id=$1 AND status='pending' AND lease_token=$2
		FOR UPDATE`, id, leaseToken).Scan(&claimedDeviceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		return err
	}
	if claimedDeviceID != deviceID {
		return domain.ErrConflict
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET push_token=''
		WHERE id=$1 AND user_id=$2 AND push_token=$3`, deviceID, userID, pushToken); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE push_deliveries
		SET status='invalid_token',locked_until=NULL,lease_token=NULL,
			last_error_class='invalid_token',delivered_at=now(),updated_at=now()
		WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) PrunePushDeliveries(
	ctx context.Context,
	deliveredBefore, deadLetterBefore time.Time,
	limit int,
) (int64, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return 0, domain.ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, `
		WITH candidates AS (
			SELECT delivery.id
			FROM push_deliveries AS delivery
			JOIN outbox_events AS source ON source.id=delivery.outbox_event_id
			WHERE source.published_at IS NOT NULL
			  AND ((delivery.status IN ('delivered','invalid_token','canceled')
			        AND delivery.delivered_at<$1)
			    OR (delivery.status='dead_letter' AND delivery.dead_lettered_at<$2))
			ORDER BY COALESCE(delivery.delivered_at,delivery.dead_lettered_at),delivery.id
			FOR UPDATE OF delivery SKIP LOCKED
			LIMIT $3
		)
		DELETE FROM push_deliveries AS delivery
		USING candidates
		WHERE delivery.id=candidates.id`,
		deliveredBefore, deadLetterBefore, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) PrunePublishedOutbox(
	ctx context.Context,
	publishedBefore time.Time,
	limit int,
) (int64, error) {
	if limit < 1 || limit > store.MaxRetentionPruneBatchSize {
		return 0, domain.ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, `
		WITH candidates AS (
			SELECT source.id
			FROM outbox_events AS source
			WHERE source.published_at<$1
			  AND NOT EXISTS (
				SELECT 1 FROM push_deliveries AS delivery
				WHERE delivery.outbox_event_id=source.id
			  )
			ORDER BY source.published_at,source.id
			FOR UPDATE OF source SKIP LOCKED
			LIMIT $2
		)
		DELETE FROM outbox_events AS source
		USING candidates
		WHERE source.id=candidates.id`, publishedBefore, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
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

// Store mutation lock order is global and must not be inverted:
//
//	account-delivery barrier (when external delivery is involved)
//	-> user media quota (when media totals/capabilities are involved)
//	-> all live users, sorted by UUID
//	-> conversation media quota (when media is involved)
//	-> all conversations, sorted by UUID
//	-> membership/invite/entity/media child rows.
//
// Account deletion follows the same prefix. In particular, never add a user
// lock after a conversation or child-row lock: doing so creates a cycle with
// erasure's user -> conversation -> child traversal.
func lockLiveUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	var lockedUserID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, userID,
	).Scan(&lockedUserID)
	return mapError(err)
}

func lockLiveUsers(ctx context.Context, tx pgx.Tx, userIDs ...uuid.UUID) error {
	ordered := uniqueUUIDs(userIDs)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].String() < ordered[j].String() })
	for _, userID := range ordered {
		if err := lockLiveUser(ctx, tx, userID); err != nil {
			return err
		}
	}
	return nil
}

func lockConversation(ctx context.Context, tx pgx.Tx, conversationID uuid.UUID) error {
	var lockedID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM conversations WHERE id=$1 FOR UPDATE`, conversationID,
	).Scan(&lockedID)
	return mapError(err)
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
		if pgErr.ConstraintName == "conversation_member_backend_local_disjoint" {
			return domain.ErrConflict
		}
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

func normalizeUsername(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "@")
	return strings.ToLower(trimmed)
}

func normalizeUsernameList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeUsername(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func validateUsername(value string) (string, bool) {
	normalized := normalizeUsername(value)
	if len(normalized) < 3 || len(normalized) > 30 {
		return "", false
	}
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' {
			continue
		}
		return "", false
	}
	return normalized, true
}

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
