package verification

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/observability"
	"github.com/Akhilmadineni/clixor-backend/internal/tlsconfig"
	"github.com/redis/go-redis/v9"
)

type Policy struct {
	CodeLength       int
	ChallengeTTL     time.Duration
	ResendCooldown   time.Duration
	LockoutTTL       time.Duration
	MaxAttempts      int
	PhoneSendHourly  int
	PhoneSendDaily   int
	GlobalSendMinute int
	GlobalSendDaily  int
	AllowedPrefixes  []string
}

func DefaultPolicy() Policy {
	return Policy{
		CodeLength: 6, ChallengeTTL: 10 * time.Minute, ResendCooldown: time.Minute,
		LockoutTTL: 15 * time.Minute, MaxAttempts: 5, PhoneSendHourly: 5,
		PhoneSendDaily: 10, GlobalSendMinute: 60, GlobalSendDaily: 10_000,
	}
}

func (p Policy) Validate() error {
	if p.CodeLength < 6 || p.CodeLength > 8 {
		return errors.New("OTP code length must be between 6 and 8")
	}
	if p.ChallengeTTL < 2*time.Minute || p.ChallengeTTL > 30*time.Minute {
		return errors.New("OTP challenge TTL must be between 2m and 30m")
	}
	if p.ResendCooldown < 30*time.Second || p.ResendCooldown >= p.ChallengeTTL {
		return errors.New("OTP resend cooldown must be at least 30s and less than the challenge TTL")
	}
	if p.LockoutTTL < time.Minute || p.LockoutTTL > 24*time.Hour {
		return errors.New("OTP lockout TTL must be between 1m and 24h")
	}
	if p.MaxAttempts < 3 || p.MaxAttempts > 10 {
		return errors.New("OTP max attempts must be between 3 and 10")
	}
	if p.PhoneSendHourly < 1 || p.PhoneSendDaily < p.PhoneSendHourly ||
		p.GlobalSendMinute < 1 || p.GlobalSendDaily < p.GlobalSendMinute {
		return errors.New("OTP send limits are inconsistent")
	}
	for _, prefix := range p.AllowedPrefixes {
		if len(prefix) < 2 || prefix[0] != '+' {
			return fmt.Errorf("invalid OTP destination prefix %q", prefix)
		}
		for _, character := range prefix[1:] {
			if character < '0' || character > '9' {
				return fmt.Errorf("invalid OTP destination prefix %q", prefix)
			}
		}
	}
	return nil
}

type OTP struct {
	client           *redis.Client
	sender           SMSSender
	secret           []byte
	policy           Policy
	prefix           string
	webhookPublicKey ed25519.PublicKey
	now              func() time.Time
}

func NewOTP(ctx context.Context, rawRedisURL, caFile string, sender SMSSender, secret string, policy Policy, webhookPublicKey string) (*OTP, error) {
	if sender == nil || len(secret) < 32 {
		return nil, ErrUnavailable
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	options, err := redis.ParseURL(rawRedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse OTP Redis URL: %w", err)
	}
	if options.TLSConfig != nil {
		options.TLSConfig, err = tlsconfig.Client(caFile)
		if err != nil {
			return nil, err
		}
	}
	client := redis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect OTP Redis: %w", err)
	}
	publicKey, err := decodeWebhookPublicKey(webhookPublicKey)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	service := &OTP{
		client: client, sender: sender, secret: []byte(secret), policy: policy,
		webhookPublicKey: publicKey, now: time.Now,
	}
	service.prefix = "clustr:otp:{" + service.digest("namespace")[:16] + "}:"
	return service, nil
}

func (o *OTP) Send(ctx context.Context, phone string) error {
	if !o.destinationAllowed(phone) {
		return ErrUnavailable
	}
	code, err := randomNumericCode(o.policy.CodeLength)
	if err != nil {
		return fmt.Errorf("generate verification code: %w", err)
	}
	challengeID, err := randomToken(16)
	if err != nil {
		return fmt.Errorf("generate verification challenge: %w", err)
	}
	destinationID := o.digest("destination:" + phone)
	keys := o.keys(destinationID)
	result, err := issueChallengeScript.Run(ctx, o.client, keys.issue(),
		challengeID, o.codeDigest(phone, code), o.policy.ChallengeTTL.Milliseconds(),
		o.policy.ResendCooldown.Milliseconds(), o.policy.PhoneSendHourly,
		o.policy.PhoneSendDaily, o.policy.GlobalSendMinute, o.policy.GlobalSendDaily,
	).Result()
	if err != nil {
		observability.VerificationEvents.WithLabelValues("send", "dependency_error").Inc()
		return fmt.Errorf("reserve verification challenge: %w", err)
	}
	allowed, reason, retryAfter, err := parseScriptResult(result)
	if err != nil {
		return err
	}
	if !allowed {
		observability.VerificationEvents.WithLabelValues("send", reason).Inc()
		kind := ErrRateLimited
		if reason == "locked" {
			kind = ErrLocked
		}
		return &RetryError{Kind: kind, RetryAfter: retryAfter}
	}

	messageID, err := o.sender.SendCode(ctx, phone, code, o.policy.ChallengeTTL)
	if err != nil {
		_, _ = rollbackChallengeScript.Run(ctx, o.client, keys.rollback(), challengeID).Result()
		observability.VerificationEvents.WithLabelValues("send", "provider_error").Inc()
		return fmt.Errorf("send verification SMS: %w", err)
	}
	_, _ = attachMessageScript.Run(ctx, o.client,
		[]string{keys.challenge, o.prefix + "delivery:" + messageID},
		challengeID, messageID, (24 * time.Hour).Milliseconds(),
	).Result()
	observability.VerificationEvents.WithLabelValues("send", "accepted").Inc()
	return nil
}

func (o *OTP) Check(ctx context.Context, phone, code string) error {
	if !o.destinationAllowed(phone) || !numericCode(code, o.policy.CodeLength) {
		observability.VerificationEvents.WithLabelValues("check", "invalid").Inc()
		return ErrInvalidCode
	}
	destinationID := o.digest("destination:" + phone)
	keys := o.keys(destinationID)
	result, err := verifyChallengeScript.Run(ctx, o.client,
		[]string{keys.challenge, keys.cooldown, keys.lockout},
		o.codeDigest(phone, code), o.policy.MaxAttempts, o.policy.LockoutTTL.Milliseconds(),
	).Result()
	if err != nil {
		observability.VerificationEvents.WithLabelValues("check", "dependency_error").Inc()
		return fmt.Errorf("verify challenge: %w", err)
	}
	allowed, reason, retryAfter, err := parseScriptResult(result)
	if err != nil {
		return err
	}
	observability.VerificationEvents.WithLabelValues("check", reason).Inc()
	if allowed {
		return nil
	}
	switch reason {
	case "expired":
		return ErrExpiredCode
	case "locked":
		return &RetryError{Kind: ErrLocked, RetryAfter: retryAfter}
	default:
		return ErrInvalidCode
	}
}

func (o *OTP) Ping(ctx context.Context) error { return o.client.Ping(ctx).Err() }
func (o *OTP) Close() error                   { return o.client.Close() }

func (o *OTP) destinationAllowed(phone string) bool {
	if len(o.policy.AllowedPrefixes) == 0 {
		return true
	}
	for _, prefix := range o.policy.AllowedPrefixes {
		if strings.HasPrefix(phone, prefix) {
			return true
		}
	}
	return false
}

func (o *OTP) digest(value string) string {
	mac := hmac.New(sha256.New, o.secret)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (o *OTP) codeDigest(phone, code string) string {
	return o.digest("code:" + phone + ":" + code)
}

type otpKeys struct {
	challenge, cooldown, lockout, phoneHour, phoneDay, globalMinute, globalDay string
}

func (o *OTP) keys(destinationID string) otpKeys {
	return otpKeys{
		challenge:    o.prefix + "challenge:" + destinationID,
		cooldown:     o.prefix + "cooldown:" + destinationID,
		lockout:      o.prefix + "lockout:" + destinationID,
		phoneHour:    o.prefix + "send:phone:hour:" + destinationID,
		phoneDay:     o.prefix + "send:phone:day:" + destinationID,
		globalMinute: o.prefix + "send:global:minute",
		globalDay:    o.prefix + "send:global:day",
	}
}

func (k otpKeys) issue() []string {
	return []string{k.challenge, k.cooldown, k.lockout, k.phoneHour, k.phoneDay, k.globalMinute, k.globalDay}
}

func (k otpKeys) rollback() []string { return []string{k.challenge, k.cooldown} }

func randomNumericCode(length int) (string, error) {
	code := make([]byte, length)
	for index := range code {
		digit, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code[index] = byte('0' + digit.Int64())
	}
	return string(code), nil
}

func randomToken(length int) (string, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func numericCode(code string, length int) bool {
	if len(code) != length {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parseScriptResult(value any) (bool, string, time.Duration, error) {
	items, ok := value.([]any)
	if !ok || len(items) != 3 {
		return false, "", 0, fmt.Errorf("unexpected OTP script response %T", value)
	}
	status, ok := items[0].(int64)
	if !ok {
		return false, "", 0, fmt.Errorf("unexpected OTP script status %T", items[0])
	}
	reason, ok := items[1].(string)
	if !ok {
		return false, "", 0, fmt.Errorf("unexpected OTP script reason %T", items[1])
	}
	retryMilliseconds, ok := items[2].(int64)
	if !ok {
		if raw, stringOK := items[2].(string); stringOK {
			parsed, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil {
				return false, "", 0, parseErr
			}
			retryMilliseconds = parsed
		} else {
			return false, "", 0, fmt.Errorf("unexpected OTP retry value %T", items[2])
		}
	}
	if retryMilliseconds < 0 {
		retryMilliseconds = 0
	}
	return status == 1, reason, time.Duration(retryMilliseconds) * time.Millisecond, nil
}

var issueChallengeScript = redis.NewScript(`
local function remaining(key)
  local ttl = redis.call('PTTL', key)
  if ttl < 0 then return 0 end
  return ttl
end

if redis.call('EXISTS', KEYS[3]) == 1 then
  return {0, 'locked', remaining(KEYS[3])}
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  return {0, 'cooldown', remaining(KEYS[2])}
end

local limits = {tonumber(ARGV[5]), tonumber(ARGV[6]), tonumber(ARGV[7]), tonumber(ARGV[8])}
for index = 1, 4 do
  local current = tonumber(redis.call('GET', KEYS[index + 3]) or '0')
  if current >= limits[index] then
    return {0, 'budget', remaining(KEYS[index + 3])}
  end
end

local windows = {3600000, 86400000, 60000, 86400000}
for index = 1, 4 do
  local count = redis.call('INCR', KEYS[index + 3])
  if count == 1 then redis.call('PEXPIRE', KEYS[index + 3], windows[index]) end
end

redis.call('HSET', KEYS[1], 'challenge_id', ARGV[1], 'code_hash', ARGV[2], 'attempts', 0)
redis.call('PEXPIRE', KEYS[1], ARGV[3])
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[4])
return {1, 'reserved', 0}
`)

var rollbackChallengeScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'challenge_id') == ARGV[1] then
  redis.call('DEL', KEYS[1])
end
if redis.call('GET', KEYS[2]) == ARGV[1] then
  redis.call('DEL', KEYS[2])
end
return 1
`)

var attachMessageScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'challenge_id') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'message_id', ARGV[2])
redis.call('HSET', KEYS[2], 'status', 'queued')
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return 1
`)

var verifyChallengeScript = redis.NewScript(`
local function remaining(key)
  local ttl = redis.call('PTTL', key)
  if ttl < 0 then return 0 end
  return ttl
end

if redis.call('EXISTS', KEYS[3]) == 1 then
  return {0, 'locked', remaining(KEYS[3])}
end
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {0, 'expired', 0}
end
if redis.call('HGET', KEYS[1], 'code_hash') == ARGV[1] then
  redis.call('DEL', KEYS[1], KEYS[2])
  return {1, 'approved', 0}
end

local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if attempts >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1], KEYS[2])
  redis.call('SET', KEYS[3], '1', 'PX', ARGV[3])
  return {0, 'locked', tonumber(ARGV[3])}
end
return {0, 'invalid', 0}
`)
