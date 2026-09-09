# Android backend integration

## Scope and readiness

Android is a second client of the existing backend, not a second database or
Firebase backend. Accounts, sessions, groups, chat records, expenses, chores,
files, and moderation remain on OCI. FCM is used only as an optional Android
notification transport; APNs continues to serve iOS independently.

This change adds Android auth/device support, provider-isolated push delivery,
case-sensitive FCM token storage, and configurable Android App Links. It does
not create an Android application, Google/Firebase project, credentials, signing
certificate, or Play Store listing. Google Sign-In is not added; Android can use
the existing email/password flow. Phone login/reset email retain their existing
provider gates. No real-device FCM delivery is claimed until the checklist below
passes. Local API tests prove transport contracts, not Android/iOS decryption.

## Shared client contract

Production REST origin: `https://clustr-api.atlanteanz.com/v1`.
Realtime: `wss://clustr-api.atlanteanz.com/v1/realtime`.
Public links: `https://clixor.atlanteanz.com`.
The versioned schema is [api/openapi.yaml](../api/openapi.yaml).

1. Send `platform: "android"` on registration, login, phone verification and
   device registration. Omitted auth platform still defaults to iOS for old
   clients. A new registration gets a server-assigned `device.id`; do not reuse
   another account's device or generate a replacement identity on every launch.
2. Example email registration:

   ```json
   {"email":"person@example.com","password":"a-long-unique-password",
    "display_name":"Person","device_name":"Pixel","platform":"android"}
   ```

   `POST /auth/register` returns `user`, `device`, and `tokens`. Reuse the returned
   `device_id` on subsequent login for that account/installation. Store secrets
   with Android Keystore-backed protection; isolate cached state by account.
3. Use `Authorization: Bearer <access_token>`. Refresh through `POST /auth/refresh`
   with `refresh_token`; refresh tokens rotate. Serialize refresh requests and
   atomically replace the pair, rather than retrying a consumed refresh token.
   Password reset, logout, and account deletion revoke sessions server-side.
4. Register/rotate the FCM token using `PUT /devices/{device_id}`:

   ```json
   {"name":"Pixel","platform":"android","push_token":"OPAQUE_CASE_SENSITIVE_TOKEN"}
   ```

   The route must match the current authenticated device. Never lowercase the
   token. Limit: 2048 printable ASCII characters, no whitespace. Omit encryption
   keys during token-only updates to preserve them. The platform of an existing
   device is immutable: trying to turn an iOS device into Android returns 409.
   A nonempty token has one owner within its provider namespace; rotation and
   cross-account installation reassignment are transactional. Tokens are not
   returned by device-list responses. Logout clears the current device token.
5. REST request/response fields use `snake_case`. Treat UUIDs as UUIDs, not
   case-sensitive strings. Relational `user_id` is authoritative for membership;
   legacy iOS-local member UUIDs are compatibility aliases, not other people.
   Use server sequence numbers/cursors and idempotent client-message UUIDs.
   Do not derive membership or access decisions from an editable metadata blob.
6. REST groups, shared entities, expenses, recurrence, settlement, chores, feeds,
   profile, search, invites, blocking, legal policy, reporting, deletion and
   media endpoints are platform-neutral. Handle 403/404/409/422/429/503 explicitly.
   Fetch `/legal/policy` and honor its actual enabled/version/eligibility fields;
   never bypass an enabled policy or mistake a network failure for disabled.
   Optional reporting and mail/phone features may be deliberately unavailable.
7. WebSocket handshake takes the same Bearer header (for example OkHttp request
   headers); never put long-lived credentials in URLs. Wait for `session.ready`,
   then process ordered events. Reconnect with bounded jitter/backoff, refresh
   auth if needed, and fetch authoritative state to close sequence gaps. Push
   delivery is not a replacement for reconnect/catch-up or unread state.
8. Follow the existing media create/upload/complete/download contract. Upload to
   the returned short-lived HTTPS URL with the returned method/headers, then
   complete the reservation. Do not attach the API Bearer token to the object
   storage host. Persist media references, not expiring signed URLs. Server
   completion performs size/checksum verification and authorization; local UI
   upload success alone does not mean a completed attachment exists.

## Chat encryption interoperability

Port and test the exact `clixor-e2ee-v1` envelope and key serialization in the
iOS `ChatE2EEManager.swift` before enabling Android encrypted chat. The backend
already exposes device identity/signed-prekey publication and atomic one-time
prekey claims. Both platforms must match curve/key encodings, KDF inputs, nonce
and ciphertext framing, signature bytes, per-device recipient wrapping, and
attachment encryption. Add shared deterministic vectors and two physical-device
tests in both directions. Do not invent a second Android-only wire protocol or
claim Signal/WhatsApp security based only on matching JSON fields.

The retained `clustr-transition-v1` format is plaintext-equivalent to the server;
base64 is not encryption. Existing-client compatibility remains, but Android
must not silently downgrade encrypted messages to it.

## Android notifications

The durable outbox now queues iOS and Android recipient devices, excluding
unauthorized recipients as before. Workers claim only platforms with a configured
provider; missing FCM credentials neither acknowledge Android work nor consume
its attempt budget. The lease re-reads the current token/platform before send.
Generic notification content is used (no chat body, names, amounts, group IDs or
media URLs). FCM receives only notification text and `type` wake-up metadata.
The Android app must fetch authorized state after receipt/tap.

The HTTP v1 provider uses the supported Go OAuth2 client, a short-lived scoped
access token, TLS, bounded timeouts, and no redirects. A 24-hour TTL allows offline
delivery; an Android notification tag identifies retries. Delivery remains
at-least-once: the client must handle duplicate notifications/events.

Only explicit FCM `UNREGISTERED` invalidates an installation token. Unknown 404,
payload `INVALID_ARGUMENT`, or `SENDER_ID_MISMATCH` do not erase valid tokens.
429/5xx failures use the existing bounded durable retry/dead-letter policy,
including `Retry-After` and a minimum one-minute quota backoff. Provider response
text and tokens are excluded from durable error classifications.

Configuration (all blank by default):

```text
CLUSTER_ANDROID_PACKAGE_NAME=<actual applicationId>
CLUSTER_ANDROID_SIGNING_SHA256=<release certificate SHA256, colon-separated>
CLUSTER_FCM_PROJECT_ID=<Google/Firebase project ID>
CLUSTER_FCM_CREDENTIALS_FILE=<read-only service-account JSON path inside API container>
```

FCM requires project, credentials file, and package together. The service account
must belong to that project and have narrowly scoped FCM send authority. Its
JSON must use the trusted `https://oauth2.googleapis.com/token` endpoint. Store
it as a non-public regular secret file, not in Git, the Android app, a URL,
logs, or a general shared volume. Do not upload private signing keys to chat.

OCI activation is a separate reviewed secret-cohort change: add the credential
to the approved Vault/runtime-secret generation and a read-only **API-only**
mount, update integrity/boot/rollback manifests, and ensure backup/mail/proxy
containers cannot read it. The current OCI deployment does not have this new
credential mount. Merely setting an arbitrary host path in `api.env` will not
make it available inside the API containers. No secret pipeline or production
provider was silently enabled in this code change.

Create an Android notification channel and request runtime notification
permission where required. Register token refresh through `onNewToken`, and
reconcile registration again after successful login. Notification+data messages
may be rendered by Android/FCM while the app is backgrounded; handle tap extras
and foreground callbacks without assuming background code always runs.

References: [FCM HTTP v1 authorization](https://firebase.google.com/docs/cloud-messaging/send/v1-api),
[FCM errors](https://firebase.google.com/docs/cloud-messaging/error-codes),
[message fields](https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages).

## Verified App Links and release gates

`GET /.well-known/assetlinks.json` serves JSON directly without authentication
or redirects. Until real signing identity exists it returns `[]`, granting no
Android app authority. Configured statements grant only the specified package
and exact SHA-256 signing fingerprints. Use the Play App Signing certificate for
Play-distributed builds, not merely the upload certificate. Do not publish debug
certificates on the production domain. Existing Apple association files are unchanged.

The Android manifest should declare `android:autoVerify="true"` for the actual
public HTTPS host and narrowly chosen routes (including the existing `/join`
invite landing route). Handle invite secrets without logging them. Confirm on
device using `adb shell pm verify-app-links --re-verify <package>` and
`adb shell pm get-app-links <package>`.
[Android association documentation](https://developer.android.com/training/app-links/configure-assetlinks).

Before enabling Android clients in production:

- Apply migration 24 through the normal backup/migration/restore-gated rollout
  (migration 23 adds the reviewed membership-removal outbox topic).
  It changes token uniqueness from token-only to `(platform, push_token)` and
  leaves existing APNs values untouched. Keep Android enrollment off until every
  replica runs compatible code. Do not run older token-normalizing writers
  against an active Android rollout; rollback requires pausing Android ingress.
- Supply the Android applicationId and actual signing fingerprint. Publish and
  verify App Links on every hostname declared in the manifest.
- Provision the FCM project/service account and reviewed OCI API-only mount.
  Test foreground/background/terminated/offline notifications, permission denied,
  token rotation, logout, account switching, and uninstall/stale-token rejection
  with a real Android device. No real delivery is verified by fake-provider tests.
- Run Android/iOS bidirectional encrypted-message and encrypted-media vectors,
  membership removal, blocked-user, reconnect, and account-deletion tests.
- Run the Android UI journeys against the shared backend once the Android app
  exists. This work does not claim emulator or physical Android app testing.
