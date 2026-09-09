# Android backend checkpoint — 2026-09-08

- Branch: feature/akhil/android-backend-support, based on main 3261688.
- Implementation is local, uncommitted and unpushed. No deployment this turn.
- User approved FCM for push only. Accounts/data remain OCI; no Android package
  name or signing fingerprint exists yet. App Links default to `[]`; FCM off.
- Implemented Android authentication/device validation, immutable device
  platform, opaque case-sensitive tokens, provider-scoped token uniqueness via
  migration 23, platform-aware durable queue claims and delivery, FCM HTTP v1
  OAuth2 provider with bounded retries/errors, and configurable assetlinks route.
- Existing iOS default platform/APNs behavior retained. No production mutation,
  DNS change, provider account creation, secret provisioning or deployment.
- Android integration guide + OpenAPI updates cover shared REST/WebSocket,
  member IDs, media, session rotation, encryption interoperability and rollout.
- Final `go test -race -json ./...` passed with the isolated PostgreSQL URL:
  476 test/subtest pass events (103 PostgreSQL), 0 failures, 11 skipped tests.
  Skips require NATS, MinIO, Redis-backed verification, or a simulator fixture;
  these external integrations were not run. FCM HTTP calls use a fake provider.
  Android API coverage includes register/login/refresh/logout/revocation,
  case-sensitive token ownership, platform isolation, REST/WebSocket chat,
  queue leases and App Links validation. No real cryptographic client test.
- `go vet ./...`, repository gofmt check, `git diff --check`, and OpenAPI YAML
  parsing passed. YAML parsing is not a complete OpenAPI semantic validation.
- Final log: /private/tmp/clixor-android-race-tests-final.jsonl.
- Verified Go 1.26.8 tools: /private/tmp/clixor-android-tools.Fpc6Yf/go/bin.
  Local Postgres 17.5 compiled from checksum-verified official source at
  /private/tmp/clixor-android-pg.odAKsl/install; disposable data directory there,
  loopback 127.0.0.1:55437, DB clixor_android_test. Server stopped after testing;
  disposable test files retained. No production data was accessed.
- Pending configuration: applicationId, Play signing SHA256, FCM project and
  service-account secret, approved OCI API-only secret mount/cohort. No real
  Android device/emulator or real FCM send has been tested; Android app not built.
