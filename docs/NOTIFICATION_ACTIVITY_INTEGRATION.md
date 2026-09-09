# Notification activity integration — 2026-09-09

Integrates `feature/apns-activity-coverage` with Android device/FCM support and
the iOS notification routing changes based on UI main `8a0ce8f`.

## Behavior

- Chat, expense, task, settlement, subscription and group membership changes
  enter the existing durable delivery pipeline. Regular group creation notifies
  its non-creator members; a later group add targets the added member only.
  Removal notifies remaining members excluding the actor.
- Notifications retain generic title/body in storage and at the provider.
  Names, amounts, descriptions and message contents never enter remote alerts.
  Apple may retain accepted alerts after logout: a server lease cannot retract
  those alerts. Rich previews would need a separately reviewed client design.
- iOS routing metadata includes `type`, `groupId`, `entityId`, and recipient
  `accountId`. These are pseudonymous identifiers, not authorization or secrets.
  They are visible to APNs. The matching UI verifies the recipient/session and
  current server membership before navigating. Existing iOS versions still
  receive generic copy; authorization remains server-side.
- FCM remains generic and carries only `type: activity` until an Android routing
  client exists. FCM stays disabled until actual credentials/package are set.
- Repeated membership changes have distinct realtime IDs and APNs UUIDs while
  retries of one event keep the same ID. Member-removal events and their retries
  are included in account erasure.

## Rollout

Migration 23 expands the reviewed outbox topic domain. Migration 24 scopes token
uniqueness by platform; the duplicate migration numbering was corrected before
either branch was deployed. Stop older outbox workers before producing the new
membership topic: they do not know how to translate it. Use the normal gated
deployment/backup/restore procedure, not a mixed old/new worker rollout.

No APNs credentials or Firebase project are created/enabled by merging this code.
Mock-provider tests and simulator tests do not prove Apple/Google real-device
delivery. Provider activation and foreground/background/terminated-phone checks
remain separate release gates.
