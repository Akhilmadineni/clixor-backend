# Firebase migration

The Firebase cutover must be incremental. A flag-day migration would risk message
loss, duplicate expenses, and users being locked out.

## Data mapping

| Firebase source | Clustr destination |
| --- | --- |
| Auth user | `users`, `devices`, `sessions` |
| `users/{uid}` | `users.profile` |
| `groups/{groupId}` | `conversations` plus a `profile` entity |
| `groups/{id}/messages` | `messages` |
| Expenses | `expense` entities |
| Tasks | `task` entities |
| Files | `file` entities plus encrypted media |
| Chores | `chore` entities |
| Feed | `feed_item` entities |
| Settlements | `settlement` entities |
| Recurring templates | `recurring_expense` entities |
| Group metadata | `group_meta` entity |
| Firebase Storage | private S3 objects after client-side encryption |

## Safe sequence

1. Deploy this backend in shadow mode and establish SLOs, backups, and alerting.
2. Add backend account linking. A signed-in Firebase user exchanges a freshly
   issued Firebase ID token once; a short-lived migration endpoint verifies it
   server-side and links the new user ID. Remove that endpoint after cutover.
3. Backfill profiles, groups, membership, and non-message entities with stable IDs.
4. Ship an iOS client that reads Firebase and the new API, but writes only through
   an idempotent dual-write gateway. Compare records continuously.
5. Move realtime messaging to the new service by cohort. Clients use server
   sequence replay and preserve `client_message_id` across retries.
6. Stop Firebase writes, run a final incremental backfill, verify counts and
   checksums, then switch reads.
7. Keep Firebase read-only during a rollback window before decommissioning it.

## Legacy plaintext warning

Existing Firestore messages and Firebase Storage objects are plaintext from the
server's perspective. Copying them directly into the new stores does not make them
end-to-end encrypted.

Choose one explicit policy:

- leave legacy content in a read-only archive;
- have authorized clients download, encrypt, and re-upload it; or
- migrate it with server-side encryption and clearly label it as legacy,
  without claiming E2EE.

Do not silently describe server-side re-encryption as end-to-end encryption.

## Validation

- Compare per-user conversation membership.
- Compare entity counts and stable IDs per group.
- Compare financial totals independently from stored aggregates.
- Verify message sequence continuity and idempotency keys.
- Run restore drills before and after cutover.
- Maintain a cohort-level rollback switch until Firebase writes are disabled.
