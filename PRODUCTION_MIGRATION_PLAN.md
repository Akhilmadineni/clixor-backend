# Clixor production-environment migration plan

Status: proposal, not applied. Prepared 2026-09-07 against backend main
`ffb38fc8165521f0b8ef147eac7db5e96b3f47c1` and UI main
`954c24de3398832621b7bec608df7a23b977d2e6`.

## Decision

Move from the single-host OCI Free Tier topology to a paid, multi-host OCI
environment with managed PostgreSQL HA, a Redis-compatible HA service, replicated
NATS, private application nodes, and the existing Cloudflare entry point. Keep
the Go modular monolith, native OCI Object Storage, API contracts and iOS URL.
Do not introduce Kubernetes or split into microservices during this migration.

This minimizes simultaneous changes to identity, object storage, networking and
application behavior. The S3 adapter remains useful if a later provider change
is justified. A fresh AWS/GCP migration would also require new workload identity,
media URL/checksum contracts, data-transfer planning and operational automation;
it is a separate decision, not a prerequisite for eliminating the single host.

No account upgrade, paid resource, DNS change, data migration or production
deployment is authorized by this document. Obtain owner approval of the quoted
monthly ceiling and maintenance window before applying infrastructure.

## What exists and what is missing

| Area | Current repository/deployment model | Target |
| --- | --- | --- |
| Compute | Two API containers but one VM, disk, kernel and failure domain | At least two private application VMs in independent failure domains |
| Ingress | Cloudflare Tunnel, local Nginx, host-specific origin boundary | Two connector hosts, private health-checking LB, narrowly scoped API ingress |
| Database | PostgreSQL container and one data volume | Managed multi-node PostgreSQL with tested failover and recovery |
| Redis | Single endpoint used for OTP, abuse limits and presence | Compatible primary/standby endpoint, TLS, fail-closed outage behavior |
| Realtime | Core NATS fanout plus JetStream owner/fence KV on one node | Three NATS nodes; replicated owner/fence KV and tested fencing |
| Media | Private OCI objects with scoped upload/download capabilities | Retain bucket/object keys; add independently verified recovery/retention |
| Secrets | Scoped secret files; Vault hydration/approval code exists | Verified live Vault cohorts and per-role workload identity on every node |
| Release | CI plus a production-host self-hosted runner and local release controller | Isolated release runner; immutable artifact; per-node approval/drain/health gates |
| Recovery | Dump/offsite/restore tooling; documented 8h freshness and 4h restore objectives | Measured database PITR/DR; proposed RPO <=5m and RTO <=60m |

These describe the checked-in model, not a fresh certification of the live VM.
Inventory the actual selected release, secrets mode, backup results and runner
state before migration. APNs is explicitly deferred at the owner's request;
keep its implementation but do not enable, rotate or remove its credentials.
SMTP and Telnyx delivery also require independent configured-provider tests.

Oracle documents possible idle reclamation for Always Free compute. Its current
published A1 allowance is 1,500 OCPU-hours / 9,000 GB-hours monthly (2 OCPUs / 12 GB
equivalent), not the older 4/24 assumption. Check the actual tenancy entitlement
and trial expiry; do not change an existing VM based only on these figures.
Free capacity is not an availability strategy. [Oracle Free Tier](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)

## Target topology

```text
iOS (unchanged https://clustr-api.atlanteanz.com; WSS on same host)
  -> Cloudflare edge
  -> cloudflared A / B (separate hosts/failure domains; stable replica count)
  -> private load balancer (readiness checks, TLS, connection draining)
  -> API A / B (+ more nodes after measured capacity tests)
       -> managed PostgreSQL writer endpoint / HA replicas
       -> Redis-compatible HA primary endpoint
       -> NATS 1 / 2 / 3 with replicated owner/fence KV
       -> existing private OCI Object Storage
       -> configured outbound providers (APNs stays deferred)
```

Keep `clixor.atlanteanz.com` legal pages/universal links, the API hostname,
certificate coverage, JWT issuer, account IDs, object identifiers, and supported
production-05b payloads unchanged. Do not turn a temporary validation hostname
into a replacement iOS configuration.

Cloudflare replicas provide connection redundancy, not application-aware
load balancing. Each connector must reach the same healthy private LB backends;
do not bind each replica to one unmonitored local application. Avoid rapidly
autoscaling connectors because removing one drops its existing connections.
For independent region/origin steering later, use separately monitored tunnel
endpoints and explicitly priced Cloudflare Load Balancing.
[Cloudflare routing](https://developers.cloudflare.com/tunnel/routing/),
[replica lifecycle](https://developers.cloudflare.com/tunnel/deployment-guides/kubernetes/)

Oracle recommends at least two PostgreSQL nodes for HA, with regional placement
when protection against an availability-domain outage is required. Verify
Phoenix capacity and the selected SKU's actual availability/SLA rather than
inferring an application SLA from a database SLA.
[PostgreSQL HA](https://docs.oracle.com/en-us/iaas/Content/postgresql/high-availability.htm)

## Required engineering before provisioning

1. **Infrastructure isolation:** create a new Terraform root for paid HA, separate
   state/locking, compartment and least-privilege identities. Do not repurpose or
   destroy the existing Free Tier stack in place. Import retained resources only
   after reviewed ownership/state moves; protect database/bucket deletion.
2. **Cross-host boundary:** current OCI scripts assume fixed Docker addresses,
   local nftables, local release pointers and `/srv/clixor`. Implement private
   subnets/NSGs and an authenticated LB-to-API route without broadening the
   trusted-proxy range. Strip spoofed client-IP headers at the first trusted hop;
   prove the original client IP reaches abuse controls. No public DB/cache/NATS
   ports, public VM administration or broad metadata access.
3. **Database compatibility spike:** restore a copy into the selected managed
   PostgreSQL version, run all migrations and Postgres integration tests as the
   intended deployment role, and compare constraints, triggers, partitions,
   sequences and migration checksums. Check advisory locks, `SKIP LOCKED`,
   statement/lock timeouts, TLS verification and connection limits. Do not
   downgrade the current PostgreSQL 17 data directory or copy it between major
   versions. Managed role/extension restrictions need explicit validation.
   [Supported extensions](https://docs.oracle.com/en-us/iaas/Content/postgresql/extensions.htm)
4. **Database connections:** use a stable writer endpoint and bounded pools;
   require `max_API_replicas * pool_max + workers + migration/admin reserve`
   below the database connection budget. Start without transaction-mode PgBouncer
   until session/lock/statement behavior is proven. Test mid-transaction failover
   and retry idempotency, not just reconnecting a health check.
5. **Redis compatibility:** clients currently use `redis.NewClient(ParseURL(...))`,
   not ClusterClient/Sentinel discovery. Select a compatible stable primary
   endpoint, or implement discovery deliberately. Exercise Lua scripts and
   multi-key operations before selecting a sharded service. OTP/send budgets are
   security state: cache loss is not automatically safe; retain authenticated
   persistence where available and block OTP issuance if continuity is uncertain.
6. **NATS durability:** `internal/events/nats.go:openKV` requests file storage but
   does not set/validate replica count. Add environment-specific configuration
   and validation for three copies of both `CLIXOR_REALTIME_OWNERS` and
   `CLIXOR_REALTIME_FENCES`; retain one only in local development. Deploy three
   servers across failure domains and verify majority behavior under partition.
   Realtime payload fanout uses Core NATS; the database/outbox and client sequence
   replay remain the source of durable history. Do not describe it as a durable
   JetStream message stream. [NATS replication](https://docs.nats.io/learn/topologies/jetstream-in-a-cluster)
7. **Release controller:** local atomic symlink rollback is not a fleet release
   protocol. Add inventory, per-node immutable digest verification, lease/fence
   ownership, one-shot migration execution, readiness and drain ordering, and
   resumable partial-rollout recovery. Keep OIDC approval and separate build
   access from production-secret/runtime privileges. Never run untrusted PR code
   on a production-secret-bearing runner.
8. **Observability:** export logs/metrics off host; add traces with request IDs,
   secret/PII redaction, SLO burn alerts and a tested paging destination. Track
   reconnect rate, active sockets, outbox age, DB pool wait/locks, queue leases,
   Redis failure rate, KV quorum, disk and media completion failures.

Keep the existing `deploy/k8s` files labeled reference-only. They do not solve
these requirements, and an HPA maximum is not a capacity guarantee.

## Migration sequence and go/no-go evidence

### Phase 0 — baseline and recovery proof

- Record the deployed SHA, schema ledger, VM/disk inventory, sanitized config
  names, provider enablement, current API error rates, traffic and queue counts.
- Take an encrypted, checksum-verified backup and restore it in isolation. Test
  representative login, historical messages, expenses, memberships and media.
  Never log tokens, key contents or identifiable query results as evidence.
- Define owners: service owner approves cutover; DB owner proves consistency;
  release owner controls write fencing; incident owner owns rollback/paging.
- Produce a priced resource plan and approve the maintenance window.

### Phase 1 — isolated target

- Provision paid compute/network/data services with Terraform after approval.
  Start with two application nodes sized from measured per-replica load; do not
  infer capacity from DAU. Use dedicated data-service resources, not two Compose
  copies that each bring their own isolated database.
- Restore a sanitized snapshot into target validation. Do not enable target
  email, SMS, APNs, cleanup or notification workers against copied queues/users.
  Use unique test identities and isolated nonproduction provider destinations.
- Retain the existing media bucket in the same region for cutover; test instance
  principal authorization, object checksums, upload finalization, capability
  revocation and deletion. Do not copy stale media capability URLs into a new
  provider or region.

### Phase 2 — rehearsal and failure tests

- Prove all HTTP contracts for current UI and production commit
  `05b541e2c8ca4bf8aebc3e7f1da4f34c0d5f53f6`, including legacy transition messages.
- Test login/refresh/logout/delete races, membership revocation, pagination,
  concurrent expenses, chat ordering/idempotency, reconnect catchup and media.
- Kill an API node, disconnect a connector, fail over the DB and Redis, lose one
  NATS node, and partition the fence registry. Security-sensitive mutations must
  fail closed; reconnecting clients must not acquire stale access.
- Inject a failed migration and partial node rollout. Demonstrate a safe old
  application rollback on the compatible new schema with no automatic DB rewind.

### Phase 3 — controlled single-writer cutover

Default to a rehearsed maintenance window for the current small deployment.
Only introduce logical replication if measured dump/restore time exceeds the
approved window; that alternative must also synchronize DDL, sequences and every
mutable table/queue, and requires a separate rehearsal.

1. Enter maintenance at ingress; fence all writes (HTTP, WebSocket, background
   jobs, migrations and operator tooling), close/drain sockets, and verify no
   source writer or delivery lease can still act. Keep liveness/maintenance
   responses available. DNS switching alone does not fence existing sockets.
2. Quiesce outbox/mail/media-cleanup workers and retain pending jobs. Preserve
   mail queue encryption keys, JWT/access/refresh secrets, device IDs and provider
   configuration. Do not rotate credentials during the data move.
3. Export the final consistent DB snapshot, restore target and validate checksums,
   row counts, sampled relationships, sequences, schema ledger, message watermarks
   and pending-job states. The source must remain fenced throughout.
4. Migrate Redis security state with a tested procedure and verify TTL/budget
   continuity. If preservation cannot be proven, disable OTP and wait out all
   affected challenge/send-budget windows before re-enabling it; do not silently
   reset fraud counters. Presence can rebuild. Expire old NATS owner leases and
   prove all old owners are stopped before allowing the new control domain.
5. Start target APIs/workers with the final state. Publish the target only after
   private auth/chat/media/fencing checks pass. Change the existing Cloudflare
   hostname's origin routing; retain the hostname, not a new iOS endpoint.
6. Start one source of background deliveries only. Monitor leases, acknowledgements
   and dead letters; APNs remains disabled unless separately authorized later.
7. Run public disposable-account smoke tests and compare SLO/error/queue metrics
   through peak traffic. Hold at least 24h before closing the cutover watch and
   seven days before considering source decommission, subject to retention policy.

### Rollback boundary

Before target accepts writes, restore old ingress and unfreeze the original only
after proving target writers/workers are stopped. After target accepts writes,
the original database is stale: do **not** point traffic back to it. Prefer old
compatible application binaries against the target DB. A database rollback then
requires another write freeze plus verified reverse synchronization/restore and
an explicitly approved data-loss decision if reconciliation is impossible.
No automatic `terraform destroy`, schema downgrade or snapshot rewind.

## Acceptance and capacity targets (proposed, not achieved)

- API availability target: 99.95% monthly including deploys/maintenance, measured
  externally. This supersedes the old exclusion only after owner signoff.
- Authenticated message ACK p95 <250ms / p99 <750ms at approved peak load; durable
  outbox-to-realtime p99 <2s, excluding recipient offline time.
- Restore goal: RPO <=5m and RTO <=60m for the agreed disaster scenario. Validate
  the selected managed service's PITR/WAL export and cross-region capabilities;
  daily snapshots alone do not meet this goal. If unavailable, choose a service
  with verified PITR or an operated WAL/restore design before signing off.
- Load model: `peak RPS = DAU * requests_per_active_day / 86400 * peak_factor`.
  A planning scenario of 100k DAU, 200 requests/day and 5x peak is ~1,157 RPS;
  it is not a capacity result. Model concurrent sockets, fanout, media bytes,
  hot groups and background jobs separately.
- Benchmark representative data sizes and 2x observed peak, run a sustained soak,
  and exercise reconnect storms while one application node is unavailable.
  Scale only when one surviving failure domain can sustain the agreed load with
  measured CPU/memory/DB-I/O/connection headroom. No claim of 1m-user capacity.

## Cost and approval checklist

Get a dated quote for Phoenix before apply. Price all of: app/connector VMs,
database primary/replica/storage/backups, Redis HA, three NATS VMs/disks, private
LB, NAT/egress, object requests/storage/DR replication, logs/metrics/traces,
registry/scanning, isolated runner, optional Cloudflare LB/WAF plan, and provider
messages. Use `730 * hourly_resources + storage + requests + network + support`
as the monthly worksheet; do not treat Always Free credits or trial credits as a
permanent production subsidy. Budgets are alerts, not guaranteed spend caps;
use reviewed quotas, bounded autoscaling and an approved maximum bill.

Approval required: monthly ceiling, data residency/DR region, downtime window,
recovery objectives, retention, operational ownership and paid account changes.
Keep the small existing environment until those decisions and restore evidence
are ready. The first implementation PR should add isolated IaC and compatibility
tests, not mutate production while writing this plan.
