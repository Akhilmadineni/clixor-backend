# Kubernetes reference scaffold — not production-ready

These manifests illustrate API/migration separation, probes and pod resources.
No current workflow deploys them. They are retained as design examples, not as
the next production environment or an alternative to the OCI deployment.

Do not apply them unchanged. They contain placeholder images, secret values and
hostnames; broad example egress rules; no complete managed-service/identity
integration; and no end-to-end tested deployment or rollback process. They also
do not supply PostgreSQL, Redis, NATS, an ingress controller, or secret hydration.
They must not be presented as providing HA merely because replicas/HPA are set.

The supported current path is [OCI](../oci/README.md). The proposed multi-host
environment and its acceptance gates are in the
[production migration plan](../../PRODUCTION_MIGRATION_PLAN.md). Adopt Kubernetes
only when a measured operating need justifies a separately reviewed and tested
implementation.
