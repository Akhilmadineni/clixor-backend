-- Tokens belong to separate provider namespaces. Preserve existing APNs values;
-- never lowercase opaque FCM tokens. Upgrade all API replicas before launching
-- Android clients (older replicas intentionally reject platform=android).
LOCK TABLE devices IN ACCESS EXCLUSIVE MODE;
DROP INDEX devices_push_token_unique;
CREATE UNIQUE INDEX devices_push_token_unique ON devices (platform, push_token)
    WHERE push_token <> '';
