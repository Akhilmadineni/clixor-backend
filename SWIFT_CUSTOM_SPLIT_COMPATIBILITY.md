# Swift custom-split compatibility — 2026-09-07

Live simulator validation reproduced an invalid-fields response for an expense
using the group's default/custom split. Foundation encodes `[UUID: Double]` as
alternating UUID and number entries, for example:

```json
{"custom_amounts":["12345678-1234-4234-9234-123456789ABC",30]}
```

The participant validator accepted only an object. It now accepts both that
established Swift representation and UUID-keyed objects without rewriting stored
payloads or changing response formats. Existing iOS readers remain compatible.
Both formats require nonempty collections, canonical UUIDs, numeric nonnegative
amounts, distinct normalized identities and current ACL membership. Odd-length
arrays, removed users, malformed entries, and duplicate identities are rejected.

Regression tests cover both representations, legacy local IDs, and rejection
cases. No migration, auth bypass, or production configuration change is needed.

Deployment is separately blocked: GitHub's repository runner inventory currently
contains only the old NAS x64 runner, not the OCI ARM64 runner requested by the
production workflow. Until this fix deploys, live custom-split UI tests still fail;
passing local/CI validation must not be reported as a production E2E pass.
