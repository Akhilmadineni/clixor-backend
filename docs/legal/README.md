# Clixor U.S. legal package

Status: **DRAFT — NOT EFFECTIVE — NOT APPROVED FOR PUBLICATION**

Prepared: September 7, 2026

Draft version: `2026-09-07-draft-1`

This package is tailored to Clixor's group messaging, shared expenses, settlements, chores, subscriptions, trips, and media features. It is a starting point for U.S. legal review, not a legal opinion or certification of compliance. There is no single set of “U.S.-approved terms” that makes an app compliant. Some obligations require working product features and staffed processes.

## Documents

- [Terms of Service](TERMS_OF_SERVICE.md)
- [Privacy Policy](PRIVACY_POLICY.md)
- [Community Guidelines](COMMUNITY_GUIDELINES.md)
- [Copyright and Safety Reports](COPYRIGHT_AND_SAFETY.md)
- [Publication checklist, implementation gaps, and primary legal sources](RELEASE_CHECKLIST.md)

## Confirmed decisions

- Operator: **Akhil Madineni**, using the owner's name pending any future business entity. This does not establish a corporation, trademark registration, or ownership of contributors' intellectual property.
- Minimum age: **13**, with parent/legal guardian permission and review of the terms for users below the age of majority where they live. A higher legal minimum, if applicable, still controls.
- Do not restore the previously removed recurring 18+ popup. The accompanying opt-in implementation records age-category and guardian-permission declarations, not verified ages or verified parental identity.
- Operator location: Texas, United States. Public support/privacy/safety email authorized by the owner: `akhil19960323@gmail.com`. Deliverability and staffed urgent-report coverage have not been verified.
- The owner expressly declined public visibility of their residential mailing address. Do not add it to policies, source, screenshots, or release artifacts. A separate appropriate agent/business address remains unresolved where needed.
- No mandatory arbitration, class-action waiver, shortened claim period, or arbitrary liability dollar cap has been added. Such choices need separate informed review.

## Publication boundary

These Markdown documents are review drafts only. They are deliberately **not embedded in the backend**, served by a public route, or substituted into the iOS app. Publishing a privacy policy with unknown contacts, unresolved tracking disclosures, or promised procedures that do not work would be misleading.

Unless an approved release file is explicitly configured, public routes `/privacy`, `/terms`, `/legal`, and `/` still use `internal/httpapi/legal/index.html`. The updated iOS Terms screen links to the canonical web notices rather than maintaining a second policy copy. Existing published wording has **not** been certified as adequate by this review.

After the checklist is satisfied, publish the approved wording at the existing hostnames and replace the native copy in the same coordinated release. Do not change the iOS production API hostname. Keep an immutable copy of each published version and its actual effective date; this draft's preparation date is not an effective date or evidence of user assent.

## Required replacements

| Placeholder | Owner must supply or approve |
| --- | --- |
| `[EFFECTIVE_DATE]` | Actual publication/effective date after review |
| `[SAFETY_REPORT_URL]` | Public, accessible reporting intake usable without an account |
| `[DMCA_AGENT_NAME]`, `[DMCA_AGENT_ADDRESS]`, `[DMCA_AGENT_PHONE]`, `[DMCA_AGENT_EMAIL]` | Actual designated agent details, matched to Copyright Office registration if seeking the relevant safe harbor |
| `[TRACKING_DISCLOSURE_REQUIRES_OPERATOR_CONFIRMATION]` | Final, accurate sale/sharing/targeted advertising, tracking, cookies, DNT, and applicable opt-out signal disclosure |

Bracketed editorial release notes are not consumer policy language. Resolve and remove them before publication. Neither a successful document check nor passing software tests establishes legal compliance.

## Validation performed

On September 7, 2026, all six documents passed local-link, nonempty-file, draft-status, and version-consistency checks. These four existing local HTTP regression tests passed using isolated test fixtures:

- `TestLegalDocumentIsPublic`
- `TestLegacyLegalHostnameRedirectsToClixor`
- `TestDeleteAccountRevokesIdentityAndPreservesSharedHistory`
- `TestDeleteAccountImmediatelyClosesRealtimeSocket`

Those checks describe the initial document-only stage. Subsequent implementation adds acceptance receipts, reporting intake/review, and blocking. See [implementation and operations](IMPLEMENTATION.md) for rollout gates, testing evidence, and remaining gaps. The prior unrelated UI E2E failures are not claimed fixed by this package.
