# Legal publication and implementation checklist

Status: **DRAFT — NOT EFFECTIVE — NOT APPROVED FOR PUBLICATION**

Reviewed: September 7, 2026

Draft version: `2026-09-07-draft-1`

This is a scoped engineering and legal-review checklist, not an exhaustive survey of every U.S. state or a finding that every listed law applies. Akhil Madineni and qualified U.S. counsel must confirm applicability, business facts, and enforceability before publication. Terms alone do not satisfy privacy, child-safety, security, or app-store obligations.

## 1. What is law, conditional law, or a platform requirement?

| Area | Applicability and action | Primary source |
| --- | --- | --- |
| Truthful privacy/security representations | Broad baseline: do not promise privacy, security, deletion, or functionality that actual operations do not deliver. Confirm facts before publishing. | [FTC app marketing guidance](https://www.ftc.gov/business-guidance/resources/marketing-your-mobile-app-get-it-right-start), [FTC app security guidance](https://www.ftc.gov/business-guidance/resources/app-developers-start-security) |
| California online privacy notice | CalOPPA can apply to a commercial online service collecting California consumers' personal information without CCPA's business-size threshold. Disclose collection/sharing categories, an existing review/correction process, material-change notice, effective date, and applicable tracking disclosures. | [California BPC §22575](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=22575.&lawCode=BPC) |
| State comprehensive privacy laws | Conditional: assess users' states, revenue, processing volume, data uses, exemptions, and sensitive/minor data. CCPA/CPRA is not automatically applicable merely because an app exists; being below its thresholds is not a universal exemption from other laws. | [California AG CCPA guidance](https://oag.ca.gov/privacy/ccpa), [CPPA adjusted monetary thresholds](https://privacy.ca.gov/laws-and-regulations/monetary-thresholds-in-the-ccpa/) |
| Children under 13 | COPPA covers child-directed services and general-audience services with relevant actual knowledge of under-13 collection. A “13+” statement alone does not resolve this. Assess audience, knowledge escalation, deletion, and any required parental consent. | [FTC COPPA FAQ](https://www.ftc.gov/business-guidance/resources/complying-coppa-frequently-asked-questions), [FTC rule amendment announcement](https://www.ftc.gov/news-events/news/press-releases/2025/01/ftc-finalizes-changes-childrens-privacy-rule-limiting-companies-ability-monetize-kids-data) |
| Nonconsensual intimate imagery | Conditional on covered-platform status. TAKE IT DOWN Act §3 is effective May 19, 2026. Covered platforms need accessible notice/removal intake and removal within 48 hours of valid notice, including reasonable efforts concerning known identical copies. | [FTC compliance guide](https://www.ftc.gov/business-guidance/resources/complying-take-it-down-act), [Public Law 119-12, §3](https://www.congress.gov/119/plaws/publ12/PLAW-119publ12.pdf) |
| Copyright safe harbor | Conditional protection, not a requirement to register every app. If seeking the relevant §512 safe harbor, register/publish a designated agent and satisfy notice, repeat-infringer, and other statutory conditions. | [Copyright Office §512 resources](https://www.copyright.gov/512/), [agent registration](https://www.copyright.gov/onlinesp/), [17 U.S.C. §512](https://www.copyright.gov/title17/92chap5.html#512) |
| Child exploitation reporting/preservation | Counsel must assess Clixor's provider status and applicable reporting/preservation duties when qualifying facts become known. This is separate from COPPA and content takedowns; do not implement blanket destruction that conflicts with a preservation duty. | [18 U.S.C. §2258A — current-code entry](https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title18-section2258A&num=0&edition=prelim) |
| App Store distribution | Apple's platform rules, not U.S. statutes. UGC apps need filtering, reporting and timely response, user blocking, and published contacts; privacy and account deletion requirements also apply. | [Apple App Review Guidelines §§1.2, 1.5, 5.1](https://developer.apple.com/app-store/review/guidelines/) |

No “patent-ready,” “fully compliant,” or “App Store approved” representation is made. Patentability and freedom to operate are separate from these documents. Additional review is needed for state teen/sensitive-data protections, breach notification, communications privacy, consumer contracts, and any later marketing, billing, identity-verification, or financial-services features. Do not infer that the absence of a law from this table means exemption.

## 2. Code-backed facts and remaining uncertainty

The findings below record the initial baseline review, not the status of the subsequent implementation. See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the new code, rollout gates, and validation. Owner-confirmed public contact is `akhil19960323@gmail.com`; location is Texas. The residential mailing address must remain private. Urgent-report monitoring is not confirmed.

Reviewed backend base: `ffb38fc8165521f0b8ef147eac7db5e96b3f47c1`.

Reviewed UI working branch: `90c02bbd18260f3a6004398aa71977b573d0ccc0`, based on UI main `954c24de3398832621b7bec608df7a23b977d2e6`.

| Finding | Evidence | Consequence |
| --- | --- | --- |
| Existing web and native policies are separate copies | Backend `internal/httpapi/legal/index.html`; UI `Clustr/Views/ProfileView.swift` | Update together after approval; keep versioned archives to prevent drift. |
| Registration screens lack legal links/assent controls in the reviewed implementation | UI `Clustr/Views/Auth/AuthSelectionView.swift`, `SignUpView.swift` | Add conspicuous access before both email and Apple registration; do not describe existing signups as recorded acceptance. |
| Deletion removes identity/sessions while preserving shared history | Backend `internal/store/postgres/account.go`, account-deletion integration tests | Avoid promising instant deletion of every row, shared record, recipient copy, or backup. |
| Contacts can be bulk-submitted for matching | UI `ContactPickerView.swift` → `AppUsersService.fetchRegisteredPhones` → backend service | Explain nonuser number processing; review minimization, consent context, discovery protections, and retention. |
| Place queries use external providers | UI `PlaceAutocompleteService.swift`, `TripRecommendationsService.swift` | Disclose Apple/optional Google search processing; device-location permission is not needed for a typed place query. |
| Payments are outgoing links, not executed bank transfers | UI `PaymentOpener.swift`, `PaymentHandlesStore.swift` | Distinguish bookkeeping from money movement; provider eligibility and payment terms still matter. |
| Chat encryption is not app-wide encryption | Encrypted messaging implementation and shared entity model | Do not make blanket E2EE, zero-knowledge, recovery, or inability-to-access-media claims. |
| Reporting/blocking endpoints and versioned legal acceptance were not identified in the reviewed router/auth screens | Backend `internal/httpapi/server.go`; UI auth views | Treat these as implementation gaps pending a focused feature audit, not working services. |
| Infrastructure/provider settings and retention are not fully verifiable from source | OCI/Cloudflare operation plus optional providers | Operator must confirm data inventory, tracking/sale/sharing, access controls, contracts, and lifecycle settings. |

APNs enablement, SMS delivery, and outbound reset email have not been added or activated by this work. Do not advertise them as working because they appear as optional data-flow categories in the draft.

## 3. Publication gates

### Business and document review

- [ ] Confirm Akhil Madineni is the contracting operator; verify contributor/IP ownership separately without assuming the operator owns every asset.
- [ ] Fill every placeholder in the package and verify the support, privacy, and safety mailboxes using real inbound/outbound tests. Make help accessible to nonusers and people unable to sign in.
- [ ] Approve the precise tracking/sale/sharing/targeted-advertising disclosure after an SDK, network, provider-dashboard, and business-practice audit. Test DNT/GPC behavior where relevant; do not claim a signal is honored based only on text.
- [ ] Obtain counsel's review of minors' contracting capacity, guardian permission, audience classification, state-law scope, disclaimers, reporting, and proposed retention.
- [ ] Resolve every bracketed release note; set an actual effective date only when publishing. Keep draft preparation and user-acceptance timestamps distinct.

### Product and data controls

- [ ] Add always-accessible Terms and Privacy links before account creation and under Profile. Keep `https://clixor.atlanteanz.com/privacy` and `/terms` and existing legacy redirects compatible.
- [ ] Record affirmative terms acceptance with document version, account identifier, server timestamp, and flow/source where appropriate. Handle retries, offline behavior, old-client compatibility, and material-change reacceptance deliberately; do not manufacture historical assent.
- [ ] Design age/guardian handling for the chosen 13+ audience, minimizing collected data. Any screen should be tied to the appropriate onboarding decision, not a popup on every screen. Terms wording does not prove age or guardian permission. Obtain legal advice before adding ID collection.
- [ ] Add/report-verify content reporting and user blocking, with durable case IDs, staff access restrictions, safety escalation, review, and appeal handling. Do not rely on a profile-only mail link for a victim who lacks an account.
- [ ] If covered by TIDA, prove the 48-hour workflow with timed test cases, weekend coverage, nonuser intake, duplicate handling, content-cache invalidation, and audit evidence. Keep copyright counter-notices separate from safety requests.
- [ ] Establish an applicable child-exploitation reporting and preservation process with counsel. Staff should use a secure, approved workflow rather than downloading suspected illegal imagery into development tools.
- [ ] If relying on DMCA protection, register the agent, publish matching details, implement repeat-infringer handling, and test notices/counter-notices and applicable deadlines.
- [ ] Define privacy request verification, access/correction/export/deletion, agent requests, appeals, exceptions, response deadlines, and escalation. Choose request methods appropriate to applicable law.
- [ ] Establish enforced retention periods by category: accounts, shared records, media, discovery inputs, auth/security logs, support reports, backups, and legal holds. Verify restoration reapplies deletion records and media cleanup retries do not silently fail.
- [ ] Review credentials, access logs, secrets, backup encryption, breach-response procedures, and vendor agreements. A privacy policy does not replace reasonable security controls.
- [ ] Align App Store privacy disclosures and permission explanations with observed device/network behavior. Group subscription tracking must not be mislabeled as app-store billing.
- [ ] Preserve existing legal-page design attribution and contributor notices when integrating the approved wording. Keep app-store license terms distinct from service terms; obtain separate review before replacing Apple's standard license with a custom EULA.

## 4. Release validation to run after implementation

These are future acceptance tests, **not a claim that this documentation task implemented or passed them**:

1. Fresh-install simulator/device: open both notices before email and Apple signup; confirm readable text, accessible controls, no login requirement, correct version, and recorded affirmative acceptance.
2. Returning user: no recurring age prompt; material-change agreement appears only when needed; declined or failed acceptance is not recorded as successful.
3. Nonuser/browser: submit a harmless safety fixture without logging in; confirm receipt time/case ID, authorized triage, response, and removal from every applicable access path. Do not upload real harmful content for testing.
4. Two test users: blocking/reporting affects the intended communications without exposing private reports or giving the reporter authority to delete unrelated data.
5. Isolated test environment: delete a test account, verify token revocation and lookup removal, shared-history anonymization, media cleanup, and a backup/restore that does not resurrect it.
6. Privacy request: verify appropriate identity checks, access/correction/export behavior, exceptions, agent handling, and appeals without leaking another member's data.
7. Verify web/native text parity and the `/privacy`, `/terms`, `/legal`, and legacy redirect responses; scan the release artifacts for placeholders and draft markers.

No production user data, reports, accounts, DNS, provider registrations, or deployments should be changed merely to validate draft text.
