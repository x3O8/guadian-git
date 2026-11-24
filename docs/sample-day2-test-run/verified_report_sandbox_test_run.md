# Verified remediation report: juice-shop

Generated 2026-11-24T09:04:30+00:00

## Outcome

- Risks: 26 prioritised, **6 verified as resolved**, 20 remaining (1 accepted)
- Advisories: 53 before → 35 after; grade F (0) → F (0)
- Risk points: 1689.0 → 1295.2
- Final confidence: **High (0.81)** because the release candidate passed, with notes: builds, 436 tests pass, 18 advisories resolved, nothing new introduced; sqlite3 cannot be loaded in the sandbox before or after the change (a native module is not built while install scripts are disabled), so the load check is inconclusive for it; 436 unit tests passed in the sandbox; 4 of 15 critical/high risks verified as resolved; audit trail hash chain intact; before and after scanned with the same vulnerability source

Release candidate branch `guardian/20261124-085437-release-candidate` (a31e3281c): **Verified with notes**. builds, 436 tests pass, 18 advisories resolved, nothing new introduced; sqlite3 cannot be loaded in the sandbox before or after the change (a native module is not built while install scripts are disabled), so the load check is inconclusive for it

## Finding by finding

| Risk | Subject | Tier | Action | Decision | Status |
|---|---|---|---|---|---|
| RISK-001 | jsonwebtoken@0.4.0 | Critical (85.0) | Upgrade express-jwt 0.1.3 → 8.5.1 and jsonwebtoken 0.4.0 → 9.0.3 (also clears base64url, jws, moment) | approve by Claude (sandbox test run) | Fix failed validation: the build breaks with this change but not without it (run build:server - 2 TypeScript errors); 24 unit tests also fail |
| RISK-002 | marsdb@0.6.11 | Critical (85.0) | Replace or remove marsdb (no fixed version exists) | accept-risk by Claude (sandbox test run) | Risk accepted until 2026-12-31 |
| RISK-003 | crypto-js@3.3.0 | Critical (83.4) | Upgrade pdfkit 0.11.0 → 0.21.0 (also clears crypto-js) | approve by Claude (sandbox test run) | Verified remediation |
| RISK-004 | lodash@2.4.2 | Critical (83.4) | Upgrade sanitize-html 1.4.2 → 2.18.2 (also clears lodash) | reject by Claude (sandbox test run) | Fix rejected by reviewer |
| RISK-005 | sanitize-html@1.4.2 | Critical (83.0) | Upgrade sanitize-html 1.4.2 → 2.18.2 (also clears lodash) | reject by Claude (sandbox test run) | Fix rejected by reviewer |
| RISK-006 | jsonwebtoken@0.1.0 | High (79.0) | Upgrade express-jwt 0.1.3 → 8.5.1 and jsonwebtoken 0.4.0 → 9.0.3 (also clears base64url, jws, moment) | approve by Claude (sandbox test run) | Fix failed validation: the build breaks with this change but not without it (run build:server - 2 TypeScript errors); 24 unit tests also fail |
| RISK-007 | notevil@1.3.3 | High (79.0) | Replace or remove notevil (no fixed version exists) | escalate by Claude (sandbox test run) | Escalated to security review |
| RISK-008 | jws@0.2.6 | High (78.8) | Upgrade express-jwt 0.1.3 → 8.5.1 and jsonwebtoken 0.4.0 → 9.0.3 (also clears base64url, jws, moment) | approve by Claude (sandbox test run) | Fix failed validation: the build breaks with this change but not without it (run build:server - 2 TypeScript errors); 24 unit tests also fail |
| RISK-009 | moment@2.0.0 | High (77.0) | Upgrade express-jwt 0.1.3 → 8.5.1 and jsonwebtoken 0.4.0 → 9.0.3 (also clears base64url, jws, moment) | approve by Claude (sandbox test run) | Fix failed validation: the build breaks with this change but not without it (run build:server - 2 TypeScript errors); 24 unit tests also fail |
| RISK-010 | uuid@8.3.2 | High (77.0) | Pin uuid to 11.1.1 with npm overrides | approve by Claude (sandbox test run) | Verified remediation |
| RISK-011 | express-jwt@0.1.3 | High (76.8) | Upgrade express-jwt 0.1.3 → 8.5.1 and jsonwebtoken 0.4.0 → 9.0.3 (also clears base64url, jws, moment) | approve by Claude (sandbox test run) | Fix failed validation: the build breaks with this change but not without it (run build:server - 2 TypeScript errors); 24 unit tests also fail |
| RISK-012 | file-type@16.5.4 | High (74.2) | Upgrade file-type 16.5.4 → 22.3.0 | - | Waiting for a human decision |
| RISK-013 | tar@6.2.1 | High (72.2) | Upgrade sqlite3 5.1.7 → 6.0.1 (also clears @tootallnate/once, tar) | approve by Claude (sandbox test run) | Verified remediation |
| RISK-014 | @scarf/scarf@1.4.0 runs code when installed (telemetry) | High (68.0) | Turn off Scarf install telemetry | approve by Claude (sandbox test run) | Verified remediation |
| RISK-015 | hbs@4.4.0 | High (66.0) | Replace or remove hbs (no fixed version exists) | - | Waiting for a human decision |
| RISK-016 | base64url@0.0.6 | Medium (63.0) | Upgrade express-jwt 0.1.3 → 8.5.1 and jsonwebtoken 0.4.0 → 9.0.3 (also clears base64url, jws, moment) | approve by Claude (sandbox test run) | Fix failed validation: the build breaks with this change but not without it (run build:server - 2 TypeScript errors); 24 unit tests also fail |
| RISK-017 | 10 container images are referenced by tag, not by digest | Medium (61.0) | Pin 10 container image(s) by digest | - | Waiting for a human decision |
| RISK-018 | 9 installed packages are deprecated by their maintainers | Medium (52.0) | - | - | No action planned |
| RISK-019 | @cyclonedx/cyclonedx-npm@4.2.1 | Medium (49.0) | Upgrade @cyclonedx/cyclonedx-npm 4.2.1 → 6.0.0 | approve by Claude (sandbox test run) | Verified remediation |
| RISK-020 | 7 CI actions not SHA-pinned | Medium (48.0) | Pin 7 CI action(s) to a commit SHA | - | Waiting for a human decision |
| RISK-021 | @tootallnate/once@1.1.2 | Low (44.2) | Upgrade sqlite3 5.1.7 → 6.0.1 (also clears @tootallnate/once, tar) | approve by Claude (sandbox test run) | Verified remediation |
| RISK-022 | 36 of 56 production dependencies have no build provenance | Low (42.0) | - | - | No action planned |
| RISK-023 | cypress@16.3.0 runs code when installed (download) | Low (42.0) | Security review: install script in cypress@16.3.0 | - | Waiting for a human decision |
| RISK-024 | esbuild@0.28.2 runs code when installed (download) | Low (42.0) | Security review: install script in esbuild@0.28.2 | - | Waiting for a human decision |
| RISK-025 | glob@10.5.0 | Low (39.0) | Escalate glob for security review | - | Waiting for a human decision |
| RISK-026 | minimatch@9.0.9 | Low (39.0) | Pin minimatch to 11.0.1 with npm overrides | - | Waiting for a human decision |

## Final output: the committed fix

Branch `guardian/20261124-085437-release-candidate`, commit `a31e3281ce33` (local, not merged or pushed). Files changed: package-lock.json, package.json. Patches and fixed files: `day2/final/`.

## Audit trail

25 entries, chain intact.

## Responsible AI

- Agents 1-8 find, score and validate with deterministic tools; the LLM only explains evidence they produced.
- Every AI answer is grounding-checked: any advisory id or package@version not in the evidence gets the answer rejected.
- AI text is labelled as inference and shown next to, never mixed with, the verified evidence.
- No change is applied without a named human approval; nothing is merged, pushed or deployed automatically.
- Validation runs in a separate git worktree with dependency install scripts disabled.
- Only package names, versions, advisory text and public registry data are sent to the LLM; no secrets, tokens or source files.
- All prompts and responses are logged in day2/llm_log.jsonl; all decisions in a hash-chained audit log.
