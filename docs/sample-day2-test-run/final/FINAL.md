# Final output: validated remediation for juice-shop

- Branch: `guardian/20261124-085437-release-candidate` in `target/juice-shop` (local only: not merged, not pushed)
- Approval tag: `guardian-approved/20261124-085437` (annotated, created in the approver's name)
- Commit: `a31e3281ce33cd1f896beb92d0293eb9cd4de783` on top of the snapshot `3cae4785b5d2` of base `c9f99228d9d5`
- Verdict: **Verified with notes**: builds, 436 tests pass, 18 advisories resolved, nothing new introduced; sqlite3 cannot be loaded in the sandbox before or after the change (a native module is not built while install scripts are disabled), so the load check is inconclusive for it
- Advisories 53 -> 35; tests 436 passed, 0 failed
- SBOM components 533 -> 432; 0 new advisories

## Fixes in this commit

- ACT-003 Upgrade pdfkit 0.11.0 → 0.21.0 (also clears crypto-js) (approved by Claude (sandbox test run) 2026-11-24T08:54)
- ACT-004 Upgrade sqlite3 5.1.7 → 6.0.1 (also clears @tootallnate/once, tar) (approved by Claude (sandbox test run) 2026-11-24T08:54)
- ACT-005 Pin uuid to 11.1.1 with npm overrides (approved by Claude (sandbox test run) 2026-11-24T08:54)
- ACT-007 Turn off Scarf install telemetry (approved by Claude (sandbox test run) 2026-11-24T08:54)
- ACT-008 Upgrade @cyclonedx/cyclonedx-npm 4.2.1 → 6.0.0 (approved by Claude (sandbox test run) 2026-11-24T08:54)

## Files changed

- package-lock.json
- package.json

## Commits

```
commit a31e3281ce33cd1f896beb92d0293eb9cd4de783
Author: Software Supply Chain Guardian
Date:   Tue Nov 24 09:03:03 2026 +0000

Guardian fix approved by Claude (sandbox test run): ACT-003, ACT-004, ACT-005, ACT-007, ACT-008

- ACT-003 Upgrade pdfkit 0.11.0 → 0.21.0 (also clears crypto-js)
- ACT-004 Upgrade sqlite3 5.1.7 → 6.0.1 (also clears @tootallnate/once, tar)
- ACT-005 Pin uuid to 11.1.1 with npm overrides
- ACT-007 Turn off Scarf install telemetry
- ACT-008 Upgrade @cyclonedx/cyclonedx-npm 4.2.1 → 6.0.0

Approved-by: Claude (sandbox test run) <noreply@anthropic.com> (ACT-003, 2026-11-24T08:54:37+00:00)
Approval-comment: ACT-003: test of the validation pipeline
Approved-by: Claude (sandbox test run) <noreply@anthropic.com> (ACT-004, 2026-11-24T08:54:37+00:00)
Approval-comment: ACT-004: test of the validation pipeline
Approved-by: Claude (sandbox test run) <noreply@anthropic.com> (ACT-005, 2026-11-24T08:54:37+00:00)
Approval-comment: ACT-005: test of the validation pipeline
Approved-by: Claude (sandbox test run) <noreply@anthropic.com> (ACT-007, 2026-11-24T08:54:37+00:00)
Approval-comment: ACT-007: test of the validation pipeline
Approved-by: Claude (sandbox test run) <noreply@anthropic.com> (ACT-008, 2026-11-24T08:54:37+00:00)
Approval-comment: ACT-008: test of the validation pipeline
Validated-by: Software Supply Chain Guardian, sandbox run 20261124-085437
```

## Review, apply, roll back (a person does this)

```bat
:: the branches and approval tags the Guardian created
git -C target\juice-shop branch --list "guardian/*" -v
git -C target\juice-shop tag -n9 --list "guardian-approved/*"
:: the commit, with who approved it
git -C target\juice-shop log -1 guardian/20261124-085437-release-candidate
git -C target\juice-shop show --stat a31e3281ce33
:: open the fixed code in its own folder, without touching your copy
git -C target\juice-shop worktree add ..\juice-shop-fixed guardian/20261124-085437-release-candidate
:: apply to your own branch when you are satisfied
git -C target\juice-shop merge --no-ff guardian/20261124-085437-release-candidate
:: or, in any clone of the project: git am 0001-Guardian-remediation.patch
:: undo after merging
git -C target\juice-shop revert -m 1 HEAD
```

Juice Shop ignores package-lock.json in git; if `merge` complains that the untracked lockfile would be overwritten, delete target\juice-shop\package-lock.json first (the branch carries the new one).
