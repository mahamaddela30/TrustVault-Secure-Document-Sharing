# PROMPTS.md — AI use log

**Important:** Keep this file truthful. The first entry records the actual project-generation request in this conversation. Do not invent commit hashes, test results, or AI mistakes. Add entries as you work, with the real date, actual output, specific defect you found, your correction, and the actual commit URL/hash.

## 2026-11-09 — Initial architecture and runnable MVP
- **Prompt / request:** “Give complete project according to given text and running” after providing the TrustVault RISE problem statement.
- **Produced:** Flask/SQLite application with per-document grants, private file storage, login roles, audit hash chain, upload validation, admin audit view, tests and threat documentation.
- **What I independently checked / still must check:** Run the app and tests locally. Verify IDOR denial, direct download denial, role checks, CSRF, revocation, file signature validation and audit verification. Do not claim checks passed until you run them.
- **Correction / commit:** Fill in after running and correcting the code. Add the real commit URL/hash here.

## 2026-11-09 — Authorisation review (to complete with actual evidence)
- **Prompt:** Record the exact prompt you use to review `can_read`, `can_edit`, and every document route.
- **AI output:** Record the actual suggestions.
- **What was wrong:** Record a specific incorrect or incomplete suggestion you identify; do not write “nothing”.
- **What I changed:** Record your code change and actual commit URL/hash.

## 2026-11-09 — Audit trail review (to complete with actual evidence)
- **Prompt:** Record the exact prompt you use to threat-model audit integrity, denied attempts, and verification.
- **AI output:** Record the actual suggestions.
- **What was wrong:** Record a specific gap you identify (for example, key compromise or events not centrally captured) if that is what you find.
- **What I changed:** Record your code change and actual commit URL/hash.

## 2026-11-10 — Test review (to complete)
- **Prompt:** Record the exact prompt used to review the automated authorisation tests.
- **AI output:** Record the actual output.
- **What was wrong:** Record the test gap you found by running or mutating code.
- **What I changed:** Record the actual correction and commit URL/hash.

## 2026-11-10 — Deployment review (to complete)
- **Prompt:** Record the exact prompt used to review deployment and configuration.
- **AI output:** Record the actual output.
- **What was wrong:** Record a concrete deployment/security issue found.
- **What I changed:** Record the actual correction and commit URL/hash.

## Reusable project context
- Permission rule: owner or explicit per-document grant only; admin has no automatic content access.
- Never trust hidden buttons or client-side checks; enforce authorisation on every server route.
- Do not claim a feature works until tested.
