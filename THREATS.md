# THREATS.md — TrustVault

This is an honest MVP threat register. Re-test every item against the deployed build and update status with evidence.

| Threat / attack | Mitigation in this MVP | Test / remaining risk |
|---|---|---|
| User changes document UUID in URL (IDOR) | `can_read()` checks owner or an explicit per-document grant on every detail/download request. | `test_other_user_cannot_view_or_download`; keep tests coupled to real routes. |
| Viewer calls upload endpoint directly | Role decorator protects POST `/upload` on server. | `test_viewer_cannot_upload`. |
| Non-owner grants/revokes access | Grant and revoke routes compare document owner ID with current user. | Add/retain negative tests for both routes. |
| Revoked user reuses old URL | Grant row is deleted; every subsequent request re-queries grants. | `test_revoke_takes_effect_immediately`. A copy already downloaded cannot be recalled. |
| File path traversal / guessed storage path | Random server-generated storage name; user filename never becomes a filesystem path; files are outside static. | Test malicious filenames and verify storage path remains under private directory. |
| Malicious upload / extension spoof | Extension allowlist, size cap, basic file signature checks, random stored name. | Signature checks are not antivirus or full parser validation. Consider malware scanning and content disarm/reconstruction for production. |
| CSRF on state-changing forms | Session CSRF token checked on every POST. SameSite=Lax cookie. | Add automated tests for missing/invalid CSRF. |
| Password disclosure / weak passwords | Werkzeug password hashing; admin-created accounts require 12+ character password. | Demo passwords are public in README and must never be used on a public deployment. No MFA or breached-password check. |
| Session theft / fixation | Session cleared on successful login; HttpOnly and SameSite cookies; Secure configurable. | HTTPS and `COOKIE_SECURE=1` required in production; no MFA/device controls. |
| Audit record alteration | HMAC hash chain links each event to previous hash; admin can verify chain. | Key stored as environment secret, not in DB. A privileged attacker who obtains both DB write access and key can forge history. For stronger evidence, export/sign checkpoints to independent append-only storage/WORM. |
| Audit omissions / denied access | Login success/failure and denied document detail/download attempts are recorded; successful upload/download/permission/deletion events recorded. | Some malformed/blocked requests are not logged. Add central security event middleware and alerting for production. |
| Admin account compromise | Admin sees audit and user metadata, not document content by default. | No MFA, approval workflow, or privileged-action alerting in MVP. |
| Database or host compromise | Parameterized SQL and private storage paths. | Host/root compromise can expose files and keys. Use encryption at rest, backups, least-privilege service account and managed secrets. |
| Search leaks metadata | Dashboard SQL limits rows to owned/granted documents. | Re-check every new search/export/API endpoint with the same authorization policy. |
| Concurrent grant/revoke/download race | Each request checks the current grant in SQLite. | A download already authorized and in progress may finish during revocation; already downloaded copies cannot be recalled. |
| Availability / brute force | Upload cap and generic login error. | No rate limiting, lockout, quota, malware scanning, backup/restore or monitoring yet. Add before production. |

## Permission model
- `admin`: manage accounts and inspect audit metadata; no implicit access to document bytes.
- `owner`: upload, view/download, grant/revoke named-user read/edit access, and soft-delete own documents.
- `viewer`: view/download only when explicitly granted `read` or `edit`.
- `edit`: grant is represented and enforced as an access grant, but content editing is intentionally not implemented in this MVP. Do not describe it as a working edit feature.

## Design decisions / accepted limitations
- No folder inheritance or group grants: explicit per-document grants are easier to reason about and test.
- No public file URLs: all downloads pass through an authenticated route.
- Revocation affects future server requests immediately, not files already downloaded or in-flight transfers.
- Hash-chain audit is tamper-evident only while the HMAC key remains secret. It is not equivalent to independent immutable/WORM storage.
- Soft delete removes visibility and grants but retains the file bytes for recovery; a production retention/purge policy is needed.
- The app is a challenge MVP, not a certified secure document-management product.
