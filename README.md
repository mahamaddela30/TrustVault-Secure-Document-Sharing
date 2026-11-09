# TrustVault — secure document sharing

A Python/Flask + SQLite starter implementation for the Snovasys RISE challenge. It is designed to be understandable and runnable locally. **Do not claim it is production-hardened**: read `THREATS.md` before deployment.

## Requirements
- Python 3.10+
- pip

## Run on Windows (PowerShell)
```powershell
cd TrustVault
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:TRUSTVAULT_SECRET = "replace-with-a-long-random-secret"
$env:TRUSTVAULT_AUDIT_KEY = "replace-with-a-different-long-random-key"
flask --app app init-db
flask --app app seed-demo
flask --app app run
```
Open http://127.0.0.1:5000

## Demo accounts (local demo only)
| Role | Username | Password |
|---|---|---|
| Administrator | admin | AdminDemo!2026Secure |
| Owner | owner1 | OwnerDemo!2026Secure |
| Viewer | viewer1 | ViewerDemo!2026Secure |
| Second viewer | viewer2 | ViewerTwo!2026Secure |

Change these passwords and remove/demo-disable accounts before any public deployment. Do not publish a live system with these credentials.

## Main behaviour
- Owner uploads and owns a document.
- Owner grants a named account `read` or `edit` permission per document.
- Viewer sees only documents they own (normally none) or those granted to them.
- Every document-detail and download request is checked on the server. A guessed UUID is not authority.
- Revocation deletes the grant; subsequent requests are denied. Already downloaded copies cannot be recalled.
- Admin can inspect accounts and the audit activity; admin does **not** automatically gain document-content access.
- Files are stored under `private_uploads/`, outside Flask's static directory, with random storage names.
- Upload allowlist: PDF, PNG, JPG/JPEG, TXT; 10 MB maximum; basic signature/content validation.

## Tests
```powershell
pytest -q
```
Tests create an isolated temporary database and upload directory.

## Routes / access summary
| Endpoint | Allowed |
|---|---|
| `GET /login`, `POST /login` | Public |
| `GET /dashboard` | Authenticated; only owned/granted documents listed |
| `POST /upload` | Owner, Admin |
| `GET /document/<id>` | Owner or named read/edit grantee |
| `GET /document/<id>/download` | Owner or named read/edit grantee |
| `POST /document/<id>/grant` | Document owner only |
| `POST /document/<id>/revoke` | Document owner only |
| `POST /document/<id>/delete` | Document owner only |
| `GET /admin`, `/admin/audit-verify`, `/admin/users` | Admin only |
| `POST /admin/users` | Admin only |

`edit` is recorded as a distinct permission for future metadata/content editing; this MVP does not expose document-content editing. Document deletion is owner-only.

## Before deployment
Set strong, unique `TRUSTVAULT_SECRET` and `TRUSTVAULT_AUDIT_KEY` environment variables; set `COOKIE_SECURE=1` behind HTTPS; use a persistent private disk and persistent database; disable debug mode; replace demo credentials; test the public URL in a private browser. The development Flask server is not a production server. Deploy behind a production WSGI server (e.g. gunicorn) and HTTPS. SQLite and local disk may not suit multi-instance hosting.
