# AI Usage Log — TrustVault Secure Document Sharing

**Important:** This log records actual AI-assisted work and testing. Commit links must be added only after the corresponding changes are committed. No unverified commit hashes or test results are claimed.

## 2026-11-09 — Initial Architecture and Runnable MVP

- **Prompt:** "Give complete project according to given text and running" after providing the TrustVault RISE problem statement.
- **AI output:** Generated a Python Flask and SQLite starter application with role-based login, document upload, per-document permissions, private file storage, audit logging, admin dashboard, tests, README and threat documentation.
- **What I checked:** Ran the application locally and executed the automated authorization tests.
- **Observed result:** Five automated tests passed locally.
- **Correction:** The application was subsequently configured and deployed to PythonAnywhere.
- **Commit:** Initial project commit — add the actual GitHub commit URL.

## 2026-11-09 — Authorization and Document Access Testing

- **Prompt/request:** Asked for step-by-step help deploying and testing the TrustVault application, including owner and viewer access.
- **AI output:** Explained the owner, viewer and admin roles, document permission grants, revocation and server-side access checks.
- **What I tested:** Logged in as the owner, uploaded a document, granted read access to `viewer1`, and verified that the viewer could access the shared document.
- **Issue/limitation identified:** The MVP records `edit` as a separate permission but does not implement document-content editing.
- **Correction:** No code correction is claimed from this test. The edit limitation must remain documented.
- **Commit:** No separate authorization correction commit verified yet.

## 2026-11-09 — Permission Revocation Testing

- **Prompt/request:** Asked for guidance to verify whether a viewer loses access after the owner revokes permission.
- **AI output:** Provided a step-by-step revocation and re-login test.
- **What I tested:** Revoked `viewer1`'s permission using the owner account and checked the viewer's access again.
- **Observed result:** The viewer could no longer access the previously shared document after revocation.
- **Correction:** No code change is claimed; this entry records the live application test.
- **Commit:** No separate correction commit verified.

## 2026-11-09 — Audit Trail Integrity Verification

- **Prompt/request:** Asked how to verify the audit chain on the deployed TrustVault application.
- **AI output:** Guided the admin to open `/admin/audit-verify`.
- **What I tested:** Logged in as admin and opened the audit verification endpoint.
- **Observed result:** The deployed application displayed `Audit chain verified: 15 entries.`
- **Limitation identified:** A successful hash-chain verification does not prove protection against compromise of the audit signing key or database.
- **Correction:** No additional audit-hardening code change is claimed.
- **Commit:** No separate audit correction commit verified.

## 2026-11-09 — PythonAnywhere Deployment and Configuration

- **Prompt/request:** Asked for step-by-step guidance to deploy the Flask application on PythonAnywhere.
- **AI output:** Guided repository cloning, virtual environment creation, dependency installation, WSGI configuration, database initialization and deployment.
- **Issue identified:** The original application contained development-only fallback secret keys and demo account passwords.
- **Correction:** Generated separate strong secret values for the deployed application, configured persistent database and upload paths, and changed the four demo account passwords.
- **What I tested:** Successfully opened the deployed website, logged in as admin and owner, uploaded a document, tested viewer permissions and verified the audit chain.
- **Observed result:** The live website and tested workflows were accessible.
- **Remaining limitation:** This is a prototype deployment, not a production-hardened service. Production WSGI hosting, infrastructure hardening and further security testing remain necessary.
- **Commit:** Deployment configuration is maintained on PythonAnywhere; add a Git commit only if a corresponding repository change is made.

## Project Security Principles

- Every document request must be authorized on the server.
- Document owners control per-document grants and revocations.
- Admin access does not automatically grant document-content access.
- Revoked permissions must not authorize future requests.
- Audit integrity verification must not be confused with complete protection against tampering.
- Features and security claims must be supported by actual tests.

## Known MVP Limitations

- Document-content editing is not implemented.
- Date-based document filtering is not implemented.
- SQLite and local file storage have deployment and scaling limitations.
- Audit hash-chain verification does not replace secure external audit storage and key management.
- The project requires further security review before production use.

**Live application:** https://mahamaddela30.pythonanywhere.com

**GitHub repository:** https://github.com/mahamaddela30/TrustVault-Secure-Document-Sharing
