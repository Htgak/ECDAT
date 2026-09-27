# ECDAT engineering handoff

Last updated: September 27, 2026  
Workspace: `D:/Projects/SIH-Main`  
Primary documentation: [README.md](README.md)  
Review decisions: [review.md](review.md)

## September 27 - environment-only administrator configuration

Administrator provisioning and password changes now require editing root `.env`. Removed the batch credential helper and the Python command that wrote admin credentials. Normal users are still managed from `/admin/users`. Restart the native backend or recreate Docker services after editing `.env`. Existing credentials and evidence were not changed.

## September 27 - gateway failure and route audit

- Observed live Docker backend repeatedly failing startup because an environment account password violates the 15-128 character requirement. Credentials were not printed, replaced or weakened. Owner must configure strong `.env` credentials and recreate Compose services.
- Added shared JSON response validation to login, account management, inventory and finding flows; reject HTML even with HTTP 200. Exports reject HTML and invalidate expired sessions. Nginx gateway failures now return JSON; syntax checked in the existing container image.
- Added anonymous/forged-token checks over every protected OpenAPI operation. Expanded isolated browser checks to route aliases, finding details, three export formats and an injected HTML login failure.
- Expanded `.gitignore` for test artifacts, caches, logs and local scan reports. No live evidence was deleted.
- Verification: 177 backend tests passed (one upstream test-client deprecation warning), frontend lint/build passed and nginx syntax validated. Isolated browser checks passed across 56 route/viewport/theme combinations, HTML gateway failure handling, finding details, three exports, admin management and account isolation. External repository/decompiler behavior remains fixture-tested rather than a guarantee for every external input. Live Docker remains blocked by invalid environment credentials until the owner updates them and recreates services.

## September 27 - admin routes and themes

- Account management uses `/admin/users`, with redirects from `/admin` and `/users`; sidebar and header identify Administration. Normal-user denial and existing backend role enforcement remain in place.
- Added a sun/moon toggle on login and workspace headers. System preference is used initially, with browser-local persistence and early theme initialization to prevent a theme flash. Light-theme tokens cover forms, tables, navigation, risk badges, buttons, code and modal surfaces.
- Frontend lint/build passed; isolated browser checks passed for 28 route/viewport/theme combinations, theme persistence, legacy redirect, account creation, user isolation and admin access denial.

## September 27 - local scripts and administrator-managed users

This section supersedes earlier operator-only setup and equal-user/default-password notes.

- `setup.bat` installs dependencies, starts either local server, or runs checks. Administrator credentials are configured only by editing root `.env`. Local scripts default to `ecdat-backend/evidence_store` and honor an explicit shared `EVIDENCE_STORE_PATH`.
- `AUTH_USERNAME`/`AUTH_PASSWORD` define the administrator. The admin-only Users screen creates normal users and supports password reset and enable/disable. API role checks prevent normal users managing accounts or creating admins.
- Each stored UUID owns separate scans and exports. Admin role does not grant cross-user evidence access. Environment sync preserves IDs, revokes sessions on password/role changes and disables removed environment accounts. Fixed old-password fallback and mismatched-ID bugs in the supplied environment login code.
- SQLite role/source columns are added in-place without deleting accounts/evidence. Existing IDs are preserved. UI-created accounts have role user; optional AUTH_USERS imports cannot redefine the administrator.
- Removed admin/admin from the template and Compose defaults. Passwords require 15-128 characters. Edit `AUTH_USERNAME` and `AUTH_PASSWORD` in root `.env` before local startup when an existing `.env` has short credentials. No actual user credentials were printed or changed during development.
- Root `.env` loads independently of working directory and overrides backend `.env`; process environment variables override both. Restart after environment changes. Native and Docker evidence remain separate.
- Verification: `setup.bat install` and `setup.bat test` passed: 176 backend tests, frontend lint and production build. One upstream test-client deprecation warning remains. Batch help/error handling and admin listing from another working directory with a storage path containing spaces passed.
- Browser verification against temporary storage passed: wrong password, login/refresh/logout, admin creates a normal user, normal-user admin API/UI denial and scan isolation, plus 14 route/viewport checks without page errors or horizontal overflow. Screenshot: `ecdat-web/artifacts/admin-users-desktop.png`. Live credentials and Docker services were not changed.

Local sequence: `setup.bat`, edit root `.env`, then `setup.bat backend` and `setup.bat frontend` in separate terminals. Open http://localhost:5173 and use Users to create normal accounts.

## Previous implementation checkpoint

## Current state - prototype authentication and review follow-up

The Docker stack has two services: FastAPI and the React/nginx frontend. Scan artifacts remain filesystem-backed. Authentication is now mandatory and uses an embedded `auth.sqlite3` account/session store in the evidence volume; no PostgreSQL, queue service, ORM or OPA was reintroduced.

The cleanup proposal was assessed against actual code. Its instructions to remove login and make scanning synchronous were not followed: the user requested real authentication, and bounded background scanning/polling already supports the working flow.

### Authentication and first use

```powershell
docker compose up -d --build
docker compose exec backend uv run python -m ecdat.apps.api.auth.store create admin --legacy-owner
```

Passwords are entered interactively (15-128 characters). No live account or default password is seeded by development tooling. `--legacy-owner` assigns the former default workspace ID and grants access to preserved default/unscoped scans; other accounts get isolated UUID directories. Old guest folders remain on disk without automatic adoption or deletion.

- Salted scrypt password hashes; opaque random one-hour sessions, stored only as SHA-256 digests.
- HttpOnly/SameSite=Strict cookies; Secure configurable for HTTPS. Logout revokes server-side state; operator password reset revokes every session for the account; disable blocks existing sessions.
- No anonymous workspace mode, shared-token credential or guest UUID/header authentication. All API/export/artifact paths require authentication except session inspection/login and probes.
- Backend account scoping covers scans, finding details, recommendations, policies and exports. Caller-supplied IDs never select the authenticated account.
- Provision/reset/disable/list accounts through `python -m ecdat.apps.api.auth.store`; see README. No public registration, self-service recovery, MFA or SSO. Host administrators remain trusted.
- Origin/fetch-metadata checks and persisted per-peer/per-account login throttles. Proxy peers share the peer limit; arbitrary forwarded IP headers are not trusted.

### Cleanup and bug fixes

Removed the unreferenced SQL audit service, stale external-service dependency lock entries and broken CLI Merkle verification command. Kept structured normalization metadata, observed-vs-indicator evidence and standard report formats. Fixed CLI deduplication across distinct source locations, restored rejection of secret-bearing collector metadata in CLI projection, and corrected streamed body-limit responses to HTTP 413.

Removed guest UI/storage headers and unreliable tab-close cleanup. Preserved user evidence. Updated README, environment template and review disposition. Docker dependency installation now uses the checked-in lockfile.

### Verification

- Full backend suite after frozen dependency sync: **172 passed**, one upstream Starlette/httpx deprecation warning.
- Frontend production build and lint passed. Final authentication-only regressions passed (5 tests) after adding bounded concurrent password hashing.
- Added real-app security tests for anonymous/guest/token bypass attempts, login errors, cookies, cross-account scan/artifact/export isolation, expiry, password reset, account disabling, throttling and CSRF checks.
- Replaced stale integration/performance tests referencing deleted architecture with retained collector/report tests. Test fixtures remain outside live evidence.
- Final targeted account/workspace regressions: **14 passed**, including the additional legacy-owner isolation test (included in the full 172-test run).
- Browser verification against isolated temporary storage: wrong password, login, refresh, source scan, 12 route/viewport checks, logout and post-logout API denial passed. Screenshot: `ecdat-web/artifacts/prototype-auth-login.png`; script: `check-prototype-auth.cjs`.
- Docker build with frozen dependencies succeeded; backend is healthy and frontend is running at http://localhost:3000. Removed four orphaned legacy service containers without deleting their volumes. Live login screen checked at 390/1440 widths with no page errors or overflow; unauthenticated uploads, inventory and advisory APIs return 401. Account-management CLI help verified inside the container. No live account/password has been created; provision the first account with the command above.

### Operational limits

Use one API process for process-local scan admission/recovery. Existing decompiler integration is retained, but static results are not exhaustive runtime coverage. Context remains user-supplied; advice is not automatic source migration or measured latency/cost. Back up both authentication SQLite and evidence files consistently; there is no automatic retention purge/global storage quota. Enable TLS and Secure cookies before remote exposure.

The historical notes below describe earlier states and are superseded by this section. In particular, prior guest isolation, tab-close deletion and optional-auth claims are obsolete.

---

## Historical change notes

## September 27, 2026 — Over-Engineering Cleanup, Optional Auth & Ephemeral Guest Sessions

This update supersedes all previous references to PostgreSQL databases, background workers, OPA sidecars, Valkey/Redis, Merkle trees, and multi-tenant authentication systems.

### 1. Infrastructure Removal
- **PostgreSQL & Alembic Eliminated**: Deleted `ecdat/apps/api/database.py`, `alembic/`, `alembic.ini`, and PostgreSQL ORM model tables (`user.py`, `asset.py`, `scan.py`, `job.py`, `risk.py`, `evidence.py`, `advisory.py`, `base.py`). Retained canonical enums in `ecdat/core/model/types.py`.
- **10 Legacy DB Routers Deleted**: Removed all dead routers (`scans.py`, `assets.py`, `findings.py`, `risk.py`, `policies.py`, `exports.py`, `snapshots.py`, `audit.py`, `admin.py`, `auth.py`). The API now loads only `uploads.py`, `workspace.py`, `advisories.py`, and `access.py`.
- **OPA & Worker Daemon Removed**: Deleted the worker subsystem (`ecdat/apps/worker`) and OPA client (`ecdat/core/policy`). Policy compliance runs deterministically inline via `ecdat/core/discovery/policies.py`.
- **Merkle Trees & RFC 3161 TSA Client Removed**: Deleted `merkle.py`, `rfc3161.py`, and `snapshot.py`. Retained `envelope.py` for collector data models.
- **Correlation & Confidence Engines Removed**: Removed `core/correlation` and `core/confidence` engines; simplified CLI scan aggregation directly from collector envelopes.
- **Docker Compose Simplified**: `docker-compose.yml` stripped from 5 containers down to **2 services**: `backend` and `frontend` with a single `evidence_store` volume.

### 2. Optional Auth & Ephemeral Guest Sessions
- **Guest Access**: `WorkspaceAccess.tsx` offers a **Continue as Guest** option that requires no credentials.
- **Data Expiration on Tab Close**:
  - Guest identity is managed in tab-scoped `sessionStorage`.
  - Scans are strictly isolated to `uploads/<guest_uuid>/`.
  - When the user closes or removes the tab, `beforeunload` and `pagehide` listeners send `navigator.sendBeacon('/api/v1/session/guest/<guest_id>/cleanup')`.
  - The backend immediately wipes the temporary directory from disk.
  - Tab close automatically purges `sessionStorage`.
- **Individual Workspace Users**: Can provide `WORKSPACE_ACCESS_TOKEN` for persistent workspace discovery across sessions.
- **In-App Guest Banner**: A top banner indicates `Guest Mode — Temporary isolated session` with a **Clear data & Exit** button.

### 3. Frontend & Navigation Cleaned
- **Audit Page Removed**: Deleted `AuditPage.tsx` and redirected `/audit` to `/exports`.
- **Sidebar Cleaned**: `Sidebar.tsx` navigation updated to:
  - **WORKSPACE**: Overview (`/`), Crypto inventory (`/assets`), Discovery scans (`/scans`)
  - **GOVERNANCE**: Policy compliance (`/policies`), PQC advisories (`/advisories`), Exports & CBOM (`/exports`)

---

## September 26, 2026 — Connected workspace, UI and pipeline audit

- Fixed overflowing recommendation cards with responsive rows, grouped observations, wrapping evidence paths and readable standard links.
- Dashboard, inventory/detail, policies, suggestions, evidence and aggregate exports unified on filesystem-backed completed scans through `/api/v1/workspace`.
- Added versioned deterministic ECDAT review baseline rules (v1.0.0).
- Fixed repeated enrichment inventing missing context, distinct mode/key configurations collapsing into one identity, and DSA substring false detection in PQC algorithm names.
- Verification: full backend unit/security/integration/performance suite passed; frontend build, TypeScript, and lint passed.

---

## September 26, 2026 — Real-data recommendations and demo cleanup

- `/advisories` and its page derived suggestions from actual completed saved scans, retaining file, location, evidence, and scan links.
- Removed confirmed demo repository (`payment-gateway-service`).
- Added qualitative tradeoff explanations for post-quantum migrations (ML-KEM, ML-DSA, SLH-DSA).

---

## September 26, 2026 — Assessed discovery and AI removal

- Removed chatbot drawer, navigation action, AI remediation controls, client methods/types, and AI API router/service.
- Every new file/Git scan applies validated application-level planning context: data lifetime ($X$), migration duration ($Y$), quantum horizon ($Z$), criticality, sensitivity, exposure, and priority.
- Added binary library uploads (`.so`, `.dll`, `.dylib`, `.a`, `.jar`, `.zip`) and saved Docker/OCI/rootfs TAR inputs (`.tar`, `.gz`, `.tgz`).
- Standardized exports to CycloneDX 1.6 CBOM, SARIF 2.1.0, and CSV.

---

## Historical Notes (September 22–25, 2026)

- Prior checkpoints implemented the initial file-upload UI, Git shallow-cloning snapshot pipeline, and Tree-sitter AST collectors for Java and Python.
- Historical PostgreSQL database models, Alembic migrations, worker DAGs, and OPA sidecars created during those phases have been superseded by the September 27 cleanup.

Administrator UI update: admins land on `/admin/users`, where Add user and the account list are shown. Admin frontend URLs redirect there; scan navigation and scan creation controls are reserved for normal-user workspaces. Backend account isolation remains unchanged. The header and login page provide a labeled Light theme / Dark theme toggle. Rebuild the Docker frontend after UI changes.
