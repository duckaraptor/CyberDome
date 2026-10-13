# Changelog

This file records development changes made while preparing and running CyberDome locally. Runtime-generated data is listed separately from intentional source and configuration changes.

## 2026-10-12

### Fixed

- The Web UI now returns the verdict for the request it sent, instead of the newest entry in `access_decision.json`. The access request `ID` is passed through the engines as `request_id`, and node 4 waits up to 10 seconds for the matching verdict. With no verdict, access is denied (`504`, verdict `0`). This also fixes the crash on the first access request of a fresh setup.

## 2026-10-11

### Added

- Added LDAP users `bob`, `charlie`, and `foo` to `infra/openldap/bootstrap.ldif`, with `Researcher`, `Administrator`, and `Policy Administrator` LDAP groups.
- Added `Researcher` and `Administrator` client roles to `infra/keycloak/myrealm-realm.json`.
- Added the `app roles` LDAP role mapper, which maps LDAP groups in `ou=groups` to `ZeroTrustPlatform` client roles of the same name.
- Added `docs/managing-users.md`.

### Removed

- Removed the unused 2023 `Keycloak/` and `OpenLDAP/` setups, replaced by `compose.yml` and `infra/`.
- Stopped tracking runtime data: `access_requests.json`, `access_decision.json`, `auth_data.json`, `events.json`, `user_data.json`, and `ZeroTrustWebUI/instance/`. They are now git-ignored and recreated by the app.

### Changed

- `.gitignore` now covers runtime data, `.DS_Store`, `.env`, and `.venv/`, and fixes the editor-backup pattern (`*~`).

### Fixed

- `/logging` no longer crashes when `access_requests.json` doesn't exist yet.

## 2026-10-05

### Added

- Added `requirements.txt` with the Python runtime dependencies used by the project:
  - Flask;
  - Flask-OIDC;
  - Flask-SQLAlchemy;
  - p2pnetwork;
  - python-keycloak;
  - PyYAML;
  - requests; and
  - tss.
- Added executable `runAll.sh` to start the Trust Engine, Policy Engine, and Access Proxy together.
  - Starts the processes in dependency order.
  - Checks that ports `8001`, `8002`, and `8003` are available.
  - Monitors child processes and stops the full group when one exits or the launcher receives a termination signal.
- Added root `compose.yml` for a portable local identity stack containing:
  - Keycloak 26.4;
  - Postgres 16;
  - OpenLDAP;
  - phpLDAPadmin; and
  - named volumes for database and directory persistence.
- Added `infra/openldap/Dockerfile` so the LDAP bootstrap LDIF is copied into the image instead of mounted from a Colima/macOS host filesystem that prevents ownership changes.
- Added `infra/openldap/bootstrap.ldif` with:
  - the `ou=users` and `ou=groups` directory structure;
  - the local LDAP user `alice`; and
  - the `Approver` LDAP group.
- Added `infra/keycloak/myrealm-realm.json` with:
  - the `myrealm` realm;
  - the confidential `ZeroTrustPlatform` OIDC client;
  - local Flask redirect URIs and web origins;
  - `Approver`, `Security Viewer`, and `Policy Administrator` client roles;
  - the native `demo` user;
  - OpenLDAP user federation; and
  - LDAP username, first-name, last-name, and email attribute mappers.
- Added `docs/how-it-works.md` with architecture, authentication, access-decision, trust-scoring, policy, PAM, persistence, bootstrap, limitation, and troubleshooting documentation.

### Changed

- Updated `AccessProxy.py`, `TrustEngine.py`, and `PolicyEngine.py` to support both interactive and background execution.
  - Interactive runs retain their `exit` prompts.
  - Background runs wait without reading from standard input.
  - `SIGTERM` triggers graceful node shutdown.
  - Trust and Policy nodes now stop in `finally` blocks.
- Updated `ZeroTrustWebUI/keycloak_config.py` so Keycloak URL, realm, client ID, client secret, and optional admin client secret can be supplied through environment variables.
- Updated `ZeroTrustWebUI/app.py` to use the shared Keycloak URL and realm configuration instead of duplicated literals.
- Updated `README.md` with:
  - Python environment setup;
  - Colima and Compose startup commands;
  - local service URLs and development accounts;
  - engine and Web UI startup commands;
  - shutdown and volume-reset commands; and
  - a link to the detailed architecture guide.

### Fixed

- Fixed Keycloak startup failures caused by an invalid realm component export structure.
  - LDAP mappers are now nested beneath the LDAP provider through `subComponents`.
  - Unsupported `parentId` fields were removed from imported mapper representations.
- Fixed LDAP-backed Keycloak authentication returning a server error because no LDAP attribute mappers were configured.
- Added both `localhost` and `127.0.0.1` Flask callback origins to the Keycloak client configuration.
- Fixed the first-login `KeyError: 'createdTimestamp'` in the Flask home route.
  - Added tolerant Keycloak user normalization for fields that may be absent from native or federated user representations.
  - Added defaults for email-verification and TOTP flags.
  - Allowed a missing creation timestamp to be represented as `null`.
- Fixed a second first-login failure risk by handling users with no `ZeroTrustPlatform` client roles instead of indexing an empty role list.
- Completed the Python dependency declaration, replacing the previous single-package requirements file.

### Runtime-Generated State

- Running the login flow appended the local `alice` and `demo` identities to `user_data.json`.
  - This is application-generated state, not a hand-authored seed change.
  - The native `demo` representation currently has no Keycloak creation timestamp, so its persisted `created_timestamp` is `null`.
- Created and exercised the local Colima Compose stack and its named Postgres/OpenLDAP volumes.
- Applied LDAP mapper and client callback updates to the live Keycloak realm while diagnosing startup and login behavior.

### Validation Performed

- Confirmed Python 3.13 resolves every package in `requirements.txt` with pip's dry-run resolver.
- Compiled all changed Python entry points successfully.
- Validated `runAll.sh` Bash syntax, executable mode, occupied-port detection, and preservation of pre-existing processes.
- Validated Compose configuration, Keycloak realm JSON, and LDAP LDIF syntax.
- Confirmed Postgres and OpenLDAP health checks pass under the Colima Docker context.
- Confirmed Keycloak OIDC discovery returns HTTP `200` at the configured realm URL.
- Confirmed phpLDAPadmin returns HTTP `200`.
- Confirmed direct LDAP search returns the seeded `alice` user.
- Confirmed both native `demo` and federated `alice` users can obtain a Keycloak token without exposing tokens in command output.
- Confirmed Flask redirects the login route to the expected Keycloak authorization endpoint.
- Confirmed the Keycloak normalization helper handles the live `alice` and `demo` admin-API payloads.
- Validated the README link, documentation headings, Markdown fences, required sections, and Mermaid block structure.

### Files Changed

#### New Files

- `compose.yml`
- `docs/changelog.md`
- `docs/how-it-works.md`
- `infra/keycloak/myrealm-realm.json`
- `infra/openldap/Dockerfile`
- `infra/openldap/bootstrap.ldif`
- `requirements.txt`
- `runAll.sh`

#### Modified Files

- `AccessProxy.py`
- `PolicyEngine.py`
- `README.md`
- `TrustEngine.py`
- `ZeroTrustWebUI/app.py`
- `ZeroTrustWebUI/keycloak_config.py`
- `user_data.json` (runtime-generated identity records)