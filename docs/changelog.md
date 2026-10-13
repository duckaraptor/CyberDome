# Changelog

This file records the changes we make to CyberDome, newest first. For each fix we write what we saw, what was wrong and how we fixed it. Runtime-generated data is listed separately from intentional source and configuration changes.

## 2026-10-13

### Changed: one node base class with a subclass per node

**Why:** There were two node classes. `Networking.py` in the root was used by all three engines, and `ZeroTrustWebUI/Networking.py` was an older, smaller copy used by the Web UI. Every engine carried the handlers of every other engine and worked out its job from who sent the message. The two copies had already drifted apart.

**What we changed:**

- Moved `Networking.py` to `cyberdome/networking.py` and removed `ZeroTrustWebUI/Networking.py`.
- The `Networking` base class keeps what every node shares: sending to a node by ID, receiving and dispatching by sender, catching errors, and the connection messages. Its message handlers only print.
- Added one subclass per node. Each one sets its own node ID and overrides only the handler it needs:
  - `AccessProxyNode` (1) handles requests from the Web UI.
  - `TrustEngineNode` (2) handles score requests from the Access Proxy.
  - `PolicyEngineNode` (3) handles scores from the Trust Engine.
  - `WebUINode` (4) handles verdicts from the Policy Engine and has `wait_for_access_decision`.
- The launchers, `app.py`, `node1.py` and `tests/testAP.py` create their own node type, for example `AccessProxyNode("127.0.0.1", 8001)`. The node ID is no longer passed in, so it can't be wrong.
- The engine logic itself didn't change.
- We tested the node IDs, that each class overrides only its own handler, that a crash in a handler keeps the connection working, and that `WebUINode` receives its verdict. We also ran alice's request through the real engines started by `scripts/runAll.sh`. The Web UI got the verdict for that request, with the same score and verdict as before.

### Changed: policy rules moved to `cyberdome/policy.py`

**Why:** The Policy Engine's rules (`make_access_decision`) were a method inside the network class in `Networking.py`, next to the message handling. Section 3.4 of the assignment needs at least five explicit policies, so the rules need a place of their own that is easy to read, test and extend.

**What we changed:**

- Moved `make_access_decision` from `Networking.py` to `cyberdome/policy.py` as a plain function. The rules are the same.
- Added `load_policy_configuration`, which reads `policyConfiguration.yml` on every call, like before.
- `make_access_decision` can take the configuration as an optional argument. Tests can use this instead of changing the file.
- Removed the `yaml` and `POLICY_CONFIG_FILE` imports from `Networking.py`. Only the moved method used them.
- We compared the old method and the new function on 2,772 combinations of role (including unknown roles and no role), trust score and sign-in value. They gave the same verdict every time.

### Changed: shared code moved into a `cyberdome/` package

**Why:** The trust score and the data helpers are used by both the engines and the Web UI, but they lived inside `ZeroTrustWebUI/`. The engines had to import them as `ZeroTrustWebUI.TrustAlgorithm`, and the Web UI imported the same files a different way, which needed a try/except import.

**What we changed:**

- Moved three files into a new `cyberdome/` package and renamed them to Python's usual `snake_case` style:
  - `ZeroTrustWebUI/TrustAlgorithm.py` → `cyberdome/trust_algorithm.py`
  - `ZeroTrustWebUI/trust_signal_collection.py` → `cyberdome/trust_signals.py`
  - `ZeroTrustWebUI/data_paths.py` → `cyberdome/data_paths.py`
- Everything now imports them as `cyberdome.*`. `app.py` and `synthetic_data.py` add the repo root to Python's import path, based on their own location and before their imports. The old `sys.path.insert(0,'..')` in `app.py` ran after the imports and depended on the start folder.
- `Networking.py` imports the three functions it uses by name, and imports `json` and `os` itself. Before, it got them through `import *`.
- Removed an unused `import *` from `PolicyEngine.py`.
- No calculation changed. We checked that alice's trust score stayed at 0.609, that `app.py` loads with all 25 routes, and that a request through all three engines still returns the matching verdict.

### Changed: scripts and test files have their own folders

**Why:** Five shell scripts and two test scripts were spread over the repo root and `ZeroTrustWebUI/`. Each one only worked when started from the folder it lived in.

**What we changed:**

- Moved `runAll.sh`, `runAccessProxy.sh`, `runTrustEngine.sh`, `runPolicyEngine.sh` and `ZeroTrustWebUI/runWebUI.sh` to `scripts/`. Each script now moves to the folder it needs first (the repo root, or `ZeroTrustWebUI/` for the Web UI), so it works from any folder.
- Moved `test.py` and `testAP.py` to `tests/`. They find the project code from their own location. `test.py` now takes the user ID as an argument, because its hard-coded ID belonged to a user that no longer exists.
- We tested this by starting `scripts/runAll.sh` from an unrelated folder (all three engines came up) and running `tests/test.py` from two folders (same score).

### Changed: runtime data now lives in `data/`

**Why:** The generated files were spread over the repo root and `ZeroTrustWebUI/instance/`. Each file was found by a path relative to the folder the process started in, so the Web UI had to start from `ZeroTrustWebUI/` and the engines from the repo root.

**What we changed:**

- Added `ZeroTrustWebUI/data_paths.py`, which builds every data and config path from the code's location.
- Moved `access_requests.json`, `access_decision.json`, `auth_data.json`, `events.json`, `user_data.json` and `privileged_access.db` into `data/`. The folder is created on startup and git-ignored.
- `Networking.py`, `TrustAlgorithm.py`, `trust_signal_collection.py`, `app.py` and `synthetic_data.py` now use these paths. `policyConfiguration.yml` and the demo data stay where they were, but are also found by absolute path.

### Fixed: one error made an engine stop listening

**What we saw:** After the Trust Engine crashed once, it printed nothing for later access requests, even for users with valid data. No verdict came back.

**What was wrong:** `p2pnetwork` reads each connection's messages in its own thread and passes them to our `node_message`. When our code raised an error there, nothing caught it, so the thread ended. The socket stayed open, so the Access Proxy could still send without any error, but the Trust Engine never read another message from it until a restart.

**How we fixed it:** `node_message` in both `Networking.py` and `ZeroTrustWebUI/Networking.py` now catches errors and prints the traceback with the node's name. The connection keeps working for the next message. We tested this with two real nodes: a message that crashes, then a normal one, which still arrived.

### Fixed: access requests failed with "Invalid MAC Address"

**What we saw:** Clicking a resource under **Access Protected Resources** showed "Invalid MAC Address" for every user, and the request never reached the engines.

**What was wrong:** `/resource-selection` reads the MAC address of the machine running Flask and asks macvendors.com who made it. Our Mac uses a private (randomly generated) MAC, which macOS uses for privacy and virtual network adapters also use. Random MACs have no maker, so the lookup returned `404`. The free API also returns `429` when we call it more than about once a second. In both cases `get_mac_details` (`ZeroTrustWebUI/Keycloak_functions.py`) raised an error that nothing caught.

**How we fixed it:** `get_mac_details` now returns `Unknown` when the lookup fails or takes more than 5 seconds, and prints why. The request carries on.

### Fixed: the Trust Engine crashed for users without login data

**What we saw:** The Trust Engine printed `TypeError: 'NoneType' object is not subscriptable` in `calculate_authentication_data_score`, and no verdict came back.

**What was wrong:** The trust score needs each user's login history from `auth_data.json`, and alice had none. Three things caused this:

1. Keycloak didn't save login events, because the realm never turned them on (`eventsEnabled`).
2. `store_keycloak_events` (`ZeroTrustWebUI/trust_signal_collection.py`) only asked Keycloak for events from 2023.
3. `process_events` skipped every event for a user who already had a row in `auth_data.json`, so a user's login history never updated after the first time.

**How we fixed it:**

1. `infra/keycloak/myrealm-realm.json` now sets `eventsEnabled` with `LOGIN` and `LOGIN_ERROR` events. We also turned this on in the running Keycloak through the admin API, so no reset was needed.
2. `store_keycloak_events` fetches recent events without a date range.
3. `process_events` adds every new event, matched by user and time.

## 2026-10-12

### Fixed: the Web UI returned the wrong verdict

**What we saw:** The verdict in the browser didn't always match the decision the Policy Engine printed. The first access request on a fresh setup crashed.

**What was wrong:** After sending the request to the Access Proxy, Flask straight away read the newest entry in `access_decision.json`. It didn't wait for the engines, so it usually returned the previous request's verdict, which could be for a different user. On a fresh setup the file didn't exist yet, so reading it crashed.

**How we fixed it:** The access request `ID` now travels through the Access Proxy, Trust Engine and Policy Engine as `request_id`, and comes back with the verdict. Node 4 (`ZeroTrustWebUI/Networking.py`) waits up to 10 seconds for the verdict with that ID (`ACCESS_DECISION_TIMEOUT` in `app.py`). If none arrives, Flask denies access with `504` and verdict `0`.

## 2026-10-11

### Added

- Added LDAP users `bob`, `charlie`, and `foo` to `infra/openldap/bootstrap.ldif`, with `Researcher`, `Administrator`, and `Policy Administrator` LDAP groups.
- Added `Researcher` and `Administrator` client roles to `infra/keycloak/myrealm-realm.json`.
- Added the `app roles` LDAP role mapper, which maps LDAP groups in `ou=groups` to `ZeroTrustPlatform` client roles of the same name.

### Removed

- Removed the unused 2023 `Keycloak/` and `OpenLDAP/` setups, replaced by `compose.yml` and `infra/`.
- Stopped tracking runtime data: `access_requests.json`, `access_decision.json`, `auth_data.json`, `events.json`, `user_data.json`, and `ZeroTrustWebUI/instance/`. They are now git-ignored and recreated by the app.

### Changed

- `.gitignore` now covers runtime data, `.DS_Store`, `.env`, and `.venv/`, and fixes the editor-backup pattern (`*~`).

### Fixed: `/logging` crashed on a fresh setup

**What was wrong:** The page opened `access_requests.json` without checking that it exists. After we stopped tracking the runtime files in git, a fresh clone has no such file until the first access request.

**How we fixed it:** The page shows an empty list when the file doesn't exist yet.

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