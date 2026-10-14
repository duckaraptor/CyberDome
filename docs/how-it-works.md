# How CyberDome Works

CyberDome is a local zero-trust access-control prototype. It combines OIDC authentication, LDAP-backed identities, contextual trust scoring, role-based policy thresholds, a peer-to-peer decision pipeline, and a Flask Web UI.

This is a research and demonstration system, not a production security gateway. It uses local development credentials, JSON files for decision data, and unencrypted peer-to-peer connections on localhost.

## Architecture

```mermaid
flowchart LR
    Browser[Browser] -->|HTTP :5000| Web[Flask Web UI]
    Web -->|OIDC| KC[Keycloak :8080]
    KC -->|User federation| LDAP[OpenLDAP :389]
    KC --> PG[(Postgres)]
    Admin[phpLDAPadmin :8081] --> LDAP

    Web -->|Node 4 :8004| AP[Access Proxy<br/>Node 1 :8001]
    AP -->|Trust request| TE[Trust Engine<br/>Node 2 :8002]
    TE -->|Trust score| PE[Policy Engine<br/>Node 3 :8003]
    PE -->|Allow or deny| Web

    Web --> Data[(JSON and SQLite state)]
    TE --> Data
    PE --> Data
```

| Component | Responsibility |
| --- | --- |
| Flask Web UI | Login, resource selection, policy configuration, access logs, and privileged-access workflows |
| Keycloak | OIDC authorization, tokens, application roles, login events, and LDAP federation |
| OpenLDAP | Directory identities; the local seed includes `alice` |
| Postgres | Keycloak persistence |
| Access Proxy | Receives Web UI requests and asks for a trust evaluation |
| Trust Engine | Calculates a score from identity, authentication, account, and request context |
| Policy Engine | Applies role-specific thresholds and records an allow or deny verdict |
| phpLDAPadmin | Browser-based administration for OpenLDAP |

## Authentication Flow

1. A browser requests Flask at `http://localhost:5000`.
2. Flask-OIDC redirects the browser to the `myrealm` realm in Keycloak.
3. Keycloak authenticates a native user such as `demo` or a federated OpenLDAP user such as `alice`.
4. Keycloak redirects the browser to Flask with an authorization code.
5. Flask exchanges the code for tokens and introspects the access token.
6. The home route reads the current client role and Keycloak user/event data.
7. Normalized users are written to `data/user_data.json`, and processed authentication events to `data/auth_data.json`.

The application recognizes the Keycloak client roles `Approver`, `Security Viewer`, and `Policy Administrator`. The seeded `demo` user has the `Approver` role. LDAP authentication for `alice` works, but an application client role must be assigned before using role-dependent Web UI workflows.

## Access-Decision Flow

Every request for a protected resource (both resources, policy configuration, logging and PAM approval) goes through the decision engines before the page runs. Opening a page directly by URL takes the same path.

```
User -> Authentication -> Access Proxy -> Trust Engine -> Policy Engine -> Allow/Deny -> Resource
```

1. The user opens a protected page, for example `/resource-1`.
2. `@protected_resource` (`web/authz.py`) checks the login and asks Keycloak whether the token is still active. Otherwise: login redirect or `401`.
3. The role table in `policyConfiguration.yml` is checked as a first gate. Otherwise: `403`. (This moves into the Policy Engine with the policies of section 3.4.)
4. The Web UI builds the request record on the server (`web/request_context.py`, see Request Record below): user, roles, resource, action, time, authentication status, source IP and its location, device ID, and device type, OS and browser. It appends the record to `data/access_requests.json` with a new `ID`.
5. The Web UI's node 4 (`web/proxy_client.py`, one node shared by all requests on port `8004`) sends the record to the Access Proxy on port `8001`.
6. The Access Proxy checks the record is complete (ID, user, resource, action, authentication status), stamps it as mediated, and forwards the whole record to the Trust Engine on port `8002`. An incomplete record is rejected with a reason.
7. The Trust Engine scores this request and sends the record and score to the Policy Engine on port `8003`. If scoring fails, it sends the error instead.
8. The Policy Engine decides, writes the decision (with resource, action, trust score and reason) to `data/access_decision.json`, and sends it to node 4.
9. The page runs only if the decision is allow. Otherwise the user sees `403` with the reason. No verdict within 10 seconds gives `504`, and an unreachable Access Proxy gives `503`. Both deny access.

The response carries `X-CyberDome-Request-Id`, `X-CyberDome-Decision` and `X-CyberDome-Decided-By` headers, so each page can be traced to its decision.

The access request's `ID` travels through the engines as `request_id`, so each verdict can be matched to its request. Each node is its own class in `cyberdome/networking.py` and only handles the messages it expects. Messages are Python dictionaries wrapped with a sender ID and exchanged by `p2pnetwork` over localhost TCP connections.

## Request Record

The Web UI builds the record in `web/request_context.py`. Every value comes from something the server controls: the checked token, the page, the HTTP connection and the browser's headers. Values in a request body are never used, because the user can change them.

| Field | Source |
| --- | --- |
| `user_id`, `username`, `roles`, `authentication_status` | The token, checked with Keycloak |
| `resource`, `path`, `action` | The page and the HTTP method (`read` for GET, `write` for POST) |
| `access_request_time` | The server clock |
| `source_ip` | The HTTP connection |
| `location` | A lookup of `source_ip`, as a country code. `LOCAL` for localhost and private addresses, `Unknown` if the lookup fails |
| `device_id` | A random ID in the `cyberdome_device_id` cookie (`HttpOnly`, one year), set on the first visit |
| `new_device` | `true` until access was allowed once from this device for this user. Known devices are kept in `data/known_devices.json` |
| `browser`, `device_type`, `device_OS` | The `User-Agent` header |

Why these fields:

- The trust score should use facts about the user's own request. The original record used the Flask server's public IP, location and MAC address, so every user got the same values. These fields are removed.
- A website can't see a visitor's MAC address, because MAC addresses don't cross routers. The device ID cookie takes its place.
- The country code has the same format as the risk lists in `policyConfiguration.yml` (for example `KE`), so location rules can match.
- On localhost the location is always `LOCAL`. Tests for an unusual location fake it inside the test code, not in the app, so a user can't choose their own location.
- A cookie is a weak device identity: the user can delete or copy it. A real deployment would use device certificates or a device management (MDM) check.

## Trust Calculation

The overall score is a weighted sum of four segments:

```text
overall = identity * 0.30
        + request_context * 0.20
        + authentication * 0.25
        + account_experience * 0.25
```

### Identity

```text
identity = email_verified * 0.40
         + totp_enabled * 0.40
         + role_score * 0.20
```

Role scores are `0.9` for Policy Administrator, `0.7` for Approver, and `0.5` for other roles.

### Request context

```text
request_context = location * 0.30
                + request_time * 0.20
                + operating_system * 0.25
                + device_type * 0.25
```

Location categories and the night-time period come from `policyConfiguration.yml`. Mobile and Linux requests currently receive lower component scores than other device types and operating systems.

### Authentication

```text
authentication = sign_in_value * 0.60
               + authentication_type * 0.40
```

The field named `sign_in_risk` is currently calculated as successful authentications divided by total authentication attempts. Higher values therefore represent more successful history, despite the field name.

### Account experience

Account experience is derived from the Keycloak creation timestamp and converted to approximate 30-day months. The implementation then assigns a discrete score based on account tenure.

## Policy Decision

The Policy Engine begins with an allow verdict and changes it to deny when:

- an Approver score is below `approverThreshold`;
- a Security Viewer score is below `securityViewerThreshold`;
- a Policy Administrator score is below `adminThreshold`; or
- the sign-in value is below `signInRiskThreshold`.

Thresholds and contextual categories are configured in `policyConfiguration.yml` and can also be updated through the Web UI policy page.

## Role-Based Access to Pages

Every protected page checks the user before it runs (`web/authz.py`):

1. Not logged in: redirect to the Keycloak login.
2. Token no longer active (introspection): `401`.
3. None of the user's roles is allowed for the page's resource: `403`.

The allowed roles per resource are in the `resources` section of `policyConfiguration.yml`. The policy page rewrites this file when it saves, so keys get sorted and comments are dropped.

## Privileged Access Management

The Web UI also has a separate privileged-access workflow:

1. A requester selects approvers and submits a reason and duration.
2. The application generates a resource secret and splits it into shares with threshold secret sharing.
3. Selected approvers receive shares by email and approve or reject the request.
4. Once enough shares are supplied, the application reconstructs and validates the secret.
5. Requests and approver records are stored in `data/privileged_access.db`.

The threshold is currently calculated as 80 percent of the available approvers.

## State And Data

Most JSON and SQLite state files below are created or updated at runtime after their corresponding workflow is used.

| Path | Contents |
| --- | --- |
| `data/access_requests.json` | Context submitted by the Web UI |
| `data/access_decision.json` | Policy verdicts and trust scores |
| `data/auth_data.json` | Processed authentication events and sign-in values |
| `data/events.json` | Raw events collected from Keycloak |
| `data/user_data.json` | Normalized Keycloak identities and application roles |
| `policyConfiguration.yml` | Thresholds, location groups, and time period |
| `data/privileged_access.db` | PAM requests and approver state |
| Docker named volumes | Keycloak Postgres data and OpenLDAP data/configuration |

## Runtime Topology

| Port | Process |
| --- | --- |
| `389` | OpenLDAP |
| `5000` | Flask Web UI |
| `8001` | Access Proxy, peer node 1 |
| `8002` | Trust Engine, peer node 2 |
| `8003` | Policy Engine, peer node 3 |
| `8004` | Web UI peer node 4, started on the first protected request |
| `8080` | Keycloak under the `/auth` path |
| `8081` | phpLDAPadmin |

`scripts/runAll.sh` starts the Trust Engine, Policy Engine, and Access Proxy in dependency order. It checks ports `8001` through `8003`, monitors its child processes, and stops all three on `Ctrl+C`.

All data paths come from `cyberdome/data_paths.py` and are built from the code's location, so they don't depend on the folder a process starts in. Settings and secrets for the Web UI (Keycloak client secret, Keycloak admin login, Flask session key, optional PAM email account) come from environment variables, read by `cyberdome/settings.py`. It first loads `.env` from the repo root if it exists. `.env` is git-ignored, and `.env.example` lists every variable.

## Identity Bootstrap

`compose.yml` starts Postgres, OpenLDAP, phpLDAPadmin, and Keycloak. The first startup initializes:

- the `myrealm` Keycloak realm;
- the confidential `ZeroTrustPlatform` OIDC client;
- the three application client roles;
- the native `demo` user;
- the OpenLDAP federation provider and attribute mappers; and
- the LDAP `alice` user and `Approver` LDAP group.

Keycloak imports `infra/keycloak/myrealm-realm.json` only when `myrealm` does not already exist. OpenLDAP similarly initializes its seed only with a fresh data volume. To rebuild both from source configuration:

```bash
docker compose down -v
docker compose up -d --build
```

This command destroys all local identity data.

## Prototype Limitations

- Local peer traffic is unauthenticated and unencrypted.
- JSON files are shared mutable state without locking or transactions.
- The device ID is a cookie, so a user can delete or copy it. On localhost the location is always `LOCAL`.
- Trust scoring expects complete identity, authentication, and request records plus a numeric account timestamp.
- Pages now check roles against the resource table, but the Policy Engine's own role thresholds still don't deny users with an unknown role.
- The Web UI's secrets come from `.env`, but the identity stack's local passwords are still in `compose.yml` and `infra/` (Postgres, LDAP admin, Keycloak admin, and the seeded users). The `ZeroTrustPlatform` client secret is also in `infra/keycloak/myrealm-realm.json`, and `KEYCLOAK_CLIENT_SECRET` must match it.
- Flask debug mode and Keycloak development mode are enabled.

## Troubleshooting

### Keycloak connection refused

```bash
docker context use colima
docker compose ps -a
docker compose logs --tail=100 keycloak
curl http://localhost:8080/auth/realms/myrealm/.well-known/openid-configuration
```

The discovery request should return JSON and HTTP `200`.

### An engine port is already in use

```bash
lsof -nP -iTCP:8001-8003 -sTCP:LISTEN
```

Stop old engine processes before running `./scripts/runAll.sh` again.

### Login works but evaluation fails

Verify that the user has an application client role and matching records in `data/user_data.json`, `data/auth_data.json`, and `data/access_requests.json`. The current scoring code requires all three records.

## Main Source Files

| Path | Purpose |
| --- | --- |
| `engines/access_proxy.py` | Access Proxy process, node 1 |
| `engines/trust_engine.py` | Trust Engine process, node 2 |
| `engines/policy_engine.py` | Policy Engine process, node 3 |
| `cyberdome/networking.py` | Peer-to-peer nodes: a `Networking` base class plus `AccessProxyNode`, `TrustEngineNode`, `PolicyEngineNode` and `WebUINode` |
| `cyberdome/policy.py` | Policy rules: role thresholds and the sign-in check |
| `scripts/` | Launchers: `runAll.sh` for the three engines, `runWebUI.sh` for the Web UI, and one script per engine |
| `tests/` | Manual check scripts: `test.py` prints one user's trust score, `testAP.py` runs a stand-alone Access Proxy |
| `compose.yml` | Local identity and database stack |
| `infra/keycloak/` | Seeded Keycloak realm |
| `infra/openldap/` | OpenLDAP image and seed LDIF |
| `web/app.py` | Creates the Flask app, loads its settings and registers the pages |
| `web/authz.py` | Page checks: `@require_authentication` (login and active token) and `@require_role(resource)` (role table) |
| `cyberdome/access_rules.py` | Reads the role-to-resource table from `policyConfiguration.yml` |
| `web/extensions.py` | Shared objects: login (`oidc`), the PAM database (`db`) and the Keycloak clients |
| `web/models.py` | PAM database tables (`AccessRequest`, `Approver`) |
| `web/routes/` | The pages, one blueprint per area: `auth`, `access`, `resources`, `policy_config`, `monitoring`, `privileged_access` |
| `cyberdome/trust_algorithm.py` | Trust-score calculations |
| `cyberdome/data_paths.py` | Locations of the shared data and config files |
| `cyberdome/settings.py` | Settings and secrets from environment variables and `.env` |
| `cyberdome/trust_signals.py` | Event processing and JSON lookups |