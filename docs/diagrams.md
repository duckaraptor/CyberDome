# Diagrams

Pictures of how CyberDome works, to help the team (and readers of the report) find their way in the code. The diagrams are written in [Mermaid](https://mermaid.js.org/), so GitHub and VS Code (with a Markdown preview that supports Mermaid) draw them from the text. To change a diagram, edit the text.

Contents:

1. [Architecture](#1-architecture): the parts of the system and how they connect
2. [Logging in](#2-logging-in): what happens when a user logs in
3. [A protected request](#3-a-protected-request): the full path of one request, from the browser to the resource
4. [Policies](#4-policies): how the Policy Engine decides
5. [Trust score](#5-trust-score): how the Trust Engine scores a request
6. [Audit log](#6-audit-log): where log entries come from
7. [Code map](#7-code-map): which file does what
8. [Data files](#8-data-files): who reads and writes each file

More detail: [how-it-works.md](how-it-works.md), [trust-model.md](trust-model.md), [policies.md](policies.md) and [audit-log.md](audit-log.md).

## 1. Architecture

The user only talks to the Web UI. The Web UI asks Keycloak who the user is, and asks the decision engines whether a request is allowed. The engines are three separate Python processes that send each other messages over local TCP connections (`p2pnetwork`).

```mermaid
flowchart LR
    user(["User's browser"])

    subgraph identity["Identity stack (Docker)"]
        keycloak["Keycloak<br/>port 8080<br/>login, tokens, events"]
        ldap["OpenLDAP<br/>port 389<br/>users and groups"]
        postgres[("Postgres<br/>Keycloak's data")]
    end

    subgraph webui["Web UI (Flask, port 5000)"]
        pages["Pages<br/>web/routes/"]
        authz["Access checks<br/>web/authz.py"]
        node4["Node 4<br/>port 8004<br/>web/proxy_client.py"]
    end

    subgraph engines["Decision engines (Python processes)"]
        ap["Access Proxy<br/>node 1, port 8001"]
        te["Trust Engine<br/>node 2, port 8002"]
        pe["Policy Engine<br/>node 3, port 8003"]
    end

    data[("data/<br/>requests, audit log,<br/>login history, devices")]
    config[/"policyConfiguration.yml<br/>roles, minimums, weights"/]

    user -- "HTTP" --> pages
    pages --> authz
    authz -- "OIDC login,<br/>token check" --> keycloak
    keycloak -- "user federation" --> ldap
    keycloak --> postgres
    authz --> node4
    node4 -- "1. access request" --> ap
    ap -- "2. checked request" --> te
    te -- "3. request, score,<br/>breakdown" --> pe
    pe -- "4. decision" --> node4
    te -. reads .-> data
    te -. reads .-> config
    pe -. reads .-> config
    pe -. "writes audit log" .-> data
    authz -. "writes requests,<br/>audit log" .-> data
```

Each engine also connects to the other engines at startup, but messages always travel in the order shown: Access Proxy, Trust Engine, Policy Engine, back to the Web UI.

## 2. Logging in

Keycloak owns the login page, so CyberDome never sees the user's password. After the login, the home page copies Keycloak's data that the Trust Engine needs into `data/`.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant W as Web UI
    participant K as Keycloak
    participant L as OpenLDAP
    participant D as data/

    U->>W: Open http://localhost:5000
    W->>U: Redirect to the Keycloak login page
    U->>K: Username and password
    K->>L: Check the password, read the user's groups
    L-->>K: OK, groups (for example Researcher)
    alt wrong password
        K->>K: Record a LOGIN_ERROR event
        K-->>U: "Invalid username or password"
    else correct
        K->>K: Record a LOGIN event
        K-->>W: Login code (back to /login)
        W->>K: Exchange the code for tokens
        K-->>W: Access token with the user's roles
        W->>U: Redirect to /home, device ID cookie on the first visit
        U->>W: Open /home
        W->>K: Fetch users and login events
        W->>D: user_data.json, events.json, auth_data.json (login history)
        W->>D: audit.log: new failed logins as AUTHENTICATION_FAILURE
        W-->>U: Home page with the menu for the user's roles
    end
```

## 3. A protected request

Every protected page (both resources, policy configuration, logging and PAM approval) takes this path, also when it's opened directly by URL. The page only runs after an "allow".

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant W as Web UI
    participant K as Keycloak
    participant AP as Access Proxy
    participant TE as Trust Engine
    participant PE as Policy Engine
    participant D as data/

    U->>W: GET /resource-1 (with the device ID cookie)
    alt not logged in
        W->>D: audit.log: AUTHENTICATION_FAILURE
        W-->>U: Redirect to the Keycloak login
    end
    W->>K: Is this token still active? (introspection)
    K-->>W: Active, roles: Researcher
    alt token invalid, expired or revoked
        W->>D: audit.log: AUTHENTICATION_FAILURE
        W-->>U: 401 Invalid or expired token
    end
    W->>W: Build the request record (user, roles, resource, action,<br/>device ID, new device, source IP, location, time)
    W->>D: Append to access_requests.jsonl, get the request ID
    W->>AP: Access request
    AP->>AP: Check the record is complete, stamp it as mediated
    AP->>TE: Request a trust score
    TE->>D: Login history, identity, recent requests
    TE->>TE: Score the 7 factors, weighted sum
    TE->>PE: Request, trust score and breakdown
    PE->>PE: Check P1 to P6, the first deny decides
    PE->>D: audit.log: the decision, before it is sent
    PE->>W: Decision with policy, outcome and reason
    alt ALLOW (P6)
        W->>D: Remember the device as known
        W-->>U: 200 The page
    else DENY (P1 to P5)
        W-->>U: 403 Access denied, with the policy and the reason
    end
    Note over W,PE: No decision within 10 seconds: 504, and an audit entry (DENY)
```

## 4. Policies

The Policy Engine checks six policies in order. The first one that denies decides, so the reason is always the clearest one. Rules that don't depend on the trust score come first.

```mermaid
flowchart TD
    start(["Request record, trust score and breakdown,<br/>sign-in success rate"])
    p1{"P1 Invalid authentication<br/>Authenticated, and a login<br/>is recorded?"}
    p2{"P2 Unauthorized resource<br/>Role allowed this resource?<br/>For a write: role in writeRoles?"}
    p3{"P3 Risky context<br/>High-risk country? Privileged role from a<br/>medium-risk country or at night?<br/>Admin page at night? Many failed logins?"}
    p4{"P4 Admin resource<br/>Not an admin resource, or<br/>trust score at least 0.75?"}
    p5{"P5 Low trust<br/>Trust score at least the<br/>resource's minTrustScore?"}
    allow(["ALLOW, P6 Permitted access"])
    authfail(["DENY, outcome AUTHENTICATION_FAILURE"])
    violation(["DENY, outcome POLICY_VIOLATION"])
    deny(["DENY, outcome DENY<br/>The reason names the weakest trust factors"])

    start --> p1
    p1 -- yes --> p2
    p1 -- no --> authfail
    p2 -- yes --> p3
    p2 -- no --> violation
    p3 -- none of these --> p4
    p3 -- one of these --> deny
    p4 -- yes --> p5
    p4 -- no --> deny
    p5 -- yes --> allow
    p5 -- no --> deny
```

The settings (allowed roles, `writeRoles`, `minTrustScore` per resource, `adminMinTrustScore`, `privilegedRoles`, risk lists, night window) are in `policyConfiguration.yml`. See [policies.md](policies.md).

## 5. Trust score

The Trust Engine scores 7 factors between 0 and 1, and adds them up with the weights from `policyConfiguration.yml` (`trustWeights`). Behaviour (login history, device, access frequency) is 55% of the score.

```mermaid
flowchart LR
    subgraph inputs["Where the facts come from"]
        auth[("auth_data.json<br/>last 10 logins")]
        record["Request record<br/>new_device, location, time"]
        reqs[("access_requests.jsonl<br/>recent requests")]
        users[("user_data.json<br/>email, MFA, created")]
    end

    subgraph factors["Factors (score 0 to 1) x weight"]
        f1["Login history x 0.20"]
        f2["Device x 0.20"]
        f3["Access frequency x 0.15"]
        f4["Location x 0.15"]
        f5["Identity strength x 0.15"]
        f6["Time of access x 0.10"]
        f7["Account age x 0.05"]
    end

    sum(["Trust score =<br/>sum of score x weight<br/>divided by sum of weights"])
    out["To the Policy Engine:<br/>score and breakdown<br/>(each factor's score, weight, reason)"]

    auth --> f1
    record --> f2
    reqs --> f3
    record --> f4
    users --> f5
    record --> f6
    users --> f7
    f1 & f2 & f3 & f4 & f5 & f6 & f7 --> sum --> out
```

Example: a known device in the daytime from `LOCAL`, all logins successful, verified email, no MFA, a new account gives about 0.90. The same on a new device gives about 0.78. See [trust-model.md](trust-model.md).

## 6. Audit log

Every decision ends up in `data/audit.log`, one JSON entry per line, whoever made it. The `/logging` page shows the newest entries.

```mermaid
flowchart LR
    subgraph sources["Who decides"]
        pe["Policy Engine<br/>every decision, P1 to P6"]
        web["Web UI<br/>not logged in, bad token,<br/>engines down"]
        kc["Keycloak<br/>failed logins<br/>(LOGIN_ERROR events)"]
    end

    log[("data/audit.log<br/>append-only, one JSON entry per line")]
    page["The logging page (/logging)<br/>Administrator, Security Viewer<br/>filter by outcome and user"]

    pe -- "ALLOW, DENY,<br/>AUTHENTICATION_FAILURE,<br/>POLICY_VIOLATION" --> log
    web -- "AUTHENTICATION_FAILURE,<br/>DENY" --> log
    kc -- "AUTHENTICATION_FAILURE<br/>(copied when events sync)" --> log
    log --> page
```

Each entry has the task's data model fields (`user`, `role`, `resource`, `action`, `device_id`, `source_ip`, `decision`, `trust_score`, `reason`), plus the policy, who decided, the trust breakdown and the context. See [audit-log.md](audit-log.md).

## 7. Code map

Where to look in the code. Arrows mean "uses".

```mermaid
flowchart TB
    subgraph web["web/: the Flask Web UI"]
        app["app.py<br/>creates the app, settings,<br/>device cookie hooks"]
        routes["routes/<br/>auth, access, resources,<br/>policy_config, monitoring,<br/>privileged_access"]
        authz["authz.py<br/>login check, protected_resource,<br/>Web UI audit entries"]
        reqctx["request_context.py<br/>request record, device ID,<br/>location"]
        proxy["proxy_client.py<br/>node 4, sends requests,<br/>waits for decisions"]
        kc["keycloak_config.py,<br/>keycloak_functions.py,<br/>extensions.py"]
        pam["pam.py, pam_mail.py,<br/>models.py<br/>privileged access (PAM)"]
    end

    subgraph engines["engines/: start the decision engines"]
        launch["access_proxy.py,<br/>trust_engine.py,<br/>policy_engine.py"]
    end

    subgraph shared["cyberdome/: shared by the Web UI and the engines"]
        net["networking.py<br/>one class per node,<br/>message handling"]
        trust["trust_algorithm.py<br/>the 7 factors"]
        signals["trust_signals.py<br/>Keycloak events, login history,<br/>recent requests"]
        policy["policy.py<br/>P1 to P6"]
        audit["audit.py<br/>audit entries"]
        jsonl["jsonl.py<br/>append-only files"]
        rules["access_rules.py,<br/>config.py<br/>resource table, settings"]
        paths["data_paths.py,<br/>settings.py<br/>file paths, .env"]
    end

    app --> routes
    routes --> authz
    authz --> reqctx
    authz --> proxy
    authz --> audit
    authz --> kc
    routes --> pam
    routes --> signals
    proxy --> net
    launch --> net
    net --> trust
    net --> policy
    net --> audit
    trust --> signals
    trust --> rules
    policy --> trust
    policy --> rules
    audit --> jsonl
    signals --> jsonl
    proxy --> jsonl
```

Tests are in `tests/`: `test_trust.py`, `test_policies.py` and `test_audit.py` need nothing running. `check_access_control.py` needs the identity stack and the engines. The start scripts are in `scripts/`.

## 8. Data files

All runtime data is in `data/` (git-ignored). Settings are in `policyConfiguration.yml`, secrets in `.env`.

| File | Written by | Read by | What's in it |
| --- | --- | --- | --- |
| `data/access_requests.jsonl` | Web UI, for every protected request | Trust Engine (access frequency) | The request records, one per line |
| `data/audit.log` | Policy Engine, Web UI, Keycloak sync | `/logging` page, tests | Every access decision, one per line |
| `data/known_devices.json` | Web UI, after an "allow" | Web UI (`new_device`) | The devices each user was allowed access from |
| `data/events.json` | Home page and `/logging` (from Keycloak) | Event processing, audit sync | Keycloak's login events |
| `data/auth_data.json` | Home page (event processing) | Trust Engine, Policy Engine | Login attempts and the sign-in success rate |
| `data/user_data.json` | Home page (from Keycloak) | Trust Engine | Email verified, MFA, account creation time |
| `data/keycloak_audit_state.json` | Audit sync | Audit sync | The newest Keycloak event already in the audit log |
| `data/privileged_access.db` | PAM pages | PAM pages | Privileged access requests and approvals |
| `policyConfiguration.yml` | Policy page (Policy Administrator) | Trust Engine, Policy Engine, Web UI | Resource table, minimum scores, weights, risk lists, night window |
