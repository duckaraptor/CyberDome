# Step-up and Session End

How CyberDome carries out the adaptive responses in Task 2: the OTP step-up at MEDIUM, the full step-up at HIGH, and ending the session at CRITICAL. Which response a request gets is decided by policy R1 (`policies.md`). This page is about what happens next.

The code is in `web/step_up.py` and `web/authz.py` (the Web UI), the Keycloak setup is in `scripts/setup_keycloak_step_up.py` and `infra/keycloak/myrealm-realm.json`.

## The four responses

| Response level | Outcome | What the user sees | Code |
| --- | --- | --- | --- |
| LOW | `ALLOW` | The page | `authz.py` |
| MEDIUM | `STEP_UP_REQUIRED`, `otp` | Keycloak asks for a one-time code (OTP), then the page | `step_up.redirect_to_step_up()` with `acr_values=2` |
| HIGH | `STEP_UP_REQUIRED`, `full` | Keycloak asks for the password and an OTP, then the page | the same, plus `prompt=login` |
| CRITICAL | `RISK_ALERT` | `403` "Access denied, session ended". The next page asks for a new login | `step_up.end_session()` |

## Step-up, step by step

```text
Browser           Web UI (PEP)                      Keycloak                   Engines
  │ GET /resource-1  │                                  │                          │
  │─────────────────►│ request record (sid, auth_time, acr=1)                      │
  │                  │────────────────────────────────────────────────────────────►│ risk MEDIUM
  │                  │◄──────────────── STEP_UP_REQUIRED, otp ─────────────────────│ session: step-up waiting
  │                  │ keep {kind: otp, next: /resource-1} in the signed session   │
  │◄── 302 /step-up ─│                                  │                          │
  │ GET /step-up     │                                  │                          │
  │─────────────────►│── 302 /auth?acr_values=2 ───────►│ OTP form                 │
  │◄─────────────────────────────────────────────────── │ (first time: set up the  │
  │ code from the authenticator app ───────────────────►│  authenticator app)      │
  │◄── 302 /authorize?code=... ─────────────────────────│                          │
  │─────────────────►│ new token: auth_time = now, acr = 2                         │
  │◄── 302 /resource-1                                  │                          │
  │ GET /resource-1  │                                  │                          │
  │─────────────────►│ request record (auth_time newer than the step-up, acr=2)    │
  │                  │────────────────────────────────────────────────────────────►│ step-up passed:
  │                  │◄──────────────────────── ALLOW ─────────────────────────────│ risk = r_t (recovery)
  │◄── 200 page ─────│                                  │                          │
```

1. R1 decides `STEP_UP_REQUIRED`. The Policy Engine marks the session "step-up waiting" in the risk state (`engine.record_decision()`).
2. The Web UI keeps the kind (`otp` or `full`) and the page to come back to in the Flask session, and redirects to `/step-up`.
3. `/step-up` sends the user to Keycloak with `acr_values=2`, and `prompt=login` for a full step-up.
4. Keycloak's "browser step-up" flow asks for the OTP (and the password first, for `full`). A user without an authenticator app is asked to set one up first.
5. Flask-OIDC's callback stores the new token and returns to the page.
6. The next request carries the new token's `auth_time` and `acr`. The risk model counts the step-up as passed if `auth_time` is after the step-up was asked for and `acr` is `2` (`riskModel.mfaAcrValues`). The risk goes back to the risk of this request (recovery), and R1 allows.

If the user doesn't come back with a passed step-up within 5 minutes (`riskModel.stepUpTimeoutMinutes`), it counts as failed, and F9 (reaction to MFA challenges) goes up. 3 failed step-ups give at least HIGH.

## The Keycloak login flow

Keycloak decides how much to ask with **levels of authentication** (LoA). Our flow, "browser step-up":

```text
browser step-up
├── Cookie                                     ALTERNATIVE   (already logged in: no form)
└── step-up forms                              ALTERNATIVE
    ├── step-up level 1                        CONDITIONAL
    │   ├── Condition - Level of Authentication  level 1, max age 10 hours
    │   └── Username Password Form             REQUIRED
    └── step-up level 2                        CONDITIONAL
        ├── Condition - Level of Authentication  level 2, max age 0
        └── OTP Form                           REQUIRED
```

- A normal login asks for level 1, so it's the password only. The token has `acr` 1.
- A step-up asks for level 2 (`acr_values=2`). Level 1 is still valid from the login, so only the OTP is asked. The token has `acr` 2.
- A full step-up also sends `prompt=login`, so Keycloak asks for the password again before the OTP.

**Why max age 0 for level 2:** with a longer max age, Keycloak would remember the OTP and not ask for it on the next step-up. Then the token would still say `acr` 2, but no new check would have happened. With 0, every step-up asks for a new code, and a new code means a new `auth_time`. That is the proof the risk model checks.

**Why the proof comes from the token:** `auth_time` and `acr` are in the token that Keycloak signs, and the Web UI gets them from Keycloak's answer about the token. The browser can't fake a passed step-up.

**Why the kind of step-up is kept in the Flask session:** the `/step-up` URL takes no parameters. If it did, a user who needs a full login could ask for only an OTP. The Flask session cookie is signed with the server's secret key, so the user can't change it. If a stricter step-up is needed while a lighter one is waiting, the stricter one is kept.

**Why there is a 60-second guard:** a user who comes back from Keycloak and still needs a step-up is not sent back straight away. They see a page with a "Verify now" button. Without the guard, a step-up that can't succeed (for example the flow is missing) would redirect forever. Requests that change something (POST) also get the button, because a form can't be sent again after a redirect.

## Setting it up

New setups get the flow from `infra/keycloak/myrealm-realm.json` on the first start. Keycloak doesn't import the file again for a realm that already exists, so for our existing realm:

```bash
python3 scripts/setup_keycloak_step_up.py
```

It adds the flow through the admin API and makes it the realm's browser flow. It reads the admin login from `.env`. `--undo` goes back to Keycloak's own browser flow, `--recreate` adds the flow again, and `--print-json` prints the flow in the format of the realm file (the realm file was made with it, so both have the same flow).

To check it worked: `acr_values_supported` in `http://localhost:8080/auth/realms/myrealm/.well-known/openid-configuration` should include `"2"`.

The first step-up of each user asks them to scan a QR code with an authenticator app (for example Google Authenticator, Microsoft Authenticator or FreeOTP). Keycloak keeps the OTP secret in its own database, also for users from LDAP.

If OTP doesn't work for us, set `riskModel.mfaAcrValues: []`. Then a new login with the password is enough to pass a step-up. That is weaker, and we would write it down as a limit.

## Ending the session (CRITICAL)

When R1 answers `RISK_ALERT`, the Web UI:

1. ends the Keycloak session with the user's own refresh token, the same way logout does (`keycloak_functions.revoke_token()`). This needs no admin rights.
2. removes the token and the waiting step-up from the Flask session.
3. removes the session's risk state (`engine.end_session()`). Its length doesn't count toward the user's usual session length, because it ended for a reason. The user's profile and failed logins stay, so a new login during an attack doesn't start clean.
4. writes a second audit entry, from the Web UI, with outcome `RISK_ALERT` and the reason "The session was ended after a CRITICAL risk". So the log shows both the alert (Policy Engine) and that the session really ended (Web UI). The experiments count alerts from the Policy Engine's entries only.

A session can also reach CRITICAL without a request, for example from failed logins. Ending it then is step 4 (continuous monitoring).

## Changes from the plan

**HIGH asks for a full step-up on every request, without a read-only mode.** The plan said a session at HIGH would be read-only until the step-up is passed: reads allowed, writes and admin pages refused. We didn't build that. At HIGH, someone else may be using the session, and read-only would still let them read every page. The full step-up is one login away, so the cost for the real user is small. Writes and admin pages are refused until the step-up is passed, as planned.

## Limits

- **We haven't tested it against the real Keycloak yet.** The flow, `acr_values` and `prompt=login` follow Keycloak's documentation for step-up authentication. We still need to check in the browser that the token after an OTP step-up has a new `auth_time`. If it doesn't, no OTP step-up can pass, and we would see it at once.
- **The step-up only proves the token is new.** A full and an OTP step-up both end with `acr` 2. That the full one also asked for the password comes from `prompt=login`, which the Web UI sends. The risk model can't see it in the token.
- **OTP only.** Keycloak also supports WebAuthn (security keys, passkeys) at level 2. That would resist phishing better, but it needs more setup for the demo.
