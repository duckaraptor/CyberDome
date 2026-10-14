# Audit Log

How CyberDome records every access decision (assignment section 3.5), and why the log looks the way it does.

The code is in `cyberdome/audit.py`. The log is `data/audit.log`, and the `/logging` page shows it.

## What gets logged

Every decision, wherever it is made:

| Decided by | Event | Outcome |
| --- | --- | --- |
| Policy Engine | Every decision on a protected page (policies P1 to P6, see `policies.md`) | `ALLOW`, `DENY`, `AUTHENTICATION_FAILURE` or `POLICY_VIOLATION`, as the policy decided |
| Web UI | Someone who isn't logged in opens a protected page, and is sent to the login page | `AUTHENTICATION_FAILURE` |
| Web UI | The login token is invalid, expired or revoked (`401`) | `AUTHENTICATION_FAILURE` |
| Web UI | Keycloak can't be reached to check the token (`503`) | `DENY` |
| Web UI | The decision engines are down (`503`) or don't answer in time (`504`) | `DENY` |
| Keycloak | A failed login, for example a wrong password (Keycloak's `LOGIN_ERROR` events) | `AUTHENTICATION_FAILURE` |

The four outcomes are the categories the task asks for:

| Outcome | Meaning |
| --- | --- |
| `ALLOW` | Access was given (policy P6) |
| `DENY` | Access was refused because of low trust or risky context (P3, P4, P5), or because the request couldn't be checked |
| `AUTHENTICATION_FAILURE` | The user couldn't prove who they are: not logged in, a bad token, a failed login, or P1 |
| `POLICY_VIOLATION` | The user is known, but their role may not do this (P2) |

## What an entry looks like

One JSON object per line. An example (shown on several lines here):

```json
{
  "time": "2026-10-14 20:15:03",
  "outcome": "POLICY_VIOLATION",
  "decision": "DENY",
  "trust_score": 0.895,
  "reason": "Role Researcher may not access resource_2 (allowed: Administrator)",
  "policy_id": "P2",
  "policy_name": "Unauthorized resource",
  "decided_by": "Policy Engine",
  "user": "bob",
  "role": "Researcher",
  "resource": "resource_2",
  "action": "read",
  "device_id": "6ae1f108-1030-41a0-b76e-0efad1a0905b",
  "source_ip": "127.0.0.1",
  "user_id": "79b8a60d-d1c0-4323-b039-3a3ce4bf7777",
  "roles": ["Researcher"],
  "path": "/resource-2",
  "location": "LOCAL",
  "new_device": false,
  "authentication_status": "authenticated",
  "request_id": 412,
  "trust_factors": {"device": {"score": 1.0, "weight": 0.2, "reason": "known device"}, "...": "..."}
}
```

Fields that don't apply are `null`. For example, a visitor who isn't logged in has no `user`, `role` or `trust_score`.

## The task's data model

Section 4 of the task gives a minimum data model. Every audit entry has these fields with exactly these names:

| Task field | In the audit entry | Where it comes from |
| --- | --- | --- |
| `user` | `user` | The username from the token (`username` in the request record) |
| `role` | `role` | The user's roles from the token, joined with commas (`roles` in the request record, which is a list because a user can have several) |
| `resource` | `resource` | The page's resource in the resource table |
| `action` | `action` | `read` for GET, `write` for POST |
| `device_id` | `device_id` | The `cyberdome_device_id` cookie |
| `source_ip` | `source_ip` | The HTTP connection |
| decision | `decision` | `ALLOW` or `DENY` |
| trust score | `trust_score` | The Trust Engine's score for this request |
| reason | `reason` | The policy's reason, or the Web UI's or Keycloak's reason |

The request record (`data/access_requests.jsonl`) keeps the repository's own names (`username`, `roles`), as the task allows ("adapting it to the repository's existing format"). The audit log uses the task's names, so each field of section 4 is easy to find.

## Why the log looks like this

### Why one log for every source

The task asks that all decisions are logged. Before this change, only the Policy Engine's decisions were saved (`data/access_decision.json`). Failed logins, bad tokens and visitors who weren't logged in left no trace, because they never reach the Policy Engine. Now the Web UI and Keycloak's events write to the same log, so one place answers "what happened, and why?".

### Why append-only, one JSON object per line

- **Old entries never change.** That is what an audit log should guarantee. Nobody (and no bug) rewrites history by accident.
- **It's fast.** Before, every request read and rewrote `data/access_decision.json` and `data/access_requests.json` in full. The files grew with every request, so every request got slower: after many test runs, about 45 ms instead of 21 ms. Appending one line takes the same time however big the file is.
- **It can be read from the end.** The `/logging` page shows the newest entries, and the access frequency factor counts the last 5 minutes. Both read the file backwards and stop early, instead of loading all of it.
- **Two processes write to it.** The Policy Engine and the Web UI are separate programs. A file lock makes sure they never write at the same moment and mix up two lines.

### Why visitors who aren't logged in are logged

Sending someone to the login page instead of showing the page is also an access decision, and the task asks for all decisions. It also makes probing visible: someone trying many hidden URLs without logging in leaves a trail of entries from one source IP and device. The cost is a few more entries, for example when a session ends and the user clicks a link. The `/logging` page can filter them out.

### Why the decision is logged before access is given

The Policy Engine writes the entry first, and only then sends the decision to the Web UI. If writing fails, the Web UI never gets an "allow". So there is never access without a log entry.

### Why failed logins come from Keycloak's events

The login page belongs to Keycloak, so CyberDome never sees a wrong password itself. Keycloak records each failed login as a `LOGIN_ERROR` event. CyberDome already fetches these events for the trust score (login history). It copies new `LOGIN_ERROR` events into the audit log when it syncs events: when a user opens the home page, and when someone opens the `/logging` page. The entry's time is the time of the failed login, so these entries can appear a little later in the file than entries made at the same moment.

## The /logging page

Only roles allowed the `logging` resource can open it (Administrator and Security Viewer), and the request goes through the engines like every other protected page. It shows the newest 200 entries, newest first, with filters for outcome and user.

## Files

| File | What's in it |
| --- | --- |
| `data/audit.log` | The audit log, one JSON entry per line |
| `data/access_requests.jsonl` | The access requests, one per line. The Trust Engine reads it for the access frequency factor |
| `data/keycloak_audit_state.json` | The time of the newest Keycloak event already copied into the audit log, so no failed login is copied twice |

The old `data/access_decision.json` and `data/access_requests.json` are no longer written. They stay in `data/` so earlier test runs can still be looked at.

## Limits and future work

- **The log is a local file.** Someone with access to the machine could edit or delete it. A real system would send entries to a separate, write-only log server (for example a SIEM), or sign each entry.
- **No rotation.** The file grows forever. A real system would start a new file every day or at a size limit.
- **Failed logins arrive late.** They are copied in when the app syncs Keycloak's events, not at the moment they happen.
