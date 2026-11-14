# Continuous Monitoring

How CyberDome keeps watching a session after the login (Task 2, section 5.3), and the `/risk` page.

The code is in `web/monitor.py` (the monitor thread), `cyberdome/risk/model.py` (`reassess()`), `cyberdome/risk/engine.py` (`monitor_sessions()`, `active_sessions()`) and `web/routes/monitoring.py` (the page).

## Two ways the risk is recalculated

| When | What | Code |
| --- | --- | --- |
| On every request | The Risk Engine scores the request with all 9 features and updates the session risk (`risk-model.md`) | `engine.assess()` |
| Every 10 seconds, without a request | The monitor thread checks every active session for new failed logins (F4) and unanswered step-ups (F9) | `monitor.py`, `engine.monitor_sessions()` |

The first alone meets "risk is recalculated during an active session". The second covers what happens between requests. For example, someone guesses the user's password at the login page while the real user is logged in. Without the monitor, CyberDome would only notice at the user's next request.

## What the monitor thread does

Every 10 seconds (`MONITOR_INTERVAL_SECONDS`), also when nobody sends a request:

1. **Pulls Keycloak's login events** into `data/events.json` and `data/auth_data.json`, and copies new failed logins into the audit log (`AUTHENTICATION_FAILURE`). This runs in both modes.
2. **In adaptive mode, recalculates every active session** (`engine.monitor_sessions()`). Sessions with no request for 30 minutes end first, as on a request.
3. **Ends a session that reaches CRITICAL** at Keycloak (admin API: `DELETE /admin/realms/myrealm/sessions/{sid}`), removes its risk state, and writes a `RISK_ALERT` audit entry from "Risk Monitor".

The thread starts with the first request to the Web UI, like the Web UI's node. With Flask's debug reloader, that is the process that serves requests, so only one thread runs. It stops when the Web UI stops.

In NIST SP 800-207 terms, this thread is the **Policy Administrator (PA)**: it acts on the risk by ending sessions. In Task 1 we had no separate PA.

## How a session is recalculated without a request

`model.reassess()` takes the scores of the session's last request and replaces two of them with new values:

- **F4 authentication failures:** the user's failed logins in the last 10 minutes, from `data/auth_data.json`
- **F9 reaction to MFA challenges:** a step-up that wasn't passed within 5 minutes now counts as failed

The other 7 features describe a request (device, network, resource, time of day...), so they keep their last scores. The event risk is then calculated as for a request: the weighted mean, then the floors. The session risk becomes the higher of that and the decayed old risk.

Example: Bob reads Resource 1 at 09:01 (risk 0.04, LOW). At 09:03, 5 failed logins for bob arrive from Keycloak. 10 seconds later, the monitor raises his session to 0.55 (HIGH, the authentication failures floor), with no request from Bob. His next request needs a full step-up. If nothing else happens, the risk halves every 10 minutes and is LOW again by about 09:13.

**Only new information counts.** The monitor only acts when F4 or F9 is higher than the last time it was scored, by a request or by the monitor. It then stores the new value. Without this, every round would score the last request again, and a device change from an hour ago would keep the risk up forever. We found this with a test: the risk never decayed.

**The monitor only raises the risk.** Lowering is the job of the decay, which `active_sessions()` and the next request apply.

**The monitor doesn't keep a session alive.** It updates `risk_at` (when the risk last changed), but not `last_request_at`. A session still ends 30 minutes after its last request.

**With the default settings, the monitor alone reaches HIGH, not CRITICAL.** The authentication failures floor is HIGH, and F4's own weight is 0.15. CRITICAL needs more, for example a session that was already HIGH and gets a new strong signal on its next request. So step 3 at the moment is "the session is at HIGH, and the next request needs a full step-up". The session-ending code in the monitor runs when the settings allow CRITICAL (for example a floor at CRITICAL). The threshold sweep in the experiments decides the final values.

## The /risk page

For Administrator and Security Viewer (resource `risk_monitoring` in `policyConfiguration.yml`, an admin resource, like `logging`). It shows:

- every active session, highest risk first, with its risk decayed to now and its level
- the session's start, last request, request count, first IP and location, a waiting step-up, the level a passed step-up covers, and failed step-ups
- a chart of the session's risk over the last 2 hours, from `data/risk_events.jsonl`: one dot per request or monitor change (hover for the time, resource and level), and dashed lines at the thresholds

The chart is an SVG built on the server, so the page needs no JavaScript library.

**Why the page doesn't refresh itself:** every page load is a protected request through the engines. An automatic refresh every few seconds would count toward the viewer's own access frequency (F1), and it would fill the audit log. The page has a "Refresh" link instead.

## What changed in other parts

- The home page and `/logging` page used to pull Keycloak's events themselves, and each had its own copy of the code. Both now call `monitor.sync_keycloak_events()`, which holds a lock, so the thread and a page can't write `data/events.json` at the same moment. The home page still syncs, so a user's own login is in `data/` before their first request.
- Each session in `data/risk_state.json` now also keeps `last_request_at` and `last_features` (the 9 scores of its last request).
- Risk events from the monitor have `"source": "monitor"` in `data/risk_events.jsonl`.

## Limits

- **10 seconds is a delay.** A failed login raises the risk up to 10 seconds later. Keycloak can send events directly to a listener, but that needs a Keycloak extension (a Java SPI), which is more than we need for the prototype.
- **The whole event list is fetched every round.** `store_keycloak_events()` asks Keycloak for up to 10,000 events and compares them with the file. That is fine for our demo data, but a real system would only fetch new events (Keycloak's `dateFrom`).
- **Only failed logins and step-up timeouts are monitored.** Other things that could happen between requests, like a password reset or a change of roles, are not.
- **The monitor needs the Web UI.** If the Web UI is down, nobody is monitored, but nobody can use a protected page either.
