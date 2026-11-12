# Risk Model

How the adaptive risk model scores each access request (Task 2, sections 3 and 5.4), and why we built it this way.

The code is in `cyberdome/risk/`. The settings are in the `riskModel` section of `policyConfiguration.yml`. Every setting has a default in `cyberdome/risk/defaults.py`, so a missing or wrong value in the file falls back to a safe value instead of switching a check off.

> **Status:** step 3 of Task 2. The model is connected to the engines (see "How the engines use the model" below), and the Web UI carries out the responses (`step-up.md`). It only runs with `riskMode: adaptive`. The default is still `static`, so CyberDome decides exactly like Task 1 until we switch.

## How the engines use the model

With `riskMode: adaptive`, node 2 (the Trust Engine) works as the **Risk Engine**. We didn't add a new node, because one more network hop would make every request slower, and the latency comparison between System A and B would show that instead of the risk model.

```text
Web UI ──► Access Proxy ──► Risk Engine (node 2) ──► Policy Engine (node 3) ──► Web UI
            request record    engine.assess()          P1, P2, R1, P6
            + session_id        reads signals,         audit entry with the risk fields
            + auth_time         runs the model,        engine.record_decision():
            + acr               saves the session,       step-up waiting, or learn at LOW
                                logs a risk event
```

1. The Web UI adds three values from Keycloak's answer about the token to the request record: `session_id` (the token's `sid`), `auth_time` (when the user last logged in) and `acr` (how: `1` password, `2` with MFA). The browser can't change them.
2. The Risk Engine (`cyberdome/risk/engine.py`, `assess()`) counts the signals (recent requests, failed logins, role-table denials, verified email), runs `model.evaluate()` under the state lock, saves the session, and writes one line to `data/risk_events.jsonl`.
3. The Policy Engine decides with R1 (`docs/policies.md`), writes the audit entry with the risk fields (`docs/audit-log.md`), and calls `record_decision()`.

If the risk can't be computed (for example the request has no session ID), node 2 sends the error instead, and R1 denies. A request in a session that belongs to another user is also refused. That should never happen with Keycloak's session IDs, so it would mean something is wrong.

## Trust in Task 1, risk in Task 2

| | Task 1 trust score | Task 2 risk score |
| --- | --- | --- |
| Direction | 1 is good | 1 is bad |
| Memory | None. Each request is scored on its own | The session's risk carries over from request to request and fades slowly |
| Answer | Allow or deny | LOW, MEDIUM, HIGH or CRITICAL, each with its own response |
| Compared with | One rule for everyone | Each user's own usual behaviour, once we know it |

We keep the Task 1 trust score unchanged. It is System A in the experiments, so it must stay exactly as it was.

## How the score works

Two steps for every request.

**Step 1: the event risk.** Each of the 9 features gives a score between 0 (normal) and 1 (very unusual). They are combined with their weights:

```text
r_t = sum(weight * feature) / sum(weights)
```

Then the **floors**: if one strong signal fires on its own, the event risk is raised to at least a set level (see [Floors](#floors)).

**Step 2: the session risk.** The session remembers its last risk, and that memory halves every `halfLifeMinutes` (10):

```text
R_t = max(r_t, R_prev * 0.5 ^ (minutes since R_prev / halfLifeMinutes))
```

**Step 3: the level.** `R_t` is compared with the thresholds:

| Risk | Level |
| --- | --- |
| below 0.30 | LOW |
| 0.30 to below 0.55 | MEDIUM |
| 0.55 to below 0.80 | HIGH |
| 0.80 and above | CRITICAL |

On an admin resource the level goes up one step (`adminLevelBump`) before the response is chosen. MEDIUM on the audit log page is treated as HIGH.

These thresholds are a **first guess**. The task asks us to justify the final values with experiments, so they will change after the threshold sweep (step 5 of the plan). We will not keep them only because they look like the task's example.

### Example: Bob's session

Bob has a profile (he reads Resource 1 in work hours on his laptop). These numbers come from the unit tests:

| Time | What happens | Event risk | Session risk | Level |
| --- | --- | --- | --- | --- |
| 09:01 | Reads Resource 1 | 0.04 | 0.04 | LOW |
| 09:02 | Tries the audit log page. The role table denies it twice | 0.16, floor to 0.30 | 0.30 | MEDIUM |
| 09:03 | Reads Resource 1 again | 0.04 | 0.28 (0.30, a little faded) | LOW |
| 10:00 | Reads Resource 1 after an hour of quiet | 0.06 | 0.06 | LOW |

The 09:03 row shows the memory: the request itself is normal, but the session still carries most of the 09:02 risk.

## The 9 features

| # | Feature | Config key | What it measures | Score | Weight |
| --- | --- | --- | --- | --- | --- |
| F1 | Access frequency | `accessFrequency` | The user's requests in the last 5 minutes, compared with their usual number | 0 up to the usual number (at least `minBaseline`, 10). 1 at 4 times the usual number. A straight line in between | 0.15 |
| F2 | Resource-access sequence | `resourceSequence` | How likely this resource is after the previous one, for this user. Plus extra for an admin resource the user rarely uses, and for each request the role table denied in the last 10 minutes | `1 - probability`, + 0.3 for a rare admin resource, + 0.25 per denial, at most 1 | 0.12 |
| F3 | Session duration | `sessionDuration` | How long the session has lasted, compared with the user's usual session (60 minutes until we know theirs) | 0 up to the usual length. 1 at 4 times the usual length | 0.12 |
| F4 | Authentication failures | `authFailures` | Failed logins at Keycloak in the last 10 minutes | failures / 5, at most 1 | 0.15 |
| F5 | Time of day | `timeOfDay` | How many of the user's requests were around this hour (the hour and one on each side) | 0 if at least 5% of their requests are in that band. 1 if none are. Without history: 0.7 inside the night window, 0 outside | 0.09 |
| F6 | Device familiarity | `deviceFamiliarity` | A new device for the user, or a different device inside the same session | known 0, new 0.6, changed inside the session 1.0 | 0.10 |
| F7 | Network or context change | `networkChange` | The IP or location is different from the start of the session, or the location is on a risk list | same 0, medium-risk country 0.5, changed 0.7, high-risk country 1.0. The highest one counts | 0.10 |
| F8 | Identity assurance | `identityAssurance` | Was MFA **used in this login** (the token's `acr` claim), and is the email verified | MFA used 0, password only 0.5, + 0.2 for an unverified email | 0.08 |
| F9 | Reaction to MFA challenges | `mfaReaction` | Step-ups in this session that failed or were never finished | failed / 3, at most 1 | 0.09 |

Each feature also gives a **reason**, like the Task 1 factors, for example `logging after resource_1 is 1% likely for this user`. The result lists the features that raised the risk most (`top_features`), so a step-up or a deny can say why.

### Why these features

- **F1, F3, F4, F5 and F9** are the five risk factors of the ARB-ZTA paper (Nahar and Andersson), the same paper our Task 1 weights came from.
- **F2, F6 and F7** are on the task's list of recommended features. F2 also covers "recent denied requests", which we picked in our 20 October review of other factor options, because the audit log already has the data.
- **F8** fixes a weak spot in Task 1. The Task 1 factor "identity strength" checked whether MFA was **set up** on the account. An attacker who logs in with only a stolen password still got the MFA credit. F8 reads the login method of this login from the token.

### Why some Task 1 factors are not in the risk model

| Task 1 factor | Why not here |
| --- | --- |
| Login history (last 10 logins) | F4 replaces it. F4 looks at the last 10 minutes, so it reacts while an attack is going on. The Task 1 factor could take 10 logins to move |
| Account age | It hardly changes during a session, so it can't help a risk that should change during a session |
| Location (risk lists) | Now part of F7, together with a change of network inside the session |

### Each user's usual behaviour (the profile)

F1, F2, F3 and F5 compare a request with the user's own usual behaviour. The profile (`data/risk_profiles.json`) holds counts only:

| Field | What it counts |
| --- | --- |
| `requests` | How many requests were learned |
| `hours` | Requests per hour of the day |
| `resources` | Requests per resource |
| `transitions` | Moves from one resource to the next |
| `usual_requests` | The usual number of requests per 5 minutes (a moving average) |
| `session_minutes` | The usual session length (a moving average) |

**Only requests allowed at LOW risk are learned** (`model.learn()`). Otherwise an attacker's activity would slowly become the user's "usual" behaviour, and the model would stop seeing it.

**Cold start:** until a user has 20 learned requests (`minHistory`), the model doesn't use their profile. F2 then gives 0.5 ("no baseline yet"), F5 uses the Task 1 night window, and F1 and F3 use the defaults. For the experiments, we seed the demo users with a synthetic normal history.

**Transitions** use Laplace smoothing: every count gets 1 added. A move the user never made is unlikely, but not impossible, so one new page doesn't score a full 1.

## Floors

A weighted mean has a weak spot: one feature can only add its own weight. In our first test, Bob tried the audit log page and the role table denied him twice. F2 was at its maximum (1.0), but the risk was only 0.16, still LOW, because F2's weight is 0.12. The same happened for a burst of 40 requests in 5 minutes (0.19). Privilege abuse and high-frequency access are two of the task's attack scenarios, so the model has to react to them.

A floor says: if this one feature reaches this score, the event risk is at least the threshold of this level.

| Feature | At | At least | Why |
| --- | --- | --- | --- |
| F4 Authentication failures | 1.0 (5 failures in 10 minutes) | HIGH | Someone is guessing the password right now |
| F9 Reaction to MFA challenges | 1.0 (3 failed step-ups) | HIGH | Someone has the password but not the second factor |
| F7 Network or context change | 1.0 (high-risk country) | HIGH | Same rule as Task 1 policy P3, which denied high-risk countries |
| F2 Resource-access sequence | 1.0 | MEDIUM | Privilege abuse: an unusual admin request, often with denials |
| F6 Device familiarity | 1.0 (device changed inside the session) | MEDIUM | One session should stay on one browser. A change can mean a stolen session |
| F1 Access frequency | 1.0 (4 times the usual rate) | MEDIUM | Automated access |

**Alternatives we didn't choose:**

- *Higher weights for F2 and F1.* Then normal small changes in those features would also push normal users toward MEDIUM, and the other features would count for less.
- *Taking the highest feature instead of the mean.* Every single odd signal (a new device) would decide alone. That would ask normal users for MFA much more often, which is the security fatigue our research question is about.

Floors keep the mean for normal, mixed signals, and only step in for the few signals that are strong on their own. Whether frequency alone should ever reach HIGH (for example at 10 times the usual rate) is a question for the experiments.

## Memory and recovery

### Why the session risk has memory

Without memory, an attacker could make one odd request between many normal ones, and every request would be judged alone. With memory, the odd request keeps the session elevated for a while.

**Why `max` and not a sum:** a sum would let many small, normal signals add up to a step-up during a long, normal working day. With `max`, the risk is the worst recent thing, faded by time.

**Why a half-life of 10 minutes:** a CRITICAL risk (0.80) fades below MEDIUM (0.30) in about 14 minutes of normal activity, and even the highest MEDIUM risk (just under 0.55) fades to LOW within about 9 minutes. That is long enough to cover the next requests of an attack, and short enough that a user isn't punished for the rest of the day. It's a first guess, and the experiments will test it.

We will check the choice with numbers: the experiments run the model with `memory: false` too (`R_t = r_t`), and compare the two (an ablation).

### Recovery (task section 5.4)

| How | What happens |
| --- | --- |
| A passed step-up | The session risk starts again from this request (`R = r_t`). Failed step-ups go back to 0. The device, IP and location of the verified request become the session's own, so they don't keep counting as a change |
| Normal activity | The risk halves every 10 minutes, so it falls by itself |
| A new session after CRITICAL | Starts at 0, but F4 (failed logins) and the profile don't reset, so a new session during an attack still starts high |

### How we know a step-up was passed

The Policy Engine marks the session with `request_step_up()` when R1 asks for a step-up. On the next requests, the model checks the token's values from Keycloak:

- `auth_time` must be after the step-up was asked for (a new login happened), and
- `acr` must be one of `mfaAcrValues` (MFA was used in that login).

Both come from the token that Keycloak signs, so the browser can't fake a passed step-up. If no passed step-up arrives within `stepUpTimeoutMinutes` (5), it counts as failed, and F9 goes up.

If the same or a weaker step-up is asked for again while one is waiting (for example the user reloads the page), the first time is kept. Otherwise reloading would restart the 5 minutes, and an unanswered step-up would never count as failed. A stricter one (`full` while `otp` waits) replaces it.

A passed step-up also sets the session's `verified_level`: the response level it was asked for. R1 doesn't ask again at that level or below for the rest of the session. "A passed step-up covers its level for the session" in `policies.md` explains why.

If OTP doesn't work with our LDAP users, we set `mfaAcrValues: []`. Then a new password login is enough to pass. That is the fallback in the plan, and it has a test.

## Where the state is kept

| File | What it holds |
| --- | --- |
| `data/risk_state.json` | Each session's state: risk, level, start time, first IP, location and device, previous resource, step-up waiting (kind, level, time), the level a passed step-up covers, failed step-ups |
| `data/risk_profiles.json` | Each user's profile (see above) |
| `data/risk_events.jsonl` | Every risk calculation, one per line, for the "risk score vs. time" graph and the demo |

The Web UI and the engines are separate processes, so the two JSON files are only read and written while a lock file is held, and they are replaced in one step (write a temporary file, then rename it). A session with no request for 30 minutes (Keycloak's default idle time) counts as ended, and its length is added to the user's usual session length.

## Privacy

Behaviour data is personal data under GDPR. We keep only what a feature needs:

- The profile holds **counts**, not a list of what the user did and when.
- No page content, no browser fingerprint. Only resource names, hours, device IDs (the cookie from Task 1) and country codes.
- Risk events older than `retentionDays` (30) are removed (`RiskStore.prune_events()`). Unlike the audit log, they are not a security record.

## All the settings

| Key | Default | Meaning |
| --- | --- | --- |
| `weights` | see the feature table | Each feature's weight. They don't need to add up to 1 |
| `thresholds` | MEDIUM 0.30, HIGH 0.55, CRITICAL 0.80 | Must be in that order, between 0 and 1. Otherwise the defaults are used |
| `memory` | true | false gives the model without memory, for the comparison |
| `halfLifeMinutes` | 10 | How fast the session risk fades |
| `adminLevelBump` | 1 | Steps up for admin resources |
| `stepUpTimeoutMinutes` | 5 | After this, a step-up that wasn't passed counts as failed |
| `mfaAcrValues` | `['2']` | Token `acr` values that mean MFA was used |
| `minHistory` | 20 | Learned requests before the user's own profile is used |
| `retentionDays` | 30 | How long risk events are kept |
| `floors` | see [Floors](#floors) | Strong single signals |
| `accessFrequency`, `resourceSequence`, ... | see the feature table | Each feature's own settings |

## Tests

`tests/test_risk.py` has 52 tests: the settings and their fallbacks, each feature, the floors, the memory and its ablation, the levels and the admin step up, the task's demo sequence (normal reads, then admin access, then failed logins), step-ups (passed, not passed, too late, asked again, the level they cover, password-only fallback), learning, the signal counts from `data/`, saving the state, and the Risk Engine (`engine.py`) with the saved state. The R1 policy is tested in `tests/test_policies.py`.

```bash
python3 tests/test_risk.py
```
