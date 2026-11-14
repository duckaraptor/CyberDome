# System A+MFA

A third system for the experiments: Task 1's static policies, plus "admin pages need MFA", once per session. It is the baseline for counting MFA prompts in our research question (Proposal 3), and is not part of Task 2's required comparison.

The code is policy M1 in `cyberdome/policy.py`. It runs with `riskMode: static-mfa` in `policyConfiguration.yml`.

## Why we need it

Our research question asks whether adaptive authentication (System B) asks for MFA less often, without losing security. System A (Task 1) never asks for MFA. So any number of prompts in System B is "more" than System A, and the comparison says nothing.

Real systems that don't use risk usually ask for MFA on admin pages. System A+MFA is that system. Now we can compare:

| System | `riskMode` | When it asks for MFA |
| --- | --- | --- |
| A (Task 1) | `static` | Never |
| A+MFA | `static-mfa` | The first admin page in each session |
| B (Task 2) | `adaptive` | When the session's risk is MEDIUM or higher (admin pages count one level higher) |

## How it works

The policies run in this order: P1 to P5 as in Task 1, then **M1 Admin MFA**, then P6.

| Situation | Decision |
| --- | --- |
| A Task 1 policy denies | The same deny as System A. No prompt for a request that is refused anyway |
| Not an admin resource | P6 allows, as in System A |
| An admin resource, and MFA was used in this login (the token's `acr` is in `riskModel.mfaAcrValues`, by default `2`) | P6 allows |
| An admin resource, and no MFA in this login | M1: `STEP_UP_REQUIRED`, `otp` |

The step-up itself is the same as in System B (`step-up.md`): the Web UI sends the user to Keycloak with `acr_values=2`, Keycloak asks for the OTP, and the new token has `acr` 2. From then on, M1 lets the session through. The audit entry has `step_up: otp` and the `session_id`, so the experiments count prompts per session in the same way for A+MFA and B.

Node 2 stays the Trust Engine in this mode, and no risk is calculated. The monitor thread pulls Keycloak's events, as in System A, but doesn't score sessions.

Example:

```text
ALLOW    P6  Role Administrator may access resource_2, and trust score 0.90 meets the minimum of 0.75
STEP_UP  M1  logging is an admin resource, and MFA was not used in this login (acr 1), so a one-time code (OTP) is needed once per session
ALLOW    P6  Role Administrator may access logging, and trust score 0.90 meets the minimum of 0.6     (after the OTP)
```

## Why once per session, not on every admin page

Asking on every admin page request would give System A+MFA many more prompts, so System B would look much better. But no one would build a real system that way, so the comparison would be unfair, and a reviewer could call it a weak baseline.

Once per session is how most real systems do admin MFA. It also matches System B, where a passed step-up covers its level for the rest of the session (`policies.md`). So both systems are measured under the same rule, and the difference in prompts comes from the risk model only.

## Choices and limits

- **M1 only runs on requests the Task 1 policies allow.** A denied request is denied without a prompt, in both A+MFA and B. So A and A+MFA block the same requests, and A+MFA only adds friction.
- **If `riskModel.mfaAcrValues` is empty, M1 doesn't ask.** An empty list is our fallback if OTP doesn't work (then no `acr` value means "MFA used"). M1 would then ask on every admin page forever, so it lets the request through instead. We would see this in the results, because A+MFA would show no prompts.
- **The token's `acr` stays 2 for the whole session,** also after a token refresh. That is what "once per session" means here. A new login starts with `acr` 1 again.
- **Not part of Task 2.** Task 2 compares System A and System B. A+MFA is on its own branch (`feat-system-a-mfa`), and we agree its use with our supervisor.

## Tests

`tests/test_policies.py` has 6 tests for this mode: the prompt on an admin page, no prompt after MFA in the login, normal resources, Task 1 denies coming first, the empty `mfaAcrValues` fallback, and the mode names (`static-mfa` and `static_mfa` both work, anything unknown is `static`).
