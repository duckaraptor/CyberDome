'''

The 9 risk features. Each one returns (score, reason): a score between 0 (normal) and
1 (very unusual), and a short reason for the logs and the audit entry.

They take plain values, not files, so the tests and the experiments can call them
directly. `s` is the feature's own settings from defaults.risk_settings().

What each feature measures, and why, is explained in docs/risk-model.md.

'''


def clamp(value, low=0.0, high=1.0):
    return max(low, min(high, value))


def linear(value, start, end):
    # 0 at `start` or below, 1 at `end` or above, a straight line in between
    if end <= start:
        return 1.0 if value > start else 0.0
    return clamp((value - start) / (end - start))


# --- F1 Access frequency ----------------------------------------------------------

def access_frequency(recent_requests, usual_requests, s):
    # recent_requests: the user's requests in the last window, not counting this one.
    # usual_requests: the user's usual number per window (None if not known yet).
    # Up to the usual rate scores 0. capRatio times the usual rate scores 1.
    baseline = max(usual_requests or 0, s['minBaseline'])
    ratio = recent_requests / baseline
    score = linear(ratio, 1.0, s['capRatio'])
    return score, (f"{recent_requests} requests in the last {s['windowMinutes']:g} minutes, "
                   f"usual up to {baseline:.0f}")


# --- F2 Resource-access sequence --------------------------------------------------

def transition_probability(previous, resource, transitions, resource_counts, known_resources, smoothing):
    # How likely this resource is for the user, after the previous one (or overall at the start
    # of a session). Laplace smoothing: every count gets `smoothing` added, so an unseen move
    # is unlikely but not impossible.
    options = max(len(set(known_resources) | set(resource_counts) | {resource}), 1)
    if previous is not None and previous in transitions:
        counts = transitions[previous]
    else:
        counts = resource_counts
    total = sum(counts.values())
    return (counts.get(resource, 0) + smoothing) / (total + smoothing * options)


def resource_sequence(previous, resource, profile, known_resources, admin_resources, recent_denials, has_history, s):
    # profile: the user's 'transitions' {from: {to: count}} and 'resources' {resource: count}.
    # known_resources: every resource in the role table. admin_resources: the ones marked adminResource.
    # recent_denials: the user's requests the role table (P2) denied in the last denialWindowMinutes.
    reasons = []
    if has_history:
        probability = transition_probability(previous, resource, profile.get('transitions') or {},
                                             profile.get('resources') or {}, known_resources, s['smoothing'])
        score = 1.0 - probability
        start = f'after {previous}' if previous else 'at the start of a session'
        reasons.append(f'{resource} {start} is {probability:.0%} likely for this user')
    else:
        score = 0.5
        reasons.append('no baseline yet')

    if resource in admin_resources:
        counts = profile.get('resources') or {}
        total = sum(counts.values())
        admin_share = (sum(counts.get(name, 0) for name in admin_resources) / total) if total else 0.0
        if admin_share < s['rareAdminShare']:
            score += s['adminJump']
            reasons.append(f'admin resource, {admin_share:.0%} of this user\'s requests are for admin resources')

    if recent_denials:
        score += s['perDenial'] * recent_denials
        reasons.append(f"{recent_denials} requests denied by the role table in the last {s['denialWindowMinutes']:g} minutes")

    return clamp(score), ', '.join(reasons)


# --- F3 Session duration ----------------------------------------------------------

def session_duration(session_minutes, usual_minutes, s):
    # Up to the usual session length scores 0. capMultiple times the usual length scores 1.
    usual = usual_minutes if usual_minutes and usual_minutes > 0 else s['usualMinutes']
    score = linear(session_minutes, usual, usual * s['capMultiple'])
    return score, f'session is {session_minutes:.0f} minutes old, usual up to {usual:.0f}'


# --- F4 Authentication failures ---------------------------------------------------

def auth_failures(failures, s):
    score = clamp(failures / s['cap']) if s['cap'] > 0 else float(failures > 0)
    return score, f"{failures} failed logins in the last {s['windowMinutes']:g} minutes"


# --- F5 Time of day ---------------------------------------------------------------

def hours_in_band(hour, band_hours):
    # The hours around `hour`, for example 13 with a band of 3 gives 12, 13 and 14. Wraps around midnight.
    width = max(int(band_hours), 1)
    first = hour - (width - 1) // 2
    return [(first + offset) % 24 for offset in range(width)]


def time_of_day(hour, hour_counts, has_history, inside_night_window, s):
    # hour_counts: how many of the user's allowed requests were in each hour, {'0': n, ..., '23': n}.
    # With history: a band with at least normalShare of the requests scores 0, an empty band scores 1.
    # Without history: the night window from Task 1 (nightScore inside, 0 outside).
    if not has_history:
        if inside_night_window:
            return s['nightScore'], 'inside the night window (no baseline yet)'
        return 0.0, 'outside the night window (no baseline yet)'

    total = sum(hour_counts.values())
    in_band = sum(hour_counts.get(str(h), 0) for h in hours_in_band(hour, s['bandHours']))
    share = in_band / total if total else 0.0
    score = clamp(1.0 - share / s['normalShare']) if s['normalShare'] > 0 else 0.0
    return score, f'{share:.0%} of this user\'s requests are around {hour:02d}:00'


# --- F6 Device familiarity --------------------------------------------------------

def device_familiarity(new_device, device_id, session_device_id, s):
    # A device change inside the session is worse than a new device at login: one session
    # should stay on one browser, so a change can mean a stolen session.
    if session_device_id and device_id and device_id != session_device_id:
        return s['changedInSession'], 'device changed inside the session'
    if new_device is False:
        return 0.0, 'known device'
    return s['newDevice'], 'new device'  # a missing value counts as new (fail safe)


# --- F7 Network or context change -------------------------------------------------

def network_change(source_ip, location, session_ip, session_location, high_risk, medium_risk, s):
    # The highest of: a high-risk location, a change of IP or location inside the session,
    # a medium-risk location
    location = str(location or 'Unknown').strip().upper()
    session_location = str(session_location or '').strip().upper()
    findings = []
    if location in high_risk:
        findings.append((s['highRiskLocation'], f'{location} is a high-risk location'))
    changed = []
    if session_ip and source_ip and source_ip != session_ip:
        changed.append(f'IP {session_ip} -> {source_ip}')
    if session_location and location != session_location:
        changed.append(f'location {session_location} -> {location}')
    if changed:
        findings.append((s['changed'], 'changed inside the session: ' + ', '.join(changed)))
    if location in medium_risk:
        findings.append((s['mediumRiskLocation'], f'{location} is a medium-risk location'))
    if not findings:
        return 0.0, f'same network as the start of the session ({location})'
    return max(findings, key=lambda finding: finding[0])


# --- F8 Identity assurance --------------------------------------------------------

def identity_assurance(acr, mfa_acr_values, email_verified, s):
    # MFA counts only if it was used in this login (the token's acr claim), not if it's only set up
    mfa_used = acr is not None and str(acr) in mfa_acr_values
    score = 0.0 if mfa_used else s['passwordOnly']
    if not email_verified:
        score += s['unverifiedEmail']
    reason = f"{'MFA used in this login' if mfa_used else 'password only'}, email {'verified' if email_verified else 'not verified'}"
    return clamp(score), reason


# --- F9 Reaction to MFA challenges ------------------------------------------------

def mfa_reaction(failed_step_ups, s):
    score = clamp(failed_step_ups / s['cap']) if s['cap'] > 0 else float(failed_step_ups > 0)
    return score, f'{failed_step_ups} step-ups failed or abandoned in this session'
