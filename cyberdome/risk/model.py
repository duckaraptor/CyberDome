'''

The risk model: turns the features into a risk score with memory, and the score into
a risk level.

    event risk    r_t = sum(weight * feature) / sum(weights), raised to a floor if one strong signal fires
    session risk  R_t = max(r_t, R_prev * 0.5 ^ (minutes since R_prev / halfLifeMinutes))
    level         LOW, MEDIUM, HIGH or CRITICAL, from the thresholds

evaluate() scores one access request. It takes the session's state and the user's
profile as plain dicts and returns new ones, and reads no files, so the tests and the
experiments can call it directly. state.py saves the dicts to data/.

The model and the reasons behind it are explained in docs/risk-model.md.

'''
import copy
from datetime import datetime

from . import features as f
from .defaults import FEATURES, LEVELS, risk_settings
from ..trust_algorithm import (DEFAULT_NIGHT_END, DEFAULT_NIGHT_START, config_time, country_list,
                               is_in_night_window)

TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

# How fast the user's usual request rate and session length follow new values (0 to 1)
LEARNING_RATE = 0.1


def parse_time(value):
    if isinstance(value, datetime):
        return value
    return datetime.strptime(value, TIME_FORMAT)


def format_time(value):
    return value.strftime(TIME_FORMAT)


def from_epoch(seconds):
    # Keycloak's auth_time is in seconds since 1970
    try:
        return datetime.fromtimestamp(float(seconds))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def minutes_between(start, end):
    return max((end - start).total_seconds() / 60.0, 0.0)


# --- Combining the features ---------------------------------------------------------

def weighted_risk(feature_scores, weights):
    # feature_scores: {feature: (score, reason)}. Returns the weighted mean, between 0 and 1.
    total = sum(weights[name] for name in feature_scores)
    if total <= 0:
        return 0.0
    return sum(weights[name] * score for name, (score, _) in feature_scores.items()) / total


def apply_floors(risk, feature_scores, settings):
    # A strong single signal sets a minimum, so the other features can't average it away.
    # Returns (risk, reason or None).
    floor_reason = None
    for floor in settings['floors']:
        score, reason = feature_scores.get(floor['feature'], (0.0, ''))
        if score >= float(floor['atLeast']):
            minimum = settings['thresholds'][floor['level']]
            if risk < minimum:
                risk = minimum
                floor_reason = f"{floor['feature']} {score:g} ({reason}) sets the risk to at least {floor['level']}"
    return risk, floor_reason


def decayed(previous_risk, minutes, half_life_minutes):
    # The previous risk, halved every half_life_minutes
    return previous_risk * 0.5 ** (minutes / half_life_minutes)


def level_of(risk, thresholds):
    if risk >= thresholds['CRITICAL']:
        return 'CRITICAL'
    if risk >= thresholds['HIGH']:
        return 'HIGH'
    if risk >= thresholds['MEDIUM']:
        return 'MEDIUM'
    return 'LOW'


def raise_level(level, steps):
    # For admin resources: the level used for the response is `steps` higher, at most CRITICAL
    return LEVELS[min(LEVELS.index(level) + max(steps, 0), len(LEVELS) - 1)]


def response_level(level, is_admin_resource, settings):
    return raise_level(level, settings['adminLevelBump']) if is_admin_resource else level


def top_features(feature_details, count=3):
    # The features that raised the risk most (weight times score), for the reason of a decision
    raised = sorted(((name, details) for name, details in feature_details.items() if details['score'] > 0),
                    key=lambda item: item[1]['score'] * item[1]['weight'], reverse=True)
    return ', '.join(f"{name} {details['score']:g} ({details['reason']})" for name, details in raised[:count])


# --- Sessions and step-ups ----------------------------------------------------------

def new_session(event, now):
    # The state of a session we see for the first time. Its start is the login time from the
    # token (auth_time) if we have it, otherwise this request.
    started = from_epoch(event.get('auth_time')) or now
    return {
        'session_id': event.get('session_id'),
        'user_id': event.get('user_id'),
        'username': event.get('username'),
        'started_at': format_time(min(started, now)),
        'first_ip': event.get('source_ip'),
        'first_location': event.get('location'),
        'device_id': event.get('device_id'),
        'last_resource': None,
        'risk': 0.0,
        'risk_at': None,
        'level': 'LOW',
        'step_up': None,
        'verified_level': None,
        'failed_step_ups': 0,
        'requests': 0,
    }


STEP_UP_KINDS = ('otp', 'full')


def request_step_up(session, kind, level, now):
    # Called when the policy asks for a step-up ('otp' or 'full') for a response level (MEDIUM or HIGH).
    # The next requests show whether it was passed. If the same or a stricter step-up is already
    # waiting, its time is kept, so reloading the page doesn't restart the timeout (F9).
    session = dict(session)
    waiting = session.get('step_up')
    if waiting and STEP_UP_KINDS.index(waiting['kind']) >= STEP_UP_KINDS.index(kind):
        return session
    session['step_up'] = {'kind': kind, 'level': level, 'requested_at': format_time(parse_time(now))}
    return session


def is_covered(response, verified_level):
    # A passed step-up covers its level and the levels below it, for the rest of the session.
    # CRITICAL is never covered.
    if response == 'CRITICAL' or verified_level not in LEVELS:
        return False
    return LEVELS.index(response) <= LEVELS.index(verified_level)


def step_up_passed(step_up, event, settings):
    # Passed if the token shows a login after the step-up was asked for, with MFA (acr) if
    # mfaAcrValues is set. Both values come from Keycloak's token, so the browser can't fake them.
    login = from_epoch(event.get('auth_time'))
    if login is None or login < parse_time(step_up['requested_at']):
        return False
    if settings['mfaAcrValues']:
        return str(event.get('acr')) in settings['mfaAcrValues']
    return True


def check_step_up(session, event, now, settings):
    # Returns (session, 'passed', 'failed' or None)
    step_up = session.get('step_up')
    if not step_up:
        return session, None
    session = dict(session)
    if step_up_passed(step_up, event, settings):
        session['step_up'] = None
        session['failed_step_ups'] = 0
        # The highest level a passed step-up covered so far in this session
        if not is_covered(step_up.get('level') or 'MEDIUM', session.get('verified_level')):
            session['verified_level'] = step_up.get('level') or 'MEDIUM'
        # The verified device and network become the session's own, so they don't keep counting as changes
        session['first_ip'] = event.get('source_ip')
        session['first_location'] = event.get('location')
        session['device_id'] = event.get('device_id')
        return session, 'passed'
    if minutes_between(parse_time(step_up['requested_at']), now) >= settings['stepUpTimeoutMinutes']:
        session['step_up'] = None
        session['failed_step_ups'] = session.get('failed_step_ups', 0) + 1
        return session, 'failed'
    return session, None


# --- The score ----------------------------------------------------------------------

def has_history(profile, settings):
    return (profile or {}).get('requests', 0) >= settings['minHistory']


def score_features(event, session, profile, signals, config, settings, now):
    # All 9 features for this request: {feature: (score, reason)}
    profile = profile or {}
    history = has_history(profile, settings)
    resources = config.get('resources') or {}
    admin_resources = [name for name, entry in resources.items() if (entry or {}).get('adminResource')]
    night = is_in_night_window(now.time(), config_time(config, 'periodStartInput', DEFAULT_NIGHT_START),
                               config_time(config, 'periodEndInput', DEFAULT_NIGHT_END))

    return {
        'accessFrequency': f.access_frequency(signals.get('recent_requests', 0),
                                              profile.get('usual_requests') if history else None,
                                              settings['accessFrequency']),
        'resourceSequence': f.resource_sequence(session.get('last_resource'), event.get('resource'), profile,
                                                list(resources), admin_resources, signals.get('recent_denials', 0),
                                                history, settings['resourceSequence']),
        'sessionDuration': f.session_duration(minutes_between(parse_time(session['started_at']), now),
                                              profile.get('session_minutes') if history else None,
                                              settings['sessionDuration']),
        'authFailures': f.auth_failures(signals.get('auth_failures', 0), settings['authFailures']),
        'timeOfDay': f.time_of_day(now.hour, profile.get('hours') or {}, history, night, settings['timeOfDay']),
        'deviceFamiliarity': f.device_familiarity(event.get('new_device'), event.get('device_id'),
                                                  session.get('device_id'), settings['deviceFamiliarity']),
        'networkChange': f.network_change(event.get('source_ip'), event.get('location'), session.get('first_ip'),
                                          session.get('first_location'), country_list(config, 'highRiskLocations'),
                                          country_list(config, 'mediumRiskLocations'), settings['networkChange']),
        'identityAssurance': f.identity_assurance(event.get('acr'), settings['mfaAcrValues'],
                                                  signals.get('email_verified', False), settings['identityAssurance']),
        'mfaReaction': f.mfa_reaction(session.get('failed_step_ups', 0), settings['mfaReaction']),
    }


def evaluate(event, session, profile, signals, config, now=None):
    '''
    Scores one access request.

    event:   the request record (user_id, resource, access_request_time, session_id, auth_time, acr,
             source_ip, location, device_id, new_device)
    session: the session's state from the last request, or None for a new session
    profile: the user's usual behaviour (see learn()), or None
    signals: counts from outside the session: recent_requests, auth_failures, recent_denials, email_verified
    config:  the whole policy configuration (riskModel, the resource table, risk lists, night window)

    Returns (result, session): the result for the Policy Engine and the audit log, and the
    session's new state.
    '''
    settings = risk_settings(config)
    now = parse_time(now or event['access_request_time'])
    session = copy.deepcopy(session) if session else new_session(event, now)

    session, step_up = check_step_up(session, event, now, settings)
    feature_scores = score_features(event, session, profile, signals or {}, config, settings, now)

    event_risk, floor_reason = apply_floors(weighted_risk(feature_scores, settings['weights']), feature_scores, settings)

    previous_risk = session.get('risk', 0.0)
    previous_at = parse_time(session['risk_at']) if session.get('risk_at') else now
    carried = decayed(previous_risk, minutes_between(previous_at, now), settings['halfLifeMinutes'])
    if step_up == 'passed' or not settings['memory']:
        risk = event_risk  # a passed step-up starts again from this request (recovery)
    else:
        risk = max(event_risk, carried)

    level = level_of(risk, settings['thresholds'])
    previous_resource = session.get('last_resource')
    session.update(risk=round(risk, 4), risk_at=format_time(now), level=level, last_resource=event.get('resource'),
                   requests=session.get('requests', 0) + 1)

    weights_total = sum(settings['weights'].values())
    feature_details = {
        name: {'score': round(score, 3), 'weight': round(settings['weights'][name] / weights_total, 3), 'reason': reason}
        for name, (score, reason) in ((name, feature_scores[name]) for name in FEATURES)
    }
    result = {
        'risk': round(risk, 4),
        'event_risk': round(event_risk, 4),
        'previous_risk': round(previous_risk, 4),
        'carried_risk': round(carried, 4),
        'level': level,
        'floor': floor_reason,
        'step_up': step_up,
        'verified_level': session.get('verified_level'),
        'memory': settings['memory'],
        'previous_resource': previous_resource,
        'features': feature_details,
        'top_features': top_features(feature_details),
    }
    return result, session


# --- Learning the user's usual behaviour -------------------------------------------

def empty_profile():
    return {'requests': 0, 'hours': {}, 'resources': {}, 'transitions': {}, 'usual_requests': None,
            'session_minutes': None}


def moving_average(current, value):
    return value if current is None else current + LEARNING_RATE * (value - current)


def learn(profile, event, previous_resource, recent_requests, now=None):
    '''
    Adds one request to the user's profile. Call it only for requests that were allowed at
    LOW risk, so an attacker's activity doesn't become the user's "usual" behaviour.
    The profile keeps counts, not a list of requests (privacy, see docs/risk-model.md).
    '''
    profile = copy.deepcopy(profile) if profile else empty_profile()
    now = parse_time(now or event['access_request_time'])
    resource = event.get('resource')

    profile['requests'] = profile.get('requests', 0) + 1
    hours = profile.setdefault('hours', {})
    hours[str(now.hour)] = hours.get(str(now.hour), 0) + 1
    resources = profile.setdefault('resources', {})
    resources[resource] = resources.get(resource, 0) + 1
    if previous_resource is not None:
        moves = profile.setdefault('transitions', {}).setdefault(previous_resource, {})
        moves[resource] = moves.get(resource, 0) + 1
    profile['usual_requests'] = moving_average(profile.get('usual_requests'), recent_requests)
    return profile


def learn_session_length(profile, session_minutes):
    # Called when a user's session ends (or a new one starts), with how long the old one lasted
    profile = copy.deepcopy(profile) if profile else empty_profile()
    profile['session_minutes'] = moving_average(profile.get('session_minutes'), session_minutes)
    return profile
