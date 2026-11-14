'''

The Risk Engine: connects the risk model to the running system (Task 2).

The Trust Engine node (node 2) calls assess() for each request when riskMode is
adaptive. The Policy Engine node (node 3) calls record_decision() after it decided,
so the session knows about a step-up it asked for, and the user's profile learns
from requests that were allowed at LOW risk.

Both read and write the risk state in data/ under one lock (state.py), because they
run in separate processes.

How this fits in the request path is explained in docs/risk-model.md and docs/policies.md.

'''
import time

from ..data_paths import ACCESS_REQUESTS_FILE, USER_DATA_FILE
from ..trust_signals import count_recent_access_requests, get_user_identity_data_by_id
from . import model
from .defaults import risk_settings
from .signals import count_auth_failures, count_recent_denials
from .state import RiskStore, end_idle_sessions

# Old risk events are removed at most this often (seconds), not on every request
PRUNE_EVERY_SECONDS = 60 * 60
_last_pruned = 0.0


def session_key(access_request):
    # The Keycloak session the request belongs to (the token's sid). Without one we can't keep
    # a session's risk, so the caller gets an error and the Policy Engine denies (fail closed).
    session_id = access_request.get('session_id')
    if not session_id:
        raise ValueError('The request has no session ID, so its session risk cannot be kept')
    return str(session_id)


def email_is_verified(user_id, user_data_file=USER_DATA_FILE):
    try:
        identity = get_user_identity_data_by_id(user_id, user_data_file) or {}
    except (FileNotFoundError, ValueError):
        return False
    return bool(identity.get('email_verified'))


def collect_signals(access_request, settings, access_requests_file=ACCESS_REQUESTS_FILE):
    # The counts from outside the session (see model.evaluate)
    user_id = access_request['user_id']
    now = access_request['access_request_time']
    return {
        'recent_requests': count_recent_access_requests(user_id, now, settings['accessFrequency']['windowMinutes'],
                                                        access_requests_file, exclude_id=access_request.get('ID')),
        'auth_failures': count_auth_failures(user_id, now, settings['authFailures']['windowMinutes']),
        'recent_denials': count_recent_denials(user_id, now, settings['resourceSequence']['denialWindowMinutes']),
        'email_verified': email_is_verified(user_id),
    }


def event_record(access_request, result, signals):
    # One line of data/risk_events.jsonl: what the graphs and the demo need, no page content
    return {
        'time': access_request['access_request_time'],
        'request_id': access_request.get('ID'),
        'session_id': access_request.get('session_id'),
        'user_id': access_request.get('user_id'),
        'username': access_request.get('username'),
        'resource': access_request.get('resource'),
        'action': access_request.get('action'),
        'risk': result['risk'],
        'event_risk': result['event_risk'],
        'carried_risk': result['carried_risk'],
        'level': result['level'],
        'floor': result['floor'],
        'step_up': result['step_up'],
        'features': {name: details['score'] for name, details in result['features'].items()},
        'signals': signals,
    }


def prune_now_and_then(store, settings, now):
    global _last_pruned
    if time.time() - _last_pruned < PRUNE_EVERY_SECONDS:
        return
    _last_pruned = time.time()
    try:
        store.prune_events(settings['retentionDays'], now)
    except OSError as e:
        print(f"Could not remove old risk events: {e}")


def assess(access_request, config, store=None, signals=None):
    '''
    Scores one request. Returns the model's result (model.evaluate) plus the session ID and the
    signals it used. Raises an error if the request can't be scored. The caller then sends no
    risk score, and the Policy Engine denies.
    '''
    store = store or RiskStore()
    settings = risk_settings(config)
    key = session_key(access_request)
    now = access_request['access_request_time']
    if signals is None:
        signals = collect_signals(access_request, settings)

    with store.locked() as (sessions, profiles):
        end_idle_sessions(sessions, profiles, now)
        session = sessions.get(key)
        if session and session.get('user_id') != access_request.get('user_id'):
            raise ValueError('The session belongs to another user')
        result, sessions[key] = model.evaluate(access_request, session, profiles.get(access_request['user_id']),
                                               signals, config)

    result = dict(result, session_id=key, signals=signals)
    try:
        store.log_event(event_record(access_request, result, signals))
    except OSError as e:
        print(f"Could not write the risk event: {e}")
    prune_now_and_then(store, settings, now)
    return result


def record_decision(access_request, risk, decision, store=None):
    '''
    Called by the Policy Engine after it decided, with the risk result it decided on:

    - a step-up decision marks the session "step-up waiting", so the next requests can see
      whether it was passed (model.check_step_up)
    - an allow at LOW risk teaches the user's profile (model.learn). Other requests don't,
      so an attacker's behaviour can't become the user's usual behaviour.
    '''
    if not risk or not risk.get('session_id'):
        return
    store = store or RiskStore()
    now = access_request['access_request_time']
    with store.locked() as (sessions, profiles):
        session = sessions.get(risk['session_id'])
        if session is None:
            return
        if decision.get('outcome') == 'STEP_UP_REQUIRED':
            sessions[risk['session_id']] = model.request_step_up(session, decision['step_up'],
                                                                 decision['response_level'], now)
        elif decision.get('outcome') == 'ALLOW' and risk.get('level') == 'LOW':
            user_id = access_request['user_id']
            profiles[user_id] = model.learn(profiles.get(user_id), access_request, risk.get('previous_resource'),
                                            (risk.get('signals') or {}).get('recent_requests', 0))


def monitor_sessions(config, now, store=None, count_failures=count_auth_failures):
    '''
    Continuous monitoring: recalculates every active session's risk without a request
    (model.reassess). Called by the Web UI's monitor thread every few seconds.

    Returns the sessions whose risk went up, as dicts with session_id, user_id, username and the
    model's result. The caller ends the ones at CRITICAL. Each rise is also logged as a risk event
    with source "monitor".
    '''
    store = store or RiskStore()
    settings = risk_settings(config)
    now = model.format_time(model.parse_time(now))
    window = settings['authFailures']['windowMinutes']
    raised = []
    with store.locked() as (sessions, profiles):
        end_idle_sessions(sessions, profiles, now)
        for session_id, session in sessions.items():
            signals = {'auth_failures': count_failures(session.get('user_id'), now, window)}
            result, sessions[session_id] = model.reassess(session, signals, config, now)
            if result:
                raised.append({'session_id': session_id, 'user_id': session.get('user_id'),
                               'username': session.get('username'), 'result': result, 'signals': signals})

    for change in raised:
        record = event_record({'access_request_time': now, 'session_id': change['session_id'],
                               'user_id': change['user_id'], 'username': change['username']},
                              change['result'], change['signals'])
        record['source'] = 'monitor'
        try:
            store.log_event(record)
        except OSError as e:
            print(f"Could not write the risk event: {e}")
    return raised


def active_sessions(config, now, store=None):
    # Every active session with its risk decayed to now, highest first (for the /risk page)
    store = store or RiskStore()
    settings = risk_settings(config)
    now = model.parse_time(now)
    with store.locked() as (sessions, _profiles):
        sessions = dict(sessions)
    rows = []
    for session_id, session in sessions.items():
        risk_at = model.parse_time(session['risk_at']) if session.get('risk_at') else now
        risk = model.decayed(session.get('risk', 0.0), model.minutes_between(risk_at, now), settings['halfLifeMinutes'])
        rows.append(dict(session, session_id=session_id, risk_now=round(risk, 4),
                         level_now=model.level_of(risk, settings['thresholds'])))
    return sorted(rows, key=lambda row: row['risk_now'], reverse=True)


def end_session(session_id, store=None):
    '''
    Removes a session's risk state when the session is ended at CRITICAL risk. Its length doesn't
    teach the user's usual session length, because it ended for a reason. The user's profile and
    failed logins stay, so a new session during an attack doesn't start clean.
    '''
    if not session_id:
        return False
    store = store or RiskStore()
    with store.locked() as (sessions, _profiles):
        return sessions.pop(str(session_id), None) is not None
