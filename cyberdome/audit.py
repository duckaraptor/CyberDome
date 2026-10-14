'''

The audit log (assignment section 3.5): one entry for every access decision, from the
Policy Engine, the Web UI and Keycloak's failed logins.

Entries are appended to data/audit.log, one JSON object per line, and never changed.
Each entry has the task's data model fields (user, role, resource, action, device_id,
source_ip, decision, trust_score, reason), plus the outcome category, the policy, who
decided, the trust breakdown and the context.

The log and the reasons behind it are explained in docs/audit-log.md.

'''
import json
from datetime import datetime

from .data_paths import AUDIT_LOG_FILE, KEYCLOAK_AUDIT_STATE_FILE
from .jsonl import append_record, read_records_backwards

OUTCOMES = ('ALLOW', 'DENY', 'AUTHENTICATION_FAILURE', 'POLICY_VIOLATION')


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def build_entry(outcome, reason, decided_by, request=None, decision=None, trust_score=None, trust_factors=None,
                time=None, **extra):
    # One audit entry. `request` is the request record (or the part of it that is known),
    # `decision` is the Policy Engine's decision (policy_id, policy_name).
    if outcome not in OUTCOMES:
        raise ValueError(f'Unknown audit outcome: {outcome}')
    request = request or {}
    decision = decision or {}
    roles = list(request.get('roles') or [])
    entry = {
        'time': time or now(),
        'outcome': outcome,
        # The task's data model: the decision, the trust score and the reason ...
        'decision': 'ALLOW' if outcome == 'ALLOW' else 'DENY',
        'trust_score': trust_score,
        'reason': reason,
        'policy_id': decision.get('policy_id'),
        'policy_name': decision.get('policy_name'),
        'decided_by': decided_by,
        # ... and the request: user, role, resource, action, device_id, source_ip
        'user': request.get('username'),
        'role': ', '.join(roles) or None,
        'resource': request.get('resource'),
        'action': request.get('action'),
        'device_id': request.get('device_id'),
        'source_ip': request.get('source_ip'),
        # More detail, to tell why the decision was made
        'user_id': request.get('user_id'),
        'roles': roles,
        'path': request.get('path'),
        'location': request.get('location'),
        'new_device': request.get('new_device'),
        'authentication_status': request.get('authentication_status'),
        'request_id': request.get('ID'),
        'trust_factors': trust_factors,
    }
    entry.update(extra)
    return entry


def log_decision(outcome, reason, decided_by, path=AUDIT_LOG_FILE, **details):
    # Build an entry and append it to the audit log. Returns the entry.
    return append_record(path, build_entry(outcome, reason, decided_by, **details))


def read_entries(limit=200, outcome=None, user=None, path=AUDIT_LOG_FILE):
    # The newest entries first, optionally only one outcome or one user
    entries = []
    for entry in read_records_backwards(path):
        if outcome and entry.get('outcome') != outcome:
            continue
        if user and user not in (entry.get('user'), entry.get('user_id')):
            continue
        entries.append(entry)
        if len(entries) >= limit:
            break
    return entries


def find_entry(request_id, path=AUDIT_LOG_FILE):
    # The Policy Engine's entry for an access request, or None
    for entry in read_records_backwards(path):
        if str(entry.get('request_id')) == str(request_id) and entry.get('decided_by') == 'Policy Engine':
            return entry
    return None


# --- Failed logins from Keycloak ---------------------------------------------------

def read_last_synced_time(state_file):
    try:
        with open(state_file, 'r') as file:
            return json.load(file).get('last_event_time', 0)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0


def import_keycloak_login_errors(events, path=AUDIT_LOG_FILE, state_file=KEYCLOAK_AUDIT_STATE_FILE):
    # Copy Keycloak's LOGIN_ERROR events (failed logins) that aren't in the audit log yet.
    # `events` are the events from data/events.json. Returns how many were copied.
    last_synced = read_last_synced_time(state_file)
    new_errors = sorted((event for event in events or []
                         if event.get('type') == 'LOGIN_ERROR' and (event.get('time') or 0) > last_synced),
                        key=lambda event: event['time'])
    for event in new_errors:
        error = event.get('error') or 'wrong password or unknown user'
        log_decision(
            'AUTHENTICATION_FAILURE', f'Failed login at Keycloak ({error})', 'Keycloak', path=path,
            request={'username': event.get('username'), 'user_id': event.get('user_id'),
                     'source_ip': event.get('ip_address'), 'authentication_status': 'failed'},
            time=datetime.fromtimestamp(event['time'] / 1000).strftime('%Y-%m-%d %H:%M:%S'))
    if new_errors:
        with open(state_file, 'w') as file:
            json.dump({'last_event_time': new_errors[-1]['time']}, file)
    return len(new_errors)
