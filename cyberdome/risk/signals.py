'''

Counts from outside the session that the risk features need, read from the files in data/:

- failed logins at Keycloak (F4), from data/auth_data.json
- requests the role table (policy P2) denied (F2), from the audit log

'''
import json
from datetime import timedelta

from ..data_paths import AUDIT_LOG_FILE, AUTH_DATA_FILE
from ..jsonl import read_records_backwards
from .model import parse_time

# The audit log is read from the end. Entries written at the same moment can be a little
# out of order, so reading stops this much before the start of the window.
ORDER_SLACK = timedelta(minutes=1)


def count_auth_failures(user_id, now, minutes, auth_data_file=AUTH_DATA_FILE):
    # Failed logins (auth_status 0) of this user in the `minutes` before `now`.
    # Keycloak's event times are in milliseconds.
    now = parse_time(now)
    start_ms = (now - timedelta(minutes=minutes)).timestamp() * 1000
    end_ms = now.timestamp() * 1000
    try:
        with open(auth_data_file, 'r') as file:
            attempts = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0
    return sum(1 for attempt in attempts
               if attempt.get('user_id') == user_id and attempt.get('auth_status') == 0
               and start_ms <= (attempt.get('time') or 0) <= end_ms)


def count_recent_denials(user_id, now, minutes, audit_file=AUDIT_LOG_FILE):
    # This user's requests that the role table (P2, outcome POLICY_VIOLATION) denied in the `minutes` before `now`
    now = parse_time(now)
    start = now - timedelta(minutes=minutes)
    count = 0
    for entry in read_records_backwards(audit_file):
        try:
            logged = parse_time(entry.get('time', ''))
        except ValueError:
            continue
        if logged < start - ORDER_SLACK:
            break
        if (entry.get('user_id') == user_id and entry.get('outcome') == 'POLICY_VIOLATION'
                and entry.get('decided_by') == 'Policy Engine' and start <= logged <= now):
            count += 1
    return count
