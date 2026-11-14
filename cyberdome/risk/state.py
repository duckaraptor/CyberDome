'''

Saves the risk model's state in data/, so it survives a restart of the engines:

- data/risk_state.json      each session's risk state (model.new_session() describes the fields)
- data/risk_profiles.json   each user's usual behaviour (model.learn() describes the fields)
- data/risk_events.jsonl    every risk calculation, one JSON object per line, for the graphs and the demo

The Risk Engine and the Web UI are separate processes, so the two JSON files are only
read and written while a lock file is held. Files are replaced in one step (write a
temporary file, then rename it), so a crash can't leave half a file.

'''
import contextlib
import fcntl
import json
import os
import tempfile
from datetime import timedelta

from ..data_paths import RISK_EVENTS_FILE, RISK_PROFILES_FILE, RISK_STATE_FILE
from ..jsonl import append_record, read_records
from . import model

# A session with no request for this long counts as ended. 30 minutes is Keycloak's default "SSO Session Idle".
SESSION_IDLE_MINUTES = 30


def read_json(path, default):
    try:
        with open(path, 'r') as file:
            data = json.load(file)
        return data if isinstance(data, type(default)) else default
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path, data):
    folder = os.path.dirname(path) or '.'
    handle, temporary = tempfile.mkstemp(dir=folder, prefix='.tmp-', suffix='.json')
    try:
        with os.fdopen(handle, 'w') as file:
            json.dump(data, file, indent=2)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.remove(temporary)
        raise


class RiskStore:
    def __init__(self, state_file=RISK_STATE_FILE, profiles_file=RISK_PROFILES_FILE, events_file=RISK_EVENTS_FILE):
        self.state_file = state_file
        self.profiles_file = profiles_file
        self.events_file = events_file
        self.lock_file = state_file + '.lock'

    @contextlib.contextmanager
    def locked(self):
        '''
        Holds the lock and gives the sessions and profiles as dicts. Changes to them are saved
        when the block ends without an error:

            with store.locked() as (sessions, profiles):
                sessions[session_id] = ...
        '''
        with open(self.lock_file, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                sessions = read_json(self.state_file, {})
                profiles = read_json(self.profiles_file, {})
                before = json.dumps([sessions, profiles], sort_keys=True)
                yield sessions, profiles
                if json.dumps([sessions, profiles], sort_keys=True) != before:
                    write_json(self.state_file, sessions)
                    write_json(self.profiles_file, profiles)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def log_event(self, record):
        return append_record(self.events_file, record)

    def prune_events(self, retention_days, now):
        # Removes risk events older than retention_days (privacy). Returns how many were removed.
        # Unlike the audit log, this file is not a security record, so old entries may go.
        cutoff = model.parse_time(now) - timedelta(days=retention_days)
        with open(self.lock_file, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                records = read_records(self.events_file)
                kept = [record for record in records if not is_older(record, cutoff)]
                if len(kept) != len(records):
                    folder = os.path.dirname(self.events_file) or '.'
                    handle, temporary = tempfile.mkstemp(dir=folder, prefix='.tmp-', suffix='.jsonl')
                    with os.fdopen(handle, 'w') as file:
                        file.writelines(json.dumps(record) + '\n' for record in kept)
                    os.replace(temporary, self.events_file)
                return len(records) - len(kept)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


def is_older(record, cutoff):
    try:
        return model.parse_time(record.get('time', '')) < cutoff
    except ValueError:
        return False


def end_idle_sessions(sessions, profiles, now, idle_minutes=SESSION_IDLE_MINUTES):
    # Removes sessions with no request for idle_minutes, and adds their length to the user's
    # usual session length. Changes both dicts in place. Returns the IDs of the ended sessions.
    now = model.parse_time(now)
    ended = []
    for session_id, session in list(sessions.items()):
        # The last request, not the last risk change: the monitor can change the risk without a request
        last = model.parse_time(session.get('last_request_at') or session.get('risk_at') or session['started_at'])
        if model.minutes_between(last, now) < idle_minutes:
            continue
        user_id = session.get('user_id')
        if user_id:
            length = model.minutes_between(model.parse_time(session['started_at']), last)
            profiles[user_id] = model.learn_session_length(profiles.get(user_id), length)
        del sessions[session_id]
        ended.append(session_id)
    return ended
