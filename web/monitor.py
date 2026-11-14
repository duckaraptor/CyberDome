'''

Continuous monitoring (Task 2, step 4): a background thread in the Web UI that runs
every MONITOR_INTERVAL_SECONDS, also when nobody sends a request.

Each round it:

1. pulls Keycloak's login events into data/ (events.json, auth_data.json) and copies
   new failed logins into the audit log. Before Task 2 this only happened when someone
   opened the home page or /logging, so failed logins arrived late.
2. in adaptive mode, recalculates every active session's risk (engine.monitor_sessions).
   Failed logins for a logged-in user raise their session's risk straight away.
3. ends a session that reaches CRITICAL, at Keycloak (admin API) and in the risk state,
   and writes a RISK_ALERT audit entry.

In NIST SP 800-207 terms this thread is the Policy Administrator: it acts on the risk by
ending sessions. How it works, and why, is explained in docs/monitoring.md.

'''
import threading
import time
from datetime import datetime

from cyberdome import audit
from cyberdome.config import load_policy_configuration
from cyberdome.data_paths import EVENTS_FILE
from cyberdome.policy import risk_mode
from cyberdome.risk import engine as risk_engine
from cyberdome.trust_signals import load_events_data, process_events, store_keycloak_events
from extensions import keycloak_admin
from keycloak_config import KEYCLOAK_REALM

MONITOR_INTERVAL_SECONDS = 10

# One sync at a time: the monitor thread and the pages share data/events.json and data/auth_data.json
_sync_lock = threading.Lock()
_thread = None
_thread_lock = threading.Lock()
_stop = threading.Event()


def sync_keycloak_events():
    # Pull Keycloak's newest login events into data/ and copy new failed logins into the audit log.
    # If Keycloak can't be reached, what is already in data/ stays as it is.
    with _sync_lock:
        try:
            store_keycloak_events(keycloak_admin)
            events = load_events_data(EVENTS_FILE) or []
            if events:
                process_events(events)
            return audit.import_keycloak_login_errors(events)
        except Exception as e:
            print(f"Could not sync the login events from Keycloak: {e}")
            return 0


def end_keycloak_session(session_id):
    # Ends one Keycloak session through the admin API. The monitor has no refresh token of the
    # user, so it can't log out the way the Web UI does for a request (step_up.end_session).
    response = keycloak_admin.connection.raw_delete(f"admin/realms/{KEYCLOAK_REALM}/sessions/{session_id}")
    return response.status_code in (200, 204)


def handle_critical(change):
    session_id = change['session_id']
    result = change['result']
    try:
        ended = end_keycloak_session(session_id)
    except Exception as e:
        print(f"Could not end the Keycloak session {session_id}: {e}")
        ended = False
    risk_engine.end_session(session_id)
    reason = (f"Session risk {result['risk']:.3f} (CRITICAL) without a request. Raised by: {result['top_features']}. "
              + ('The session was ended at Keycloak' if ended else 'Keycloak could not end the session'))
    audit.log_decision('RISK_ALERT', reason, 'Risk Monitor',
                       request={'username': change['username'], 'user_id': change['user_id']},
                       session_id=session_id, risk_score=result['risk'], risk_level='CRITICAL',
                       risk_features=result['features'], risk_floor=result['floor'])
    print(f"Risk Monitor: {reason} ({change['username']}, session {session_id})")


def run_once(now=None):
    sync_keycloak_events()
    config = load_policy_configuration()
    if risk_mode(config) != 'adaptive':
        return []
    now = now or datetime.now()
    raised = risk_engine.monitor_sessions(config, now)
    for change in raised:
        result = change['result']
        print(f"Risk Monitor: {change['username']} session {change['session_id']} "
              f"{result['previous_level']} -> {result['level']} ({result['risk']:.3f}): {result['top_features']}")
        if result['level'] == 'CRITICAL':
            handle_critical(change)
    return raised


def loop():
    while not _stop.is_set():
        started = time.time()
        try:
            run_once()
        except Exception as e:
            # Keep monitoring after an error, for example a broken line in a data file
            print(f"Risk Monitor round failed: {type(e).__name__}: {e}")
        _stop.wait(max(MONITOR_INTERVAL_SECONDS - (time.time() - started), 1))


def start_monitor():
    # Started on the first request (app.py), like the Web UI's node, so that with Flask's
    # debug reloader only the process that serves requests runs it.
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _stop.clear()
            _thread = threading.Thread(target=loop, name='risk-monitor', daemon=True)
            _thread.start()
            print(f"Risk Monitor started (every {MONITOR_INTERVAL_SECONDS} seconds)")


def stop_monitor():
    _stop.set()
