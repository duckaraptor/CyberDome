'''

Logging and monitoring:

- /logging  the audit log (data/audit.log), newest first. See docs/audit-log.md.
- /risk     the risk monitor (Task 2): active sessions, their risk now, and their risk
            over time from data/risk_events.jsonl. See docs/monitoring.md.

'''
from flask import Blueprint, render_template, request

from datetime import datetime, timedelta

from authz import protected_resource
from cyberdome import audit
from cyberdome.config import load_policy_configuration
from cyberdome.data_paths import RISK_EVENTS_FILE
from cyberdome.jsonl import read_records_backwards
from cyberdome.policy import risk_mode
from cyberdome.risk import engine as risk_engine
from cyberdome.risk import model
from cyberdome.risk.defaults import risk_settings
from monitor import MONITOR_INTERVAL_SECONDS, sync_keycloak_events

bp = Blueprint('monitoring', __name__)

PAGE_SIZE = 200


@bp.route('/logging')
@protected_resource('logging')
def access_requests():
    # The monitor thread syncs every 10 seconds. Syncing here too shows the newest failed logins.
    # If Keycloak can't be reached, the page still shows what is already in the log.
    sync_keycloak_events()
    outcome = request.args.get('outcome') or None
    user = request.args.get('user') or None
    if outcome not in audit.OUTCOMES:
        outcome = None
    entries = audit.read_entries(limit=PAGE_SIZE, outcome=outcome, user=user)
    return render_template('logging_and_monitoring.html', entries=entries, outcomes=audit.OUTCOMES,
                           selected_outcome=outcome or '', selected_user=user or '', page_size=PAGE_SIZE)


# --- The risk monitor (Task 2, step 4) ---------------------------------------------------

CHART_WIDTH = 600
CHART_HEIGHT = 140
CHART_HOURS = 2         # how far back the chart goes
CHART_MAX_EVENTS = 5000  # risk events read from the end of the file, at most


def risk_history(session_ids, now):
    # The risk events of these sessions in the last CHART_HOURS, oldest first, per session
    start = now - timedelta(hours=CHART_HOURS)
    history = {session_id: [] for session_id in session_ids}
    for count, record in enumerate(read_records_backwards(RISK_EVENTS_FILE)):
        if count >= CHART_MAX_EVENTS:
            break
        try:
            time = model.parse_time(record.get('time', ''))
        except ValueError:
            continue
        if time < start:
            break
        if record.get('session_id') in history:
            history[record['session_id']].append((time, record))
    return {session_id: sorted(points, key=lambda point: point[0]) for session_id, points in history.items()}


def chart(points, thresholds, now):
    # An SVG polyline of the risk over time, with the thresholds as dashed lines.
    # Built on the server, so the page needs no JavaScript library.
    start = now - timedelta(hours=CHART_HOURS)
    span = (now - start).total_seconds()

    def x(time):
        return round((time - start).total_seconds() / span * CHART_WIDTH, 1)

    def y(risk):
        return round(CHART_HEIGHT - risk * CHART_HEIGHT, 1)

    return {
        'width': CHART_WIDTH,
        'height': CHART_HEIGHT,
        'line': ' '.join(f"{x(time)},{y(record['risk'])}" for time, record in points),
        'dots': [{'x': x(time), 'y': y(record['risk']), 'level': record.get('level'),
                  'title': f"{record.get('time')} {record.get('resource') or record.get('source', '')} "
                           f"risk {record['risk']:.3f} {record.get('level')}"} for time, record in points],
        'thresholds': [{'level': level, 'y': y(value)} for level, value in thresholds.items()],
    }


@bp.route('/risk')
@protected_resource('risk_monitoring')
def risk_monitor():
    config = load_policy_configuration()
    now = datetime.now().replace(microsecond=0)
    sessions = risk_engine.active_sessions(config, now)
    thresholds = risk_settings(config)['thresholds']
    history = risk_history([session['session_id'] for session in sessions], now)
    for session in sessions:
        session['chart'] = chart(history[session['session_id']], thresholds, now)
    return render_template('risk_monitor.html', sessions=sessions, mode=risk_mode(config), now=model.format_time(now),
                           chart_hours=CHART_HOURS, interval=MONITOR_INTERVAL_SECONDS)
