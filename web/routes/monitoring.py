'''

Logging and monitoring: shows the audit log (data/audit.log), newest first.
See docs/audit-log.md.

'''
from flask import Blueprint, render_template, request

from authz import protected_resource
from cyberdome import audit
from cyberdome.data_paths import EVENTS_FILE
from cyberdome.trust_signals import load_events_data, store_keycloak_events
from extensions import keycloak_admin

bp = Blueprint('monitoring', __name__)

PAGE_SIZE = 200


def sync_failed_logins():
    # Fetch Keycloak's newest events and copy new failed logins into the audit log.
    # If Keycloak can't be reached, the page still shows what is already in the log.
    try:
        store_keycloak_events(keycloak_admin)
        audit.import_keycloak_login_errors(load_events_data(EVENTS_FILE) or [])
    except Exception as e:
        print(f"Could not sync failed logins from Keycloak: {e}")


@bp.route('/logging')
@protected_resource('logging')
def access_requests():
    sync_failed_logins()
    outcome = request.args.get('outcome') or None
    user = request.args.get('user') or None
    if outcome not in audit.OUTCOMES:
        outcome = None
    entries = audit.read_entries(limit=PAGE_SIZE, outcome=outcome, user=user)
    return render_template('logging_and_monitoring.html', entries=entries, outcomes=audit.OUTCOMES,
                           selected_outcome=outcome or '', selected_user=user or '', page_size=PAGE_SIZE)
