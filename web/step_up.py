'''

The adaptive responses in the Web UI (Task 2, step 3). The Web UI is the policy
enforcement point: the Policy Engine decides, and this module carries out a step-up
or the end of a session.

    STEP_UP_REQUIRED, otp   send the user to Keycloak for an OTP (acr_values=2)
    STEP_UP_REQUIRED, full  send the user to Keycloak for the password and an OTP (acr_values=2, prompt=login)
    RISK_ALERT              end the session at Keycloak and in the risk state, then refuse

Which step-up is needed is kept in the Flask session, which the server signs. The
/step-up page reads it from there, not from the URL, so a user can't ask for an OTP
when a full login is needed.

How the step-up works, and why, is explained in docs/step-up.md.

'''
import time

from flask import g, request, session, url_for
from flask_oidc.views import validate_return_url

from cyberdome.risk import engine as risk_engine
from extensions import oidc
from keycloak_config import KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, REVOCATION_URL
from keycloak_functions import revoke_token

SESSION_KEY = 'cyberdome_step_up'
KINDS = ('otp', 'full')

# A user who comes back from Keycloak and still needs a step-up within this many seconds
# is not sent back straight away. They get a page with a button instead. Without this,
# a step-up that Keycloak can't do (for example a wrong flow) would redirect forever.
LOOP_GUARD_SECONDS = 60

# The token's acr for a login with MFA: level 2 of the "browser step-up" flow
STEP_UP_ACR = '2'


def stricter(kind, other):
    if other not in KINDS:
        return kind
    return kind if KINDS.index(kind) >= KINDS.index(other) else other


def page_to_return_to():
    # A GET can be asked again after the step-up. A POST can't (its form data is gone), so
    # the user goes back to the page they came from, and sends the form again.
    if request.method in ('GET', 'HEAD'):
        return request.full_path.rstrip('?')
    return request.referrer or url_for('auth.home')


def remember_step_up(kind):
    # Keeps the step-up the Policy Engine asked for. Returns True if the user should be sent to
    # Keycloak now, False if they just came back from there (see LOOP_GUARD_SECONDS).
    waiting = session.get(SESSION_KEY) or {}
    sent_at = waiting.get('sent_at') or 0
    session[SESSION_KEY] = {
        'kind': stricter(kind, waiting.get('kind')),
        'next': validate_return_url(page_to_return_to(), request.url_root),
        'sent_at': sent_at,
    }
    return request.method in ('GET', 'HEAD') and time.time() - sent_at > LOOP_GUARD_SECONDS


def clear_step_up():
    session.pop(SESSION_KEY, None)


def redirect_to_step_up():
    # The /step-up page: sends the user to Keycloak for the step-up kept in the session.
    # After the login, Flask-OIDC's callback stores the new token and returns to `next`.
    waiting = session.get(SESSION_KEY)
    if not waiting:
        return None
    waiting['sent_at'] = time.time()
    session[SESSION_KEY] = waiting
    session['next'] = waiting['next']
    params = {'acr_values': STEP_UP_ACR}
    if waiting['kind'] == 'full':
        params['prompt'] = 'login'   # ask for the password again too, not only the OTP
    return g._oidc_auth.authorize_redirect(url_for('oidc_auth.authorize', _external=True), **params)


def end_session(access_request):
    # CRITICAL risk: end the Keycloak session (with the user's own refresh token, like logout),
    # forget it in the Flask session, and remove its risk state. Returns True if Keycloak ended it.
    ended = False
    try:
        refresh_token = oidc.get_refresh_token()
        if refresh_token:
            ended = revoke_token(KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, refresh_token, REVOCATION_URL)
    except Exception as e:
        print(f"Could not end the Keycloak session: {e}")
    for key in ('oidc_auth_token', 'oidc_auth_profile', SESSION_KEY):
        session.pop(key, None)
    try:
        risk_engine.end_session(access_request.get('session_id'))
    except Exception as e:
        print(f"Could not remove the session's risk state: {e}")
    return ended
