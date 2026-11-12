'''

Access checks for the Web UI's pages.

    @require_authentication           the user must be logged in, with a token Keycloak says is still active
    @protected_resource('resource_1') the same, and the request goes through the Access Proxy, Trust Engine
                                      and Policy Engine. The page only runs if the Policy Engine allows it.
                                      The Policy Engine checks the role table and the other policies
                                      (cyberdome/policy.py, docs/policies.md).

Each check asks Keycloak about the token once (token introspection) and keeps the
answer in flask.g for the page: g.token_info and g.user_roles.

'''
import functools

from flask import g, make_response, redirect, render_template, request, session, url_for
from keycloak.exceptions import KeycloakError

from cyberdome import audit
from extensions import keycloak_openid, oidc
from keycloak_config import KEYCLOAK_CLIENT_ID
from proxy_client import request_access_decision
from request_context import build_access_request, remember_device
from step_up import clear_step_up, end_session, remember_step_up


def access_denied(status, title, reason, resource=None, action_url=None, action_label=None):
    # A clear refusal page, with the HTTP status code the browser and tests can check.
    # action_url and action_label replace the "Back to home" button, for example with "Verify now".
    return render_template('access_denied.html', status=status, title=title, reason=reason, resource=resource,
                           action_url=action_url, action_label=action_label), status


def log_web_ui_decision(outcome, reason, resource=None, access_request=None):
    # An audit entry for a decision the Web UI makes itself, before or instead of the Policy Engine.
    # Without a request record, it records what is known: the page, the connection, the device and,
    # if the session has one, the user the session belongs to.
    if access_request is None:
        profile = session.get('oidc_auth_profile') or {}
        access_request = {
            'username': profile.get('preferred_username'),
            'user_id': profile.get('sub'),
            'resource': resource,
            'path': request.path,
            'action': 'read' if request.method in ('GET', 'HEAD') else 'write',
            'source_ip': request.remote_addr,
            'device_id': g.get('device_id'),
        }
    try:
        audit.log_decision(outcome, reason, 'Web UI', request=access_request)
    except OSError as e:
        print(f"Could not write the audit entry: {e}")


def step_up_reason(decision):
    what = 'a one-time code (OTP)' if decision.get('step_up') == 'otp' else 'your password and a one-time code (OTP)'
    return (f"{decision['policy_id']} {decision.get('policy_name', '')}: {decision.get('reason')}. "
            f"Please confirm it's you with {what}.")


def check_token(resource=None):
    # Ask Keycloak whether the user's access token is still active. Returns (token_info, None) or (None, refusal).
    try:
        token_info = keycloak_openid.introspect(oidc.get_access_token())
    except KeycloakError as e:
        # Fail closed: if we can't verify the token, we don't give access
        print(f"Token introspection failed: {e}")
        log_web_ui_decision('DENY', 'The identity provider could not be reached to check the token', resource)
        return None, access_denied(503, 'Cannot verify your login', 'The identity provider could not be reached to check your token. Please try again later.')

    if not token_info.get('active'):
        log_web_ui_decision('AUTHENTICATION_FAILURE', 'The login token is invalid, expired or revoked', resource)
        return None, access_denied(401, 'Invalid or expired token', 'Your login token is no longer valid. Please log in again.')

    return token_info, None


def roles_from_token(token_info):
    # The user's roles for this application (Keycloak client roles of ZeroTrustPlatform)
    return token_info.get('resource_access', {}).get(KEYCLOAK_CLIENT_ID, {}).get('roles', [])


def require_authentication(view, resource=None):
    # `resource` is only used for the audit entry, when the page is a protected resource
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not oidc.user_loggedin:
            log_web_ui_decision('AUTHENTICATION_FAILURE', 'Not logged in: sent to the login page', resource)
            return oidc.redirect_to_auth_server()

        token_info, refusal = check_token(resource)
        if refusal:
            return refusal

        g.token_info = token_info
        g.user_roles = roles_from_token(token_info)
        return view(*args, **kwargs)

    return wrapped


def protected_resource(resource):
    # Every request for this resource goes through Access Proxy -> Trust Engine -> Policy Engine,
    # and the page only runs if the Policy Engine allows it. A direct URL takes the same path.
    # The Web UI only checks the login, because it needs a valid token to build the request record.
    # The Policy Engine decides everything else, including the role table (policy P2).
    def decorator(view):
        @functools.wraps(view)
        def mediate(*args, **kwargs):
            access_request = build_access_request(resource)
            decision = request_access_decision(access_request)

            if decision is None:
                log_web_ui_decision('DENY', 'The decision engines did not answer in time', resource, access_request)
                return access_denied(504, 'No access decision', 'The decision engines did not answer in time, so access is denied.', resource)
            if decision.get('decided_by') != 'Policy Engine':
                # For example the Access Proxy is not reachable (proxy_client.py)
                log_web_ui_decision('DENY', decision.get('reason') or 'The request could not be checked', resource, access_request)

            g.access_decision = decision
            if decision.get('outcome') == 'STEP_UP_REQUIRED':
                # Adaptive mode, MEDIUM or HIGH risk: send the user to Keycloak for an OTP or a full
                # login (step_up.py). If they just came back from there, or sent a form, show a button.
                if remember_step_up(decision['step_up']):
                    response = make_response(redirect(url_for('auth.step_up')))
                else:
                    response = make_response(access_denied(
                        401, 'Extra verification needed', step_up_reason(decision), resource,
                        action_url=url_for('auth.step_up'), action_label='Verify now'))
            elif decision.get('outcome') == 'RISK_ALERT':
                # Adaptive mode, CRITICAL risk: deny, and end the session at Keycloak
                ended = end_session(access_request)
                log_web_ui_decision('RISK_ALERT', 'The session was ended after a CRITICAL risk'
                                    + ('' if ended else ' (Keycloak could not be reached, so only the Web UI session was ended)'),
                                    resource, access_request)
                response = make_response(access_denied(
                    403, 'Access denied, session ended',
                    f"{decision['policy_id']} {decision.get('policy_name', '')}: {decision.get('reason')}. "
                    'Your session was ended. Please log in again.', resource,
                    action_url='/home', action_label='Log in again'))
            elif decision.get('access_decision') != 1:
                status = decision.get('http_status', 403)
                title = 'Access denied' if status == 403 else 'Cannot check your request'
                reason = decision.get('reason') or 'Denied by the policy.'
                if decision.get('policy_id'):
                    reason = f"{decision['policy_id']} {decision.get('policy_name', '')}: {reason}"
                response = make_response(access_denied(status, title, reason, resource))
            else:
                clear_step_up()
                remember_device(access_request['username'], access_request['device_id'])
                response = make_response(view(*args, **kwargs))

            # Show which decision this page was served under (useful as evidence and for tests)
            response.headers['X-CyberDome-Request-Id'] = str(decision.get('request_id'))
            response.headers['X-CyberDome-Decision'] = str(decision.get('decision') or ('ALLOW' if decision.get('access_decision') == 1 else 'DENY'))
            response.headers['X-CyberDome-Decided-By'] = str(decision.get('decided_by'))
            response.headers['X-CyberDome-Policy'] = str(decision.get('policy_id'))
            if decision.get('risk_level'):
                response.headers['X-CyberDome-Risk'] = f"{decision['risk_score']:.3f} {decision['risk_level']}"
            if decision.get('step_up'):
                response.headers['X-CyberDome-Step-Up'] = str(decision['step_up'])
            return response

        return require_authentication(mediate, resource)

    return decorator
