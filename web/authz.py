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

from flask import g, make_response, render_template
from keycloak.exceptions import KeycloakError

from extensions import keycloak_openid, oidc
from keycloak_config import KEYCLOAK_CLIENT_ID
from proxy_client import request_access_decision
from request_context import build_access_request, remember_device


def access_denied(status, title, reason, resource=None):
    # A clear refusal page, with the HTTP status code the browser and tests can check
    return render_template('access_denied.html', status=status, title=title, reason=reason, resource=resource), status


def check_token():
    # Ask Keycloak whether the user's access token is still active. Returns (token_info, None) or (None, refusal).
    try:
        token_info = keycloak_openid.introspect(oidc.get_access_token())
    except KeycloakError as e:
        # Fail closed: if we can't verify the token, we don't give access
        print(f"Token introspection failed: {e}")
        return None, access_denied(503, 'Cannot verify your login', 'The identity provider could not be reached to check your token. Please try again later.')

    if not token_info.get('active'):
        return None, access_denied(401, 'Invalid or expired token', 'Your login token is no longer valid. Please log in again.')

    return token_info, None


def roles_from_token(token_info):
    # The user's roles for this application (Keycloak client roles of ZeroTrustPlatform)
    return token_info.get('resource_access', {}).get(KEYCLOAK_CLIENT_ID, {}).get('roles', [])


def require_authentication(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not oidc.user_loggedin:
            return oidc.redirect_to_auth_server()

        token_info, refusal = check_token()
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
                return access_denied(504, 'No access decision', 'The decision engines did not answer in time, so access is denied.', resource)

            g.access_decision = decision
            if decision.get('access_decision') != 1:
                status = decision.get('http_status', 403)
                title = 'Access denied' if status == 403 else 'Cannot check your request'
                reason = decision.get('reason') or 'Denied by the policy.'
                if decision.get('policy_id'):
                    reason = f"{decision['policy_id']} {decision.get('policy_name', '')}: {reason}"
                response = make_response(access_denied(status, title, reason, resource))
            else:
                remember_device(access_request['username'], access_request['device_id'])
                response = make_response(view(*args, **kwargs))

            # Show which decision this page was served under (useful as evidence and for tests)
            response.headers['X-CyberDome-Request-Id'] = str(decision.get('request_id'))
            response.headers['X-CyberDome-Decision'] = 'ALLOW' if decision.get('access_decision') == 1 else 'DENY'
            response.headers['X-CyberDome-Decided-By'] = str(decision.get('decided_by'))
            response.headers['X-CyberDome-Policy'] = str(decision.get('policy_id'))
            return response

        return require_authentication(mediate)

    return decorator
