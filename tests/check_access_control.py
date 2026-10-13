'''

Checks the Web UI's access control against the role table in policyConfiguration.yml.

It logs in as real users through Keycloak (alice, bob, charlie, foo), opens every
protected page as each one with Flask's test client, and checks the answer:

    allowed role         -> the page runs (no 401, 403 or login redirect)
    other roles          -> 403 Forbidden
    not logged in        -> redirect to the Keycloak login
    fake or revoked token -> 401 Invalid or expired token

Needs: the identity stack running (docker compose up), and the Web UI's settings
(.env or environment variables, see .env.example). The local demo users' passwords
are the same as their usernames.

Run from anywhere:  python3 tests/check_access_control.py

Note: it posts an empty update to /receivePolicyConfigurations, which rewrites
policyConfiguration.yml with the same content.

'''
import logging
import os
import sys
import time

import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, 'web'))
logging.disable(logging.CRITICAL)

import app as web_app  # noqa: E402  (needs the paths above)
from cyberdome.access_rules import is_role_allowed  # noqa: E402
from cyberdome.settings import KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET  # noqa: E402
from keycloak_config import REVOCATION_URL, TOKEN_URL  # noqa: E402

USERS = {  # username: role (from infra/openldap/bootstrap.ldif)
    'alice': 'Approver',
    'bob': 'Researcher',
    'charlie': 'Administrator',
    'foo': 'Policy Administrator',
}

# (resource in the role table, HTTP method, path)
ROLE_PROTECTED = [
    ('resource_1', 'GET', '/resource-1'),
    ('resource_2', 'GET', '/resource-2'),
    ('policy_configuration', 'GET', '/configurePolicies'),
    ('policy_configuration', 'POST', '/receivePolicyConfigurations'),
    ('logging', 'GET', '/logging'),
    ('pam_approval', 'GET', '/testing'),
    ('pam_approval', 'POST', '/approve_request'),
]

# Pages that only need a login. /resource-selection and /receive-access-request are only
# checked without a login here, because when logged in they call external services and the engines.
LOGIN_ONLY = ['/privilegedAccess', '/approval_status', '/enterSecretKey', '/protected_page', '/success', '/viewAccessRequests']
LOGIN_ONLY_NOT_CALLED = [('GET', '/resource-selection'), ('POST', '/receive-access-request')]

results = []


def check(name, ok, detail=''):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  (' + detail + ')' if detail and not ok else ''}")


def get_token(username):
    response = requests.post(TOKEN_URL, data={
        'grant_type': 'password', 'client_id': KEYCLOAK_CLIENT_ID, 'client_secret': KEYCLOAK_CLIENT_SECRET,
        'username': username, 'password': username, 'scope': 'openid email profile'})
    response.raise_for_status()
    token = response.json()
    token['expires_at'] = int(time.time()) + token['expires_in']
    return token


def client_for(token, username):
    # A test client whose session looks like a user who logged in through the browser
    client = web_app.app.test_client()
    with client.session_transaction() as session:
        session['oidc_auth_token'] = token
        session['oidc_auth_profile'] = {'sub': username, 'name': username, 'preferred_username': username, 'email': f'{username}@example.com'}
    return client


def call(client, method, path):
    return client.open(path, method=method, json={} if method == 'POST' else None)


def is_login_redirect(response):
    return response.status_code == 302 and '/login' in response.headers.get('Location', '')


def main():
    web_app.app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
    with web_app.app.app_context():
        web_app.db.create_all()

    print("== Role table: every user on every role-protected page")
    for username, role in USERS.items():
        client = client_for(get_token(username), username)
        for resource, method, path in ROLE_PROTECTED:
            response = call(client, method, path)
            if is_role_allowed([role], resource):
                ok = response.status_code not in (401, 403) and not is_login_redirect(response)
                expected = 'allowed'
            else:
                ok = response.status_code == 403
                expected = '403'
            check(f"{username:8} ({role}) {method:4} {path:30} expect {expected}", ok, f"got {response.status_code}")

    print("\n== Login-only pages: a logged-in user gets through")
    client = client_for(get_token('bob'), 'bob')
    for path in LOGIN_ONLY:
        response = call(client, 'GET', path)
        check(f"bob GET {path:30} expect allowed", response.status_code not in (401, 403) and not is_login_redirect(response), f"got {response.status_code}")

    print("\n== Not logged in: every protected page sends you to the login")
    anonymous = web_app.app.test_client()
    pages = [(m, p) for _, m, p in ROLE_PROTECTED] + [('GET', p) for p in LOGIN_ONLY] + LOGIN_ONLY_NOT_CALLED
    for method, path in pages:
        response = call(anonymous, method, path)
        check(f"anonymous {method:4} {path:30} expect login redirect", is_login_redirect(response), f"got {response.status_code}")

    print("\n== Invalid and revoked tokens (scenario 3): 401, the resource is not reached")
    fake = dict(get_token('charlie'), access_token='not-a-real-token')
    response = call(client_for(fake, 'charlie'), 'GET', '/resource-2')
    check("fake token      GET /resource-2 expect 401", response.status_code == 401, f"got {response.status_code}")

    token = get_token('charlie')
    revoked = requests.post(REVOCATION_URL, data={'client_id': KEYCLOAK_CLIENT_ID, 'client_secret': KEYCLOAK_CLIENT_SECRET,
                                                  'refresh_token': token['refresh_token']})
    response = call(client_for(token, 'charlie'), 'GET', '/resource-2')
    check(f"revoked token   GET /resource-2 expect 401 (logout returned {revoked.status_code})", response.status_code == 401, f"got {response.status_code}")

    print("\n== Task scenarios, checked directly")
    bob = client_for(get_token('bob'), 'bob')
    charlie = client_for(get_token('charlie'), 'charlie')
    check("Scenario 1: bob (Researcher) opens Resource 1 -> 200", call(bob, 'GET', '/resource-1').status_code == 200)
    check("Scenario 2: bob (Researcher) opens Resource 2 -> 403", call(bob, 'GET', '/resource-2').status_code == 403)
    check("Scenario 5: charlie (Administrator) opens the policy configuration page -> allowed",
          call(charlie, 'GET', '/configurePolicies').status_code not in (401, 403))

    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
