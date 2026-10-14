'''

Checks the Web UI's access control: the role table (section 3.1), Access Proxy
mediation and the request record (section 3.2).

It logs in as real users through Keycloak (alice, bob, charlie, foo), opens every
protected page as each one with Flask's test client, and checks the answer:

    every request                  -> goes through Access Proxy -> Trust Engine -> Policy Engine
    role not in the table          -> 403, denied by policy P2 (Unauthorized resource)
    POST without a write role      -> 403, denied by policy P2 (may view but not change)
    role in the table              -> the page runs only if the Policy Engine allows it,
                                      otherwise 403 with the policy and its reason
    not logged in                  -> redirect to the Keycloak login
    fake or revoked token          -> 401 Invalid or expired token

It also checks the request record: a new browser gets a device ID cookie, the record
holds that device ID and the user's own location, and the device counts as new until
access was allowed from it once. And it checks that several requests at the same time each get their own verdict,
and measures how long a mediated request takes.

Needs:
  - the identity stack running (docker compose up)
  - the decision engines running (./scripts/runAll.sh)
  - the Web UI's settings (.env or environment variables, see .env.example)
The local demo users' passwords are the same as their usernames.

Run from anywhere:  python3 tests/check_access_control.py

Note: it adds access requests and decisions to data/, and posts an empty update to
/receivePolicyConfigurations, which rewrites policyConfiguration.yml with the same content.

Running it several times within 5 minutes sends more than 30 requests per user, which the
Trust Engine counts as a burst (access frequency factor). Each run also uses new browsers
(new devices). Then some users' trust scores drop, and requests can be denied by P4 or P5
instead of allowed. The checks accept that wherever trust can decide. They only require
P2 (the role table) to give the expected answer.

'''
import json
import logging
import os
import socket
import statistics
import sys
import threading
import time

import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, 'web'))
logging.disable(logging.CRITICAL)

import app as web_app  # noqa: E402  (needs the paths above)
from cyberdome.access_rules import is_role_allowed, may_write  # noqa: E402
from cyberdome.data_paths import ACCESS_DECISIONS_FILE, ACCESS_REQUESTS_FILE  # noqa: E402
from cyberdome.settings import KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET  # noqa: E402
from keycloak_config import REVOCATION_URL, TOKEN_URL  # noqa: E402
from proxy_client import stop_node  # noqa: E402

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

# Pages that only need a login
LOGIN_ONLY = ['/resource-selection', '/privilegedAccess', '/approval_status', '/enterSecretKey', '/protected_page', '/success', '/viewAccessRequests']

ENGINE_PORTS = {'Access Proxy': 8001, 'Trust Engine': 8002, 'Policy Engine': 8003}

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


def mediated(response):
    # The Policy Engine decided this request (set by protected_resource in web/authz.py)
    return response.headers.get('X-CyberDome-Decided-By') == 'Policy Engine'


def saved_decision(request_id):
    with open(ACCESS_DECISIONS_FILE) as file:
        return next((d for d in json.load(file) if str(d.get('request_id')) == str(request_id)), None)


def saved_request(request_id):
    with open(ACCESS_REQUESTS_FILE) as file:
        return next((r for r in json.load(file) if str(r.get('ID')) == str(request_id)), None)


def device_cookie(response):
    # The device ID cookie the server set in this response, as (value, the whole Set-Cookie header), or (None, '')
    for header in response.headers.getlist('Set-Cookie'):
        if header.startswith('cyberdome_device_id='):
            return header.split(';')[0].split('=', 1)[1], header
    return None, ''


def engines_running():
    down = []
    for name, port in ENGINE_PORTS.items():
        with socket.socket() as sock:
            if sock.connect_ex(('127.0.0.1', port)) != 0:
                down.append(f"{name} (port {port})")
    return down


def main():
    down = engines_running()
    if down:
        print(f"The decision engines must be running (./scripts/runAll.sh). Not reachable: {', '.join(down)}")
        return 2

    web_app.app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
    with web_app.app.app_context():
        web_app.db.create_all()

    tokens = {username: get_token(username) for username in USERS}
    clients = {}
    for username in USERS:
        clients[username] = client_for(tokens[username], username)
        # /home saves the user's identity and login events to data/, which the engines read
        clients[username].get('/home')

    print("== Role table and Access Proxy mediation: every user on every role-protected page")
    for username, role in USERS.items():
        for resource, method, path in ROLE_PROTECTED:
            response = call(clients[username], method, path)
            label = f"{username:8} ({role}) {method:4} {path:30}"
            decision = response.headers.get('X-CyberDome-Decision')
            policy_id = response.headers.get('X-CyberDome-Policy')
            if is_role_allowed([role], resource) and (method == 'GET' or may_write([role], resource)):
                ok = mediated(response) and policy_id != 'P2' and (
                    (decision == 'ALLOW' and response.status_code not in (401, 403)) or
                    (decision == 'DENY' and response.status_code == 403))
                check(f"{label} expect mediated -> {decision} ({policy_id})", ok,
                      f"got {response.status_code}, decided by {response.headers.get('X-CyberDome-Decided-By')}")
            else:
                check(f"{label} expect 403, denied by P2", response.status_code == 403 and mediated(response) and policy_id == 'P2',
                      f"got {response.status_code}, policy {policy_id}")

    print("\n== Direct URL: the request goes through the engines, and the decision is saved with a reason")
    response = call(clients['bob'], 'GET', '/resource-1')
    request_id = response.headers.get('X-CyberDome-Request-Id')
    decision = saved_decision(request_id)
    check(f"bob GET /resource-1 directly is mediated (request {request_id})", mediated(response))
    check("the decision is in data/access_decision.json with a trust score, a policy and a reason",
          bool(decision and decision.get('reason') and decision.get('policy_id') and decision.get('user_trust_score') is not None),
          f"saved decision: {decision}")
    check("the saved decision has the trust breakdown (7 factors)", len((decision or {}).get('trust_factors') or {}) == 7,
          f"saved decision: {decision}")
    check("the saved decision is for this resource and action",
          bool(decision and decision.get('resource') == 'resource_1' and decision.get('action') == 'read'), f"saved decision: {decision}")

    print("\n== Request record: device ID cookie, the user's own location, new and known devices")
    browser = client_for(tokens['bob'], 'bob')  # a new browser, without a device ID yet
    device_id, cookie_header = device_cookie(browser.get('/home'))
    check("a new browser gets a device ID cookie", device_id is not None)
    check("the cookie is HttpOnly and SameSite=Lax", 'HttpOnly' in cookie_header and 'SameSite=Lax' in cookie_header, cookie_header)

    response = call(browser, 'GET', '/resource-1')
    first = saved_request(response.headers.get('X-CyberDome-Request-Id')) or {}
    check("the record holds the browser's device ID", first.get('device_id') == device_id, f"record: {first}")
    check("the first request from this device has new_device = true", first.get('new_device') is True, f"record: {first}")
    check("the record has the user's location (LOCAL on localhost)", first.get('location') == 'LOCAL', f"location: {first.get('location')}")
    check("the record has no server values (public IP, MAC, vendor)",
          not {'public_ip_address', 'device_mac', 'device_vendor'} & set(first), f"fields: {sorted(first)}")
    check("the browser keeps its device ID (no new cookie)", device_cookie(response)[0] is None)

    response = call(browser, 'GET', '/resource-1')
    second = saved_request(response.headers.get('X-CyberDome-Request-Id')) or {}
    check("after an allowed request the device is known: new_device = false", second.get('new_device') is False, f"record: {second}")

    browser.set_cookie('cyberdome_device_id', 'not-a-device-id')
    response = call(browser, 'GET', '/resource-1')
    replaced, _ = device_cookie(response)
    check("an invalid device ID cookie is replaced with a new ID", replaced not in (None, 'not-a-device-id'), f"new cookie: {replaced}")

    print("\n== Login-only pages: a logged-in user gets through")
    for path in LOGIN_ONLY:
        response = call(clients['bob'], 'GET', path)
        check(f"bob GET {path:30} expect allowed", response.status_code not in (401, 403) and not is_login_redirect(response), f"got {response.status_code}")

    print("\n== Not logged in: every protected page sends you to the login")
    anonymous = web_app.app.test_client()
    for method, path in [(m, p) for _, m, p in ROLE_PROTECTED] + [('GET', p) for p in LOGIN_ONLY]:
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

    print("\n== Several requests at the same time each get their own verdict")
    answers = []

    def one_request():
        client = client_for(tokens['bob'], 'bob')
        answers.append(call(client, 'GET', '/resource-1'))

    threads = [threading.Thread(target=one_request) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    ids = [a.headers.get('X-CyberDome-Request-Id') for a in answers]
    check("5 requests at once: all mediated, all allowed", all(mediated(a) and a.status_code == 200 for a in answers),
          f"statuses {[a.status_code for a in answers]}")
    check("5 requests at once: 5 different request IDs, each with its own saved decision",
          len(set(ids)) == 5 and all(saved_decision(i) for i in ids), f"ids {ids}")

    print("\n== Timing: bob GET /resource-1, 10 requests one after another")
    times = []
    for _ in range(10):
        start = time.perf_counter()
        call(clients['bob'], 'GET', '/resource-1')
        times.append((time.perf_counter() - start) * 1000)
    print(f"      median {statistics.median(times):.0f} ms, min {min(times):.0f} ms, max {max(times):.0f} ms per request "
          f"(token check + Access Proxy + Trust Engine + Policy Engine)")

    print("\n== Task scenarios, checked directly")
    response = call(clients['bob'], 'GET', '/resource-1')
    check("Scenario 1: bob (Researcher) opens Resource 1 -> 200, ALLOW by the Policy Engine",
          response.status_code == 200 and response.headers.get('X-CyberDome-Decision') == 'ALLOW')
    response = call(clients['bob'], 'GET', '/resource-2')
    check("Scenario 2: bob (Researcher) opens Resource 2 -> 403, POLICY_VIOLATION by P2",
          response.status_code == 403 and response.headers.get('X-CyberDome-Policy') == 'P2')
    decision = saved_decision(response.headers.get('X-CyberDome-Request-Id')) or {}
    check("Scenario 2: the saved decision has the outcome POLICY_VIOLATION and a reason",
          decision.get('outcome') == 'POLICY_VIOLATION' and bool(decision.get('reason')), f"saved decision: {decision}")
    response = call(clients['charlie'], 'GET', '/configurePolicies')
    check("Scenario 5: charlie (Administrator) opens the policy configuration page -> mediated, ALLOW",
          mediated(response) and response.headers.get('X-CyberDome-Decision') == 'ALLOW' and response.status_code not in (401, 403))
    response = call(clients['charlie'], 'POST', '/receivePolicyConfigurations')
    check("Separation of duties: charlie (Administrator) may not save policies -> 403 by P2",
          response.status_code == 403 and response.headers.get('X-CyberDome-Policy') == 'P2')
    response = call(clients['foo'], 'POST', '/receivePolicyConfigurations')
    policy_id = response.headers.get('X-CyberDome-Policy')
    check(f"Separation of duties: foo (Policy Administrator) passes P2 for saving policies -> {response.headers.get('X-CyberDome-Decision')} ({policy_id})",
          mediated(response) and policy_id in ('P6', 'P4', 'P5'), f"got {response.status_code}, policy {policy_id}")

    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    try:
        exit_code = main()
    finally:
        # Stop the Web UI's node 4, so the script exits by itself
        stop_node()
    sys.exit(exit_code)
