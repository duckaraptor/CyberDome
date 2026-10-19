'''

Tests for the Trust Engine's score (assignment section 3.3, docs/trust-model.md).

They use made-up records, so they don't need Keycloak, the engines or the files in data/.
Each test is a function named test_..., so pytest can run them too.

Run from anywhere:  python3 tests/test_trust.py

'''
import json
import os
import sys
import tempfile
from datetime import datetime, time, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from cyberdome import trust_algorithm as ta  # noqa: E402  (needs the path above)
from cyberdome.trust_signals import add_sign_in_success_rates, count_recent_access_requests, success_rate  # noqa: E402

CONFIG = {
    'trustWeights': dict(ta.DEFAULT_WEIGHTS),
    'accessFrequencyWindowMinutes': 5,
    'accessFrequencyMaxRequests': 30,
    'highRiskLocations': ['KP'],
    'mediumRiskLocations': ['KE'],
    'lowRiskLocations': ['SE'],
    'periodStartInput': '00:00:00',
    'periodEndInput': '06:00:00',
}


def days_ago_ms(days):
    return (datetime.now() - timedelta(days=days)).timestamp() * 1000


IDENTITY = {'email_verified': True, 'totp_enabled': False, 'created_timestamp': days_ago_ms(10)}


def request(**changes):
    record = {'access_request_time': '2026-10-14 12:00:00', 'location': 'LOCAL', 'new_device': False}
    record.update(changes)
    return record


def score(access_request, sign_in_success_rate=1.0, recent_requests=0, config=CONFIG, identity=IDENTITY):
    return ta.calculate_trust(identity, access_request, sign_in_success_rate, recent_requests, config)


# --- Weights -----------------------------------------------------------------------

def test_weights_come_from_the_config():
    config = dict(CONFIG, trustWeights=dict(ta.DEFAULT_WEIGHTS, device=0.5))
    assert ta.trust_weights(config)['device'] == 0.5


def test_missing_invalid_and_negative_weights():
    weights = ta.trust_weights({'trustWeights': {'device': 'abc', 'location': -1}})
    assert weights['device'] == ta.DEFAULT_WEIGHTS['device']  # invalid: default
    assert weights['location'] == 0.0  # negative: 0
    assert weights['loginHistory'] == ta.DEFAULT_WEIGHTS['loginHistory']  # missing: default


def test_all_zero_weights_fall_back_to_the_defaults():
    zero = {factor: 0 for factor in ta.DEFAULT_WEIGHTS}
    assert ta.trust_weights({'trustWeights': zero}) == ta.DEFAULT_WEIGHTS


def test_weights_that_do_not_add_up_to_1_are_scaled():
    doubled = {factor: weight * 2 for factor, weight in ta.DEFAULT_WEIGHTS.items()}
    assert score(request(), config=dict(CONFIG, trustWeights=doubled))['score'] == score(request())['score']


# --- The 7 factors -------------------------------------------------------------------

def test_login_history():
    assert ta.login_history_score(1.0)[0] == 1.0
    assert ta.login_history_score(0.7)[0] == 0.7
    assert ta.login_history_score(None)[0] == 0.5
    assert ta.login_history_score(1.5)[0] == 1.0  # never above 1


def test_device():
    assert ta.device_score(False)[0] == 1.0
    assert ta.device_score(True)[0] == 0.4
    assert ta.device_score(None)[0] == 0.4  # missing counts as new


def test_access_frequency():
    assert ta.access_frequency_score(30, 5, 30)[0] == 1.0
    assert ta.access_frequency_score(31, 5, 30)[0] == 0.3


def test_location():
    assert ta.location_score('KP', CONFIG)[0] == 0.1
    assert ta.location_score('KE', CONFIG)[0] == 0.5
    assert ta.location_score('se', CONFIG)[0] == 1.0  # lists are matched without case
    assert ta.location_score('LOCAL', CONFIG)[0] == 1.0
    assert ta.location_score('Unknown', CONFIG)[0] == 0.5
    assert ta.location_score('US', CONFIG)[0] == 0.7


def test_identity_strength():
    assert ta.identity_strength_score({'email_verified': True, 'totp_enabled': True})[0] == 1.0
    assert ta.identity_strength_score({'email_verified': True, 'totp_enabled': False})[0] == 0.5
    assert ta.identity_strength_score({})[0] == 0.0


def test_access_time():
    assert ta.access_time_score('2026-10-14 03:00:00', CONFIG)[0] == 0.5
    assert ta.access_time_score('2026-10-14 12:00:00', CONFIG)[0] == 1.0


def test_night_window_can_cross_midnight():
    # Bug fix: 22:00 to 06:00 never matched before
    start, end = time(22, 0), time(6, 0)
    assert ta.is_in_night_window(time(23, 30), start, end)
    assert ta.is_in_night_window(time(2, 0), start, end)
    assert not ta.is_in_night_window(time(12, 0), start, end)


def test_account_age_tiers():
    # Bug fix: every account older than about 4.5 days got the top score before
    assert ta.account_age_score(days_ago_ms(10))[0] == 0.4
    assert ta.account_age_score(days_ago_ms(60))[0] == 0.7
    assert ta.account_age_score(days_ago_ms(400))[0] == 1.0


# --- Sign-in success rate --------------------------------------------------------------

def test_success_rate_uses_the_last_10_attempts():
    assert success_rate([0] * 5 + [1] * 10) == 1.0  # old failures stop counting
    assert success_rate([1] * 8 + [0] * 2) == 0.8
    assert success_rate([]) is None


def test_sign_in_success_rate_is_never_above_1():
    # Bug fix: the old calculation could give 1.5 after the first successful login
    auth_data = [{'user_id': 'u1', 'time': t, 'auth_status': 1} for t in range(1, 6)]
    add_sign_in_success_rates(auth_data)
    assert all(0 <= entry['sign_in_success_rate'] <= 1 for entry in auth_data)
    assert auth_data[0]['sign_in_success_rate'] == 1.0


# --- Access frequency count ------------------------------------------------------------

def test_recent_requests_are_counted_per_user_and_window():
    requests = [
        {'ID': 1, 'user_id': 'bob', 'access_request_time': '2026-10-14 11:50:00'},  # too old
        {'ID': 2, 'user_id': 'bob', 'access_request_time': '2026-10-14 11:57:00'},
        {'ID': 3, 'user_id': 'bob', 'access_request_time': '2026-10-14 11:59:00'},
        {'ID': 4, 'user_id': 'alice', 'access_request_time': '2026-10-14 11:59:00'},  # another user
        {'ID': 5, 'user_id': 'bob', 'access_request_time': '2026-10-14 12:00:00'},  # the request being scored
    ]
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, 'access_requests.jsonl')
        with open(path, 'w') as file:
            file.writelines(json.dumps(request) + '\n' for request in requests)  # one request per line
        assert count_recent_access_requests('bob', '2026-10-14 12:00:00', 5, path, exclude_id=5) == 2


# --- The whole score (the examples in docs/trust-model.md) -----------------------------

def test_breakdown_has_all_7_factors():
    result = score(request())
    assert set(result['factors']) == set(ta.DEFAULT_WEIGHTS)
    assert all({'score', 'weight', 'reason'} <= set(details) for details in result['factors'].values())


def test_example_known_device():
    assert abs(score(request())['score'] - 0.895) < 0.001


def test_example_new_device():
    assert abs(score(request(new_device=True))['score'] - 0.775) < 0.001


def test_example_new_device_at_night_from_a_high_risk_country():
    result = score(request(new_device=True, location='KP', access_request_time='2026-10-14 03:00:00'))
    assert abs(result['score'] - 0.59) < 0.001


def test_failed_logins_and_a_burst_lower_the_score():
    normal = score(request())['score']
    assert score(request(), sign_in_success_rate=0.5)['score'] < normal
    assert score(request(), recent_requests=100)['score'] < normal


def test_score_is_between_0_and_1():
    worst = score(request(new_device=True, location='KP', access_request_time='2026-10-14 03:00:00'),
                  sign_in_success_rate=0.0, recent_requests=100,
                  identity={'email_verified': False, 'totp_enabled': False, 'created_timestamp': days_ago_ms(1)})
    best = score(request(), identity=dict(IDENTITY, totp_enabled=True, created_timestamp=days_ago_ms(400)))
    assert 0 <= worst['score'] < best['score'] <= 1
    assert best['score'] == 1.0


if __name__ == '__main__':
    tests = [(name, test) for name, test in sorted(globals().items()) if name.startswith('test_') and callable(test)]
    failed = 0
    for name, test in tests:
        try:
            test()
            print(f"PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {name}  {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
