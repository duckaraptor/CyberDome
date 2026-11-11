'''

Tests for the adaptive risk model (Task 2, docs/risk-model.md).

They use made-up requests, sessions and profiles, so they don't need Keycloak, the
engines or the files in data/. Each test is a function named test_..., so pytest can
run them too.

Run from anywhere:  python3 tests/test_risk.py

'''
import copy
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from cyberdome.risk import features as f  # noqa: E402  (needs the path above)
from cyberdome.risk import model  # noqa: E402
from cyberdome.risk.defaults import DEFAULT_RISK_MODEL, FEATURES, risk_settings  # noqa: E402
from cyberdome.risk.signals import count_auth_failures, count_recent_denials  # noqa: E402
from cyberdome.risk.state import RiskStore, end_idle_sessions  # noqa: E402

CONFIG = {
    'riskModel': copy.deepcopy(DEFAULT_RISK_MODEL),
    'highRiskLocations': ['KP'],
    'mediumRiskLocations': ['KE'],
    'lowRiskLocations': ['SE'],
    'periodStartInput': '00:00:00',
    'periodEndInput': '06:00:00',
    'resources': {
        'resource_1': {'adminResource': False},
        'resource_2': {'adminResource': False},
        'logging': {'adminResource': True},
        'policy_configuration': {'adminResource': True},
    },
}
SETTINGS = risk_settings(CONFIG)
LOGIN = datetime(2026, 11, 9, 9, 0, 0)


def at(minutes):
    # A time `minutes` after bob's 09:00 login, as the request records write it
    return (LOGIN + timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S')


def request(minutes=1, **changes):
    record = {
        'user_id': 'bob-id', 'username': 'bob', 'resource': 'resource_1', 'action': 'read',
        'access_request_time': at(minutes), 'session_id': 'session-1', 'auth_time': LOGIN.timestamp(),
        'acr': '1', 'source_ip': '127.0.0.1', 'location': 'LOCAL', 'device_id': 'laptop', 'new_device': False,
    }
    record.update(changes)
    return record


SIGNALS = {'recent_requests': 2, 'auth_failures': 0, 'recent_denials': 0, 'email_verified': True}


def bob_profile():
    # Bob's usual behaviour: 100 reads of Resource 1 in work hours, short sessions
    profile = model.empty_profile()
    for day in range(10):
        previous = None
        for hour in range(9, 17):
            event = request(resource='resource_1', access_request_time=f'2026-10-{10 + day} {hour:02d}:30:00')
            profile = model.learn(profile, event, previous, recent_requests=3)
            previous = 'resource_1'
    return model.learn_session_length(profile, 45)


def evaluate(event, session=None, profile=None, signals=None, config=CONFIG):
    return model.evaluate(event, session, profile, dict(SIGNALS, **(signals or {})), config)


# --- Settings -------------------------------------------------------------------------

def test_settings_come_from_the_config():
    config = dict(CONFIG, riskModel=dict(CONFIG['riskModel'], halfLifeMinutes=20))
    assert risk_settings(config)['halfLifeMinutes'] == 20


def test_missing_section_uses_the_defaults():
    settings = risk_settings({})
    assert settings['weights'] == DEFAULT_RISK_MODEL['weights']
    assert settings['thresholds'] == DEFAULT_RISK_MODEL['thresholds']


def test_invalid_values_fall_back_to_the_defaults():
    settings = risk_settings({'riskModel': {
        'weights': {'accessFrequency': 'abc', 'authFailures': -1},
        'halfLifeMinutes': 0,
        'authFailures': {'cap': 'many'},
    }})
    assert settings['weights']['accessFrequency'] == DEFAULT_RISK_MODEL['weights']['accessFrequency']
    assert settings['weights']['authFailures'] == DEFAULT_RISK_MODEL['weights']['authFailures']
    assert settings['halfLifeMinutes'] == DEFAULT_RISK_MODEL['halfLifeMinutes']
    assert settings['authFailures']['cap'] == DEFAULT_RISK_MODEL['authFailures']['cap']


def test_thresholds_out_of_order_fall_back_to_the_defaults():
    settings = risk_settings({'riskModel': {'thresholds': {'MEDIUM': 0.6, 'HIGH': 0.5, 'CRITICAL': 0.9}}})
    assert settings['thresholds'] == DEFAULT_RISK_MODEL['thresholds']


def test_invalid_floors_are_dropped():
    settings = risk_settings({'riskModel': {'floors': [
        {'feature': 'authFailures', 'atLeast': 1, 'level': 'HIGH'},
        {'feature': 'noSuchFeature', 'atLeast': 1, 'level': 'HIGH'},
        {'feature': 'authFailures', 'atLeast': 1, 'level': 'LOW'},
        {'feature': 'authFailures', 'atLeast': 'x', 'level': 'HIGH'},
    ]}})
    assert len(settings['floors']) == 1


def test_default_weights_add_up_to_1():
    assert abs(sum(DEFAULT_RISK_MODEL['weights'].values()) - 1.0) < 1e-9
    assert set(DEFAULT_RISK_MODEL['weights']) == set(FEATURES)


# --- F1 Access frequency ----------------------------------------------------------------

def test_frequency_up_to_the_usual_rate_is_normal():
    assert f.access_frequency(10, None, SETTINGS['accessFrequency'])[0] == 0.0


def test_frequency_rises_with_the_rate():
    s = SETTINGS['accessFrequency']
    low, middle, high = (f.access_frequency(n, 10, s)[0] for n in (15, 25, 40))
    assert 0 < low < middle < high == 1.0


def test_frequency_uses_the_users_own_rate_but_not_below_the_minimum():
    s = SETTINGS['accessFrequency']
    assert f.access_frequency(30, 30, s)[0] == 0.0            # a busy user at their usual rate
    assert f.access_frequency(10, 1, s)[0] == 0.0             # minBaseline protects quiet users


# --- F2 Resource-access sequence --------------------------------------------------------

def test_usual_move_is_low_and_unusual_move_is_high():
    profile = bob_profile()
    known, admin = list(CONFIG['resources']), ['logging', 'policy_configuration']
    s = SETTINGS['resourceSequence']
    usual = f.resource_sequence('resource_1', 'resource_1', profile, known, admin, 0, True, s)[0]
    unusual = f.resource_sequence('resource_1', 'resource_2', profile, known, admin, 0, True, s)[0]
    assert usual < 0.1 < 0.9 < unusual


def test_admin_resource_and_denials_add_to_the_sequence():
    profile = bob_profile()
    known, admin = list(CONFIG['resources']), ['logging', 'policy_configuration']
    s = SETTINGS['resourceSequence']
    to_resource_2 = f.resource_sequence('resource_1', 'resource_2', profile, known, admin, 0, False, s)[0]
    to_logging = f.resource_sequence('resource_1', 'logging', profile, known, admin, 0, False, s)[0]
    with_denials = f.resource_sequence('resource_1', 'resource_2', profile, known, admin, 1, False, s)[0]
    assert to_resource_2 == 0.5  # no baseline yet
    assert to_logging == 0.8
    assert with_denials == 0.75


def test_sequence_never_goes_above_1():
    s = SETTINGS['resourceSequence']
    assert f.resource_sequence(None, 'logging', {}, ['logging'], ['logging'], 10, False, s)[0] == 1.0


# --- F3 Session duration ----------------------------------------------------------------

def test_session_duration():
    s = SETTINGS['sessionDuration']
    assert f.session_duration(30, None, s)[0] == 0.0          # default usual length is 60 minutes
    assert 0 < f.session_duration(120, None, s)[0] < 1
    assert f.session_duration(240, None, s)[0] == 1.0
    assert f.session_duration(100, 20, s)[0] == 1.0           # a user whose sessions are usually short


# --- F4 Authentication failures ---------------------------------------------------------

def test_auth_failures():
    s = SETTINGS['authFailures']
    assert f.auth_failures(0, s)[0] == 0.0
    assert f.auth_failures(2, s)[0] == 0.4
    assert f.auth_failures(9, s)[0] == 1.0


# --- F5 Time of day ---------------------------------------------------------------------

def test_time_of_day_without_history_uses_the_night_window():
    s = SETTINGS['timeOfDay']
    assert f.time_of_day(3, {}, False, True, s)[0] == s['nightScore']
    assert f.time_of_day(14, {}, False, False, s)[0] == 0.0


def test_time_of_day_with_history_uses_the_users_hours():
    s = SETTINGS['timeOfDay']
    hours = bob_profile()['hours']
    assert f.time_of_day(13, hours, True, False, s)[0] == 0.0   # bob's work hours
    assert f.time_of_day(3, hours, True, True, s)[0] == 1.0     # bob never works at 03:00
    assert f.time_of_day(22, hours, True, False, s)[0] == 1.0   # not night, but not bob's hours either


def test_hour_band_wraps_around_midnight():
    assert f.hours_in_band(0, 3) == [23, 0, 1]


# --- F6 Device familiarity --------------------------------------------------------------

def test_device_familiarity():
    s = SETTINGS['deviceFamiliarity']
    assert f.device_familiarity(False, 'laptop', 'laptop', s)[0] == 0.0
    assert f.device_familiarity(True, 'phone', None, s)[0] == s['newDevice']
    assert f.device_familiarity(None, 'phone', None, s)[0] == s['newDevice']        # missing counts as new
    assert f.device_familiarity(False, 'other', 'laptop', s)[0] == s['changedInSession']


# --- F7 Network or context change -------------------------------------------------------

def test_network_change():
    s = SETTINGS['networkChange']
    high, medium = {'KP'}, {'KE'}
    assert f.network_change('1.1.1.1', 'SE', '1.1.1.1', 'SE', high, medium, s)[0] == 0.0
    assert f.network_change('2.2.2.2', 'SE', '1.1.1.1', 'SE', high, medium, s)[0] == s['changed']
    assert f.network_change('1.1.1.1', 'KE', '1.1.1.1', 'KE', high, medium, s)[0] == s['mediumRiskLocation']
    assert f.network_change('2.2.2.2', 'KP', '1.1.1.1', 'SE', high, medium, s)[0] == s['highRiskLocation']


# --- F8 Identity assurance --------------------------------------------------------------

def test_identity_assurance_needs_mfa_used_not_only_set_up():
    s = SETTINGS['identityAssurance']
    assert f.identity_assurance('2', ['2'], True, s)[0] == 0.0
    assert f.identity_assurance('1', ['2'], True, s)[0] == s['passwordOnly']
    assert f.identity_assurance(None, ['2'], False, s)[0] == s['passwordOnly'] + s['unverifiedEmail']


# --- F9 Reaction to MFA challenges ------------------------------------------------------

def test_mfa_reaction():
    s = SETTINGS['mfaReaction']
    assert f.mfa_reaction(0, s)[0] == 0.0
    assert f.mfa_reaction(3, s)[0] == 1.0


# --- Combining, floors, memory and levels -----------------------------------------------

def test_levels():
    thresholds = SETTINGS['thresholds']
    assert [model.level_of(r, thresholds) for r in (0.1, 0.3, 0.6, 0.8)] == ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']


def test_admin_resources_raise_the_level_by_one():
    assert model.response_level('MEDIUM', True, SETTINGS) == 'HIGH'
    assert model.response_level('CRITICAL', True, SETTINGS) == 'CRITICAL'
    assert model.response_level('MEDIUM', False, SETTINGS) == 'MEDIUM'


def test_decay_halves_every_half_life():
    assert model.decayed(0.8, 10, 10) == 0.4
    assert model.decayed(0.8, 20, 10) == 0.2


def test_a_floor_cant_be_averaged_away():
    scores = {name: (0.0, '') for name in FEATURES}
    scores['authFailures'] = (1.0, '5 failed logins')
    plain = model.weighted_risk(scores, SETTINGS['weights'])
    risk, reason = model.apply_floors(plain, scores, SETTINGS)
    assert plain < SETTINGS['thresholds']['MEDIUM']
    assert risk == SETTINGS['thresholds']['HIGH'] and 'authFailures' in reason


def test_device_change_inside_the_session_is_at_least_medium():
    profile = bob_profile()
    _, session = evaluate(request(1), profile=profile)
    result, _ = evaluate(request(2, device_id='other'), session, profile)
    assert result['level'] == 'MEDIUM' and 'deviceFamiliarity' in result['floor']


def test_a_burst_of_requests_is_at_least_medium():
    profile = bob_profile()
    result, _ = evaluate(request(1), profile=profile, signals={'recent_requests': 40})
    assert result['level'] == 'MEDIUM' and 'accessFrequency' in result['floor']


def test_normal_request_is_low():
    result, session = evaluate(request(), profile=bob_profile())
    assert result['level'] == 'LOW', result
    assert session['last_resource'] == 'resource_1' and session['requests'] == 1


def test_every_feature_is_in_the_result():
    result, _ = evaluate(request())
    assert list(result['features']) == list(FEATURES)
    assert abs(sum(details['weight'] for details in result['features'].values()) - 1.0) < 0.01


def test_risk_is_recalculated_during_the_session():
    # The task's sequence: normal reads, then admin access, then repeated failed logins
    profile = bob_profile()
    session, risks = None, []
    steps = [
        (request(1), {}),
        (request(2), {}),
        (request(3, resource='logging'), {'recent_denials': 1}),
        (request(4, resource='policy_configuration'), {'recent_denials': 2}),
        (request(5), {'recent_denials': 2, 'auth_failures': 5}),
    ]
    for event, signals in steps:
        result, session = evaluate(event, session, profile, signals)
        risks.append(result)
    assert [r['level'] for r in risks[:2]] == ['LOW', 'LOW']
    assert risks[2]['level'] == 'MEDIUM'          # admin access after normal reads
    assert risks[4]['level'] in ('HIGH', 'CRITICAL')
    assert risks[4]['floor']


def test_memory_keeps_the_risk_up_and_then_lets_it_fall():
    profile = bob_profile()
    _, session = evaluate(request(1), profile=profile)
    odd, session = evaluate(request(2, resource='logging'), session, profile, {'recent_denials': 2})
    next_one, session = evaluate(request(3), session, profile)
    later, _ = evaluate(request(60), session, profile)
    assert odd['level'] == 'MEDIUM' and 'resourceSequence' in odd['floor']   # privilege abuse is not averaged away
    assert next_one['risk'] > next_one['event_risk']      # the odd request still counts
    assert next_one['risk'] < odd['risk']                 # but less
    assert later['level'] == 'LOW'                        # an hour of quiet brings it down


def test_memoryless_model_forgets_straight_away():
    config = dict(CONFIG, riskModel=dict(CONFIG['riskModel'], memory=False))
    profile = bob_profile()
    _, session = evaluate(request(1), profile=profile, config=config)
    _, session = evaluate(request(2, resource='logging'), session, profile, {'recent_denials': 2}, config=config)
    next_one, _ = evaluate(request(3), session, profile, config=config)
    assert next_one['risk'] == next_one['event_risk']


def test_new_session_starts_at_the_login_time():
    _, session = evaluate(request(90))
    assert session['started_at'] == at(0)


# --- Step-up and recovery -----------------------------------------------------------------

def test_passed_step_up_resets_the_risk_and_accepts_the_new_device():
    profile = bob_profile()
    _, session = evaluate(request(1), profile=profile)
    odd, session = evaluate(request(2, device_id='other', new_device=True, source_ip='10.0.0.9'), session, profile)
    session = model.request_step_up(session, 'otp', at(2))
    stepped_up = (LOGIN + timedelta(minutes=3)).timestamp()
    after, session = evaluate(request(4, device_id='other', new_device=True, source_ip='10.0.0.9',
                                      auth_time=stepped_up, acr='2'), session, profile)
    assert after['step_up'] == 'passed'
    assert after['risk'] == after['event_risk'] < odd['risk']
    assert after['features']['deviceFamiliarity']['reason'] == 'new device'   # no longer "changed in session"
    assert after['features']['networkChange']['score'] == 0.0
    assert session['step_up'] is None


def test_step_up_without_mfa_is_not_passed():
    _, session = evaluate(request(1))
    session = model.request_step_up(session, 'otp', at(1))
    result, session = evaluate(request(2, auth_time=(LOGIN + timedelta(minutes=2)).timestamp(), acr='1'), session)
    assert result['step_up'] is None and session['step_up'] is not None


def test_old_login_does_not_pass_a_step_up():
    _, session = evaluate(request(1))
    session = model.request_step_up(session, 'otp', at(1))
    result, _ = evaluate(request(2, acr='2'), session)  # auth_time is still the 09:00 login
    assert result['step_up'] is None


def test_step_up_not_passed_in_time_counts_as_failed():
    _, session = evaluate(request(1))
    session = model.request_step_up(session, 'otp', at(1))
    result, session = evaluate(request(1 + SETTINGS['stepUpTimeoutMinutes']), session)
    assert result['step_up'] == 'failed'
    assert session['failed_step_ups'] == 1
    assert result['features']['mfaReaction']['score'] > 0


def test_step_up_without_mfa_values_needs_only_a_new_login():
    # The fallback if OTP doesn't work: mfaAcrValues empty, a password login again is enough
    config = dict(CONFIG, riskModel=dict(CONFIG['riskModel'], mfaAcrValues=[]))
    _, session = evaluate(request(1), config=config)
    session = model.request_step_up(session, 'full', at(1))
    result, _ = evaluate(request(2, auth_time=(LOGIN + timedelta(minutes=2)).timestamp()), session, config=config)
    assert result['step_up'] == 'passed'


# --- Learning ------------------------------------------------------------------------------

def test_profile_needs_enough_history():
    profile = model.empty_profile()
    for minute in range(SETTINGS['minHistory'] - 1):
        profile = model.learn(profile, request(minute), 'resource_1', 2)
    assert not model.has_history(profile, SETTINGS)
    profile = model.learn(profile, request(30), 'resource_1', 2)
    assert model.has_history(profile, SETTINGS)


def test_profile_keeps_counts():
    profile = bob_profile()
    assert profile['requests'] == 80
    assert profile['resources'] == {'resource_1': 80}
    assert profile['transitions']['resource_1']['resource_1'] == 70
    assert profile['hours']['9'] == 10
    assert profile['session_minutes'] == 45


# --- Signals from data/ --------------------------------------------------------------------

def test_count_auth_failures():
    now = LOGIN
    ms = lambda minutes_ago: (now - timedelta(minutes=minutes_ago)).timestamp() * 1000  # noqa: E731
    attempts = [
        {'user_id': 'bob-id', 'auth_status': 0, 'time': ms(1)},
        {'user_id': 'bob-id', 'auth_status': 0, 'time': ms(5)},
        {'user_id': 'bob-id', 'auth_status': 1, 'time': ms(2)},
        {'user_id': 'bob-id', 'auth_status': 0, 'time': ms(30)},     # too old
        {'user_id': 'alice-id', 'auth_status': 0, 'time': ms(1)},    # someone else
    ]
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, 'auth_data.json')
        with open(path, 'w') as file:
            json.dump(attempts, file)
        assert count_auth_failures('bob-id', now, 10, path) == 2
        assert count_auth_failures('bob-id', now, 10, os.path.join(folder, 'missing.json')) == 0


def test_count_recent_denials():
    entries = [
        {'time': at(-30), 'user_id': 'bob-id', 'outcome': 'POLICY_VIOLATION', 'decided_by': 'Policy Engine'},
        {'time': at(-5), 'user_id': 'bob-id', 'outcome': 'POLICY_VIOLATION', 'decided_by': 'Policy Engine'},
        {'time': at(-4), 'user_id': 'bob-id', 'outcome': 'DENY', 'decided_by': 'Policy Engine'},
        {'time': at(-3), 'user_id': 'alice-id', 'outcome': 'POLICY_VIOLATION', 'decided_by': 'Policy Engine'},
        {'time': at(-1), 'user_id': 'bob-id', 'outcome': 'POLICY_VIOLATION', 'decided_by': 'Policy Engine'},
    ]
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, 'audit.log')
        with open(path, 'w') as file:
            file.writelines(json.dumps(entry) + '\n' for entry in entries)
        assert count_recent_denials('bob-id', at(0), 10, path) == 2


# --- Saving the state ----------------------------------------------------------------------

def store_in(folder):
    return RiskStore(os.path.join(folder, 'risk_state.json'), os.path.join(folder, 'risk_profiles.json'),
                     os.path.join(folder, 'risk_events.jsonl'))


def test_store_saves_sessions_and_profiles():
    with tempfile.TemporaryDirectory() as folder:
        store = store_in(folder)
        result, session = evaluate(request())
        with store.locked() as (sessions, profiles):
            sessions['session-1'] = session
            profiles['bob-id'] = bob_profile()
        with store.locked() as (sessions, profiles):
            assert sessions['session-1']['risk'] == result['risk']
            assert profiles['bob-id']['requests'] == 80


def test_store_does_not_save_after_an_error():
    with tempfile.TemporaryDirectory() as folder:
        store = store_in(folder)
        try:
            with store.locked() as (sessions, _):
                sessions['half-done'] = {}
                raise RuntimeError('stopped halfway')
        except RuntimeError:
            pass
        with store.locked() as (sessions, _):
            assert 'half-done' not in sessions


def test_idle_sessions_end_and_teach_the_session_length():
    _, session = evaluate(request(1))
    _, session = evaluate(request(40), session)
    sessions, profiles = {'session-1': session}, {}
    assert end_idle_sessions(sessions, profiles, at(50)) == []
    assert end_idle_sessions(sessions, profiles, at(80)) == ['session-1']
    assert sessions == {} and profiles['bob-id']['session_minutes'] == 40


def test_old_risk_events_are_removed():
    with tempfile.TemporaryDirectory() as folder:
        store = store_in(folder)
        store.log_event({'time': '2026-09-01 10:00:00', 'risk': 0.1})
        store.log_event({'time': '2026-11-08 10:00:00', 'risk': 0.2})
        assert store.prune_events(30, at(0)) == 1
        with open(store.events_file) as file:
            assert [json.loads(line)['risk'] for line in file] == [0.2]


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
        except Exception as e:  # noqa: BLE001  (show the error and go on with the other tests)
            failed += 1
            print(f"ERROR {name}  {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
