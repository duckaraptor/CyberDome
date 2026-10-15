'''

Tests for the Policy Engine's policies P1 to P6 (assignment section 3.4, docs/policies.md).

They use made-up requests and a made-up configuration, so they don't need Keycloak,
the engines or the files in data/. Each test is a function named test_..., so pytest
can run them too.

Run from anywhere:  python3 tests/test_policies.py

'''
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from cyberdome.policy import decide  # noqa: E402  (needs the path above)

CONFIG = {
    'adminMinTrustScore': 0.75,
    'highRiskLocations': ['KP'],
    'mediumRiskLocations': ['KE'],
    'privilegedRoles': ['Administrator', 'Policy Administrator', 'Approver'],
    'periodStartInput': '00:00:00',
    'periodEndInput': '06:00:00',
    'signInSuccessThreshold': 0.5,
    'resources': {
        'resource_1': {'allowedRoles': ['Researcher', 'Administrator'], 'writeRoles': [], 'adminResource': False, 'minTrustScore': 0.6},
        'resource_2': {'allowedRoles': ['Administrator'], 'writeRoles': [], 'adminResource': False, 'minTrustScore': 0.75},
        'policy_configuration': {'allowedRoles': ['Administrator', 'Policy Administrator'], 'writeRoles': ['Policy Administrator'],
                                 'adminResource': True, 'minTrustScore': 0.6},
        'logging': {'allowedRoles': ['Administrator', 'Security Viewer'], 'adminResource': True, 'minTrustScore': 0.6},
    },
}

FACTORS = {
    'device': {'score': 0.4, 'weight': 0.2, 'reason': 'new device'},
    'location': {'score': 1.0, 'weight': 0.15, 'reason': 'LOCAL is a low-risk location'},
    'accessFrequency': {'score': 0.3, 'weight': 0.15, 'reason': '45 requests in the last 5 minutes'},
}


def request(roles=('Researcher',), resource='resource_1', **changes):
    record = {'roles': list(roles), 'resource': resource, 'action': 'read', 'authentication_status': 'authenticated',
              'location': 'LOCAL', 'new_device': False, 'access_request_time': '2026-10-14 12:00:00'}
    record.update(changes)
    return record


def run(access_request, trust_score=0.9, sign_in_success_rate=1.0, trust_factors=None, trust_error=None, config=CONFIG):
    return decide(access_request, trust_score, trust_factors, sign_in_success_rate, trust_error, config)


def assert_decision(result, decision, policy_id, outcome):
    assert (result['decision'], result['policy_id'], result['outcome']) == (decision, policy_id, outcome), result


# --- Each policy ---------------------------------------------------------------------

def test_p1_unauthenticated_request_is_denied():
    result = run(request(authentication_status='unauthenticated'))
    assert_decision(result, 'DENY', 'P1', 'AUTHENTICATION_FAILURE')


def test_p1_no_login_history_is_denied():
    assert_decision(run(request(), sign_in_success_rate=None), 'DENY', 'P1', 'AUTHENTICATION_FAILURE')


def test_p2_role_not_allowed():
    result = run(request(roles=['Researcher'], resource='resource_2'))
    assert_decision(result, 'DENY', 'P2', 'POLICY_VIOLATION')
    assert 'Researcher' in result['reason'] and 'Administrator' in result['reason']


def test_p2_no_roles():
    assert_decision(run(request(roles=[])), 'DENY', 'P2', 'POLICY_VIOLATION')


def test_p2_unknown_resource():
    assert_decision(run(request(resource='secret_resource')), 'DENY', 'P2', 'POLICY_VIOLATION')


def test_p2_checks_all_roles_not_only_the_first():
    assert_decision(run(request(roles=['Approver', 'Administrator'], resource='resource_2')), 'ALLOW', 'P6', 'ALLOW')


def test_p2_write_needs_a_write_role():
    # Separation of duties: an Administrator may view the policies, only a Policy Administrator may change them
    viewer = run(request(roles=['Administrator'], resource='policy_configuration', action='read'))
    assert_decision(viewer, 'ALLOW', 'P6', 'ALLOW')
    writer = run(request(roles=['Administrator'], resource='policy_configuration', action='write'))
    assert_decision(writer, 'DENY', 'P2', 'POLICY_VIOLATION')
    assert 'not change it' in writer['reason']
    assert_decision(run(request(roles=['Policy Administrator'], resource='policy_configuration', action='write')), 'ALLOW', 'P6', 'ALLOW')


def test_p2_without_write_roles_nobody_may_write():
    # logging has no writeRoles in the test config: fail closed
    assert_decision(run(request(roles=['Administrator'], resource='logging', action='write')), 'DENY', 'P2', 'POLICY_VIOLATION')


def test_p3_high_risk_location():
    result = run(request(location='KP'))
    assert_decision(result, 'DENY', 'P3', 'DENY')
    assert 'KP' in result['reason']


def test_p3_admin_resource_at_night():
    result = run(request(roles=['Administrator'], resource='policy_configuration', access_request_time='2026-10-14 03:00:00'))
    assert_decision(result, 'DENY', 'P3', 'DENY')


def test_p3_normal_role_on_a_normal_resource_at_night_is_allowed():
    assert_decision(run(request(roles=['Researcher'], access_request_time='2026-10-14 03:00:00')), 'ALLOW', 'P6', 'ALLOW')


def test_p3_privileged_role_at_night_is_denied_on_any_resource():
    result = run(request(roles=['Administrator'], resource='resource_1', access_request_time='2026-10-14 03:00:00'))
    assert_decision(result, 'DENY', 'P3', 'DENY')
    assert 'privileged' in result['reason']


def test_p3_admin_resource_at_night_is_denied_for_normal_roles_too():
    result = run(request(roles=['Security Viewer'], resource='logging', access_request_time='2026-10-14 03:00:00'))
    assert_decision(result, 'DENY', 'P3', 'DENY')


def test_p3_medium_risk_location_depends_on_the_role():
    # The same context, a different answer for a different role
    assert_decision(run(request(roles=['Researcher'], location='KE')), 'ALLOW', 'P6', 'ALLOW')
    result = run(request(roles=['Administrator'], location='KE'))
    assert_decision(result, 'DENY', 'P3', 'DENY')
    assert 'KE' in result['reason'] and 'Administrator' in result['reason']


def test_p3_too_many_failed_logins():
    assert_decision(run(request(), sign_in_success_rate=0.3), 'DENY', 'P3', 'DENY')


def test_p4_admin_resource_needs_the_admin_minimum():
    result = run(request(roles=['Administrator'], resource='policy_configuration'), trust_score=0.7, trust_factors=FACTORS)
    assert_decision(result, 'DENY', 'P4', 'DENY')
    assert 'device 0.4 (new device)' in result['reason']


def test_p4_admin_on_a_new_device_alone_still_passes():
    # A new device alone gives about 0.78, so a Policy Administrator can make a device known
    result = run(request(roles=['Policy Administrator'], resource='policy_configuration', new_device=True), trust_score=0.775)
    assert_decision(result, 'ALLOW', 'P6', 'ALLOW')


def test_p5_low_trust_names_the_lowest_factors():
    result = run(request(roles=['Administrator'], resource='resource_2'), trust_score=0.67, trust_factors=FACTORS)
    assert_decision(result, 'DENY', 'P5', 'DENY')
    assert 'accessFrequency 0.3' in result['reason'] and 'device 0.4' in result['reason']
    assert 'location' not in result['reason']  # factors at 1.0 aren't listed


def test_p5_no_trust_score():
    result = run(request(), trust_score=None, trust_error='Trust evaluation failed: no identity record')
    assert_decision(result, 'DENY', 'P5', 'DENY')
    assert 'no identity record' in result['reason']


def test_p5_minimum_is_per_resource():
    # 0.7 is enough for resource_1 (0.6) but not for resource_2 (0.75)
    assert_decision(run(request(roles=['Administrator'], resource='resource_1'), trust_score=0.7), 'ALLOW', 'P6', 'ALLOW')
    assert_decision(run(request(roles=['Administrator'], resource='resource_2'), trust_score=0.7), 'DENY', 'P5', 'DENY')


def test_p6_allow_says_why():
    result = run(request())
    assert_decision(result, 'ALLOW', 'P6', 'ALLOW')
    assert result['access_decision'] == 1 and 'resource_1' in result['reason']


# --- Order: the clearest reason wins ----------------------------------------------------

def test_role_is_checked_before_trust():
    assert run(request(resource='resource_2'), trust_score=0.1)['policy_id'] == 'P2'


def test_high_risk_location_is_reported_before_low_trust():
    assert run(request(location='KP'), trust_score=0.3)['policy_id'] == 'P3'


def test_unauthenticated_is_reported_before_everything():
    result = run(request(authentication_status='unauthenticated', resource='resource_2', location='KP'), trust_score=0.1)
    assert result['policy_id'] == 'P1'


# --- The five scenarios from the task ---------------------------------------------------

def test_scenario_1_valid_request():
    assert_decision(run(request(roles=['Researcher'], resource='resource_1')), 'ALLOW', 'P6', 'ALLOW')


def test_scenario_2_unauthorized_resource():
    assert_decision(run(request(roles=['Researcher'], resource='resource_2')), 'DENY', 'P2', 'POLICY_VIOLATION')


def test_scenario_3_invalid_authentication():
    assert_decision(run(request(authentication_status='unauthenticated')), 'DENY', 'P1', 'AUTHENTICATION_FAILURE')


def test_scenario_4_low_trust():
    result = run(request(roles=['Researcher'], resource='resource_1', new_device=True), trust_score=0.47, trust_factors=FACTORS)
    assert_decision(result, 'DENY', 'P5', 'DENY')


def test_scenario_5_admin_on_admin_resource():
    assert_decision(run(request(roles=['Administrator'], resource='policy_configuration')), 'ALLOW', 'P6', 'ALLOW')
    assert_decision(run(request(roles=['Policy Administrator'], resource='policy_configuration', action='write')),
                    'ALLOW', 'P6', 'ALLOW')


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
