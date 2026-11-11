'''

The Policy Engine's rules (assignment section 3.4): six named policies that turn an
access request, its trust score and the user's login history into a decision.

The policies are checked in order, and the first one that denies decides. If none
denies, P6 allows. Every decision says which policy decided and why.

riskMode in policyConfiguration.yml chooses the set of policies:

    static    (System A, Task 1)  P1, P2, P3, P4, P5, then P6
    adaptive  (System B, Task 2)  P1, P2, R1, then P6. R1 chooses the response from the
                                  session's risk level: allow, OTP step-up, full step-up,
                                  or deny with an alert.

The policies and the reasons behind them are explained in docs/policies.md.

'''
from datetime import datetime

from .config import load_policy_configuration
from .risk import model as risk_model
from .risk.defaults import risk_settings
from .trust_algorithm import config_time, is_in_night_window, DEFAULT_NIGHT_END, DEFAULT_NIGHT_START

DEFAULT_ADMIN_MIN_TRUST_SCORE = 0.75
DEFAULT_PRIVILEGED_ROLES = ['Administrator', 'Policy Administrator', 'Approver']
DEFAULT_SIGN_IN_SUCCESS_THRESHOLD = 0.5
RISK_MODES = ('static', 'adaptive')


# --- Helpers ---------------------------------------------------------------------

def number(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def risk_mode(config):
    # Anything other than 'adaptive' runs the Task 1 policies, so a typo can't switch the checks off
    return 'adaptive' if str(config.get('riskMode', 'static')).strip().lower() == 'adaptive' else 'static'


def resource_entry(config, resource):
    return (config.get('resources') or {}).get(resource)


def country_codes(config, key):
    return {str(code).strip().upper() for code in (config.get(key) or []) if str(code).strip()}


def privileged_roles_of(roles, config):
    # The user's roles that can change the system or approve access for others
    privileged = config.get('privilegedRoles')
    if privileged is None:
        privileged = DEFAULT_PRIVILEGED_ROLES
    return [role for role in roles if role in privileged]


def lowest_factors(trust_factors, count=2):
    # The factors that pulled the score down most, for the reason of a low-trust deny
    if not trust_factors:
        return ''
    weak = sorted((item for item in trust_factors.items() if item[1]['score'] < 1.0), key=lambda item: item[1]['score'])
    if not weak:
        return ''
    return '. Lowest factors: ' + ', '.join(f"{name} {details['score']:g} ({details['reason']})" for name, details in weak[:count])


# --- The policies: each returns None (doesn't deny) or the reason for denying ----------
#
# They all take the same `facts`: the request record, the trust score and breakdown,
# the sign-in success rate, the configuration and the resource's table entry.

def p1_invalid_authentication(facts):
    request = facts['request']
    if request.get('authentication_status') != 'authenticated':
        return f"The user is not authenticated (status: {request.get('authentication_status') or 'missing'})"
    if facts['sign_in_success_rate'] is None:
        return 'No login is recorded for this user, so the login history cannot be checked'
    return None


def p2_unauthorized_resource(facts):
    request, entry = facts['request'], facts['entry']
    resource = request.get('resource')
    if entry is None:
        return f'{resource} is not in the resource table, so nobody may access it'
    allowed = list(entry.get('allowedRoles') or [])
    roles = list(request.get('roles') or [])
    if not set(roles) & set(allowed):
        return f"Role {', '.join(roles) or 'none'} may not access {resource} (allowed: {', '.join(allowed)})"

    # Changing something needs a role in writeRoles. Without writeRoles, nobody may change the resource.
    if request.get('action') != 'read':
        writers = list(entry.get('writeRoles') or [])
        if not set(roles) & set(writers):
            return (f"Role {', '.join(roles)} may view {resource} but not change it "
                    f"(may change: {', '.join(writers) or 'nobody'})")
    return None


def p3_risky_context(facts):
    request, config, entry = facts['request'], facts['config'], facts['entry']

    # Privileged roles get stricter context rules, because a stolen privileged account can do more damage
    privileged = privileged_roles_of(request.get('roles') or [], config)
    location = str(request.get('location') or '').strip().upper()

    if location in country_codes(config, 'highRiskLocations'):
        return f'The request comes from {location}, a high-risk location'
    if privileged and location in country_codes(config, 'mediumRiskLocations'):
        return f"The request comes from {location}, a medium-risk location, and {', '.join(privileged)} is a privileged role"

    start = config_time(config, 'periodStartInput', DEFAULT_NIGHT_START)
    end = config_time(config, 'periodEndInput', DEFAULT_NIGHT_END)
    time_of_day = datetime.strptime(request['access_request_time'], '%Y-%m-%d %H:%M:%S').time()
    if is_in_night_window(time_of_day, start, end):
        window = f"{start.strftime('%H:%M')} to {end.strftime('%H:%M')}"
        if entry.get('adminResource'):
            return f"Admin resources can't be used inside the night window ({window})"
        if privileged:
            return f"{', '.join(privileged)} is a privileged role, and privileged roles can't be used inside the night window ({window})"

    threshold = number(config.get('signInSuccessThreshold'), DEFAULT_SIGN_IN_SUCCESS_THRESHOLD)
    if facts['sign_in_success_rate'] < threshold:
        return f"Only {facts['sign_in_success_rate']:.0%} of the user's recent logins succeeded (minimum {threshold:.0%})"
    return None


def p4_admin_resource(facts):
    if not facts['entry'].get('adminResource') or facts['trust_score'] is None:
        return None  # not an admin resource, or no score (P5 denies that)
    minimum = number(facts['config'].get('adminMinTrustScore'), DEFAULT_ADMIN_MIN_TRUST_SCORE)
    if facts['trust_score'] < minimum:
        return (f"Admin resources need a trust score of at least {minimum:g}, "
                f"and this request has {facts['trust_score']:.2f}{lowest_factors(facts['trust_factors'])}")
    return None


def p5_low_trust(facts):
    resource = facts['request'].get('resource')
    if facts['trust_score'] is None:
        return f"No trust score for this request ({facts.get('trust_error') or 'the Trust Engine sent none'})"
    minimum = number(facts['entry'].get('minTrustScore'), 0.0)
    if facts['trust_score'] < minimum:
        return (f"Trust score {facts['trust_score']:.2f} is below the minimum of {minimum:g} for {resource}"
                f"{lowest_factors(facts['trust_factors'])}")
    return None


# (ID, name, outcome when it denies, check), in the order they're checked
POLICIES = [
    ('P1', 'Invalid authentication', 'AUTHENTICATION_FAILURE', p1_invalid_authentication),
    ('P2', 'Unauthorized resource', 'POLICY_VIOLATION', p2_unauthorized_resource),
    ('P3', 'Risky context', 'DENY', p3_risky_context),
    ('P4', 'Admin resource', 'DENY', p4_admin_resource),
    ('P5', 'Low trust', 'DENY', p5_low_trust),
]


# --- R1 Adaptive risk (adaptive mode only) ----------------------------------------------
#
# R1 returns a whole decision, not only a reason, because its outcome depends on the level.

STEP_UP_FOR_LEVEL = {'MEDIUM': 'otp', 'HIGH': 'full'}
STEP_UP_TEXT = {'otp': 'a one-time code (OTP)', 'full': 'a full login again (password and OTP)'}


def risk_summary(risk):
    text = f"Session risk {risk['risk']:.3f} ({risk['level']})"
    if risk.get('top_features'):
        text += f". Raised by: {risk['top_features']}"
    if risk.get('floor'):
        text += f". {risk['floor']}"
    return text


def r1_adaptive_risk(facts):
    # None if the risk allows access, otherwise the decision
    risk = facts['risk']
    base = {'access_decision': 0, 'policy_id': 'R1', 'policy_name': 'Adaptive risk'}
    if not risk:
        return dict(base, decision='DENY', outcome='DENY', response_level=None,
                    reason=f"No risk score for this request ({facts.get('risk_error') or 'the Risk Engine sent none'})")

    response = risk_model.response_level(risk['level'], bool(facts['entry'].get('adminResource')),
                                         risk_settings(facts['config']))
    admin_note = ' (one level up, because this is an admin resource)' if response != risk['level'] else ''
    facts['response_level'] = response
    if response == 'LOW' or risk_model.is_covered(response, risk.get('verified_level')):
        return None
    if response == 'CRITICAL':
        return dict(base, decision='DENY', outcome='RISK_ALERT', response_level=response,
                    reason=f"{risk_summary(risk)}. The response level is CRITICAL{admin_note}, so access is denied and an alert is raised")
    kind = STEP_UP_FOR_LEVEL[response]
    return dict(base, decision='STEP_UP', outcome='STEP_UP_REQUIRED', step_up=kind, response_level=response,
                reason=f"{risk_summary(risk)}. The response level is {response}{admin_note}, so {STEP_UP_TEXT[kind]} is needed")


def decide_adaptive(facts):
    for policy_id, name, outcome, check in POLICIES[:2]:  # P1 and P2 stay hard rules
        reason = check(facts)
        if reason:
            return {'decision': 'DENY', 'access_decision': 0, 'policy_id': policy_id, 'policy_name': name,
                    'outcome': outcome, 'reason': reason}

    decision = r1_adaptive_risk(facts)
    if decision:
        return decision

    risk, response = facts['risk'], facts['response_level']
    if response == 'LOW':
        why = f"{risk_summary(risk)}, so no extra check is needed"
    else:
        why = f"{risk_summary(risk)}. The response level is {response}, and a step-up passed in this session covers it"
    return {'decision': 'ALLOW', 'access_decision': 1, 'policy_id': 'P6', 'policy_name': 'Permitted access',
            'outcome': 'ALLOW', 'response_level': response,
            'reason': f"Role {', '.join(facts['request'].get('roles') or [])} may access {facts['request'].get('resource')}. {why}"}


# --- The decision ------------------------------------------------------------------

def decide(access_request, trust_score, trust_factors=None, sign_in_success_rate=None, trust_error=None, config=None,
           risk=None, risk_error=None):
    # Returns {'decision', 'access_decision', 'policy_id', 'policy_name', 'outcome', 'reason'}.
    # In adaptive mode, also 'response_level', and 'step_up' ('otp' or 'full') for a step-up.
    # Tests can pass a configuration directly instead of reading the file.
    if config is None:
        config = load_policy_configuration()

    facts = {
        'request': access_request,
        'trust_score': trust_score,
        'trust_factors': trust_factors,
        'trust_error': trust_error,
        'risk': risk,
        'risk_error': risk_error,
        'sign_in_success_rate': sign_in_success_rate,
        'config': config,
        'entry': resource_entry(config, access_request.get('resource')),
    }

    if risk_mode(config) == 'adaptive':
        return decide_adaptive(facts)

    for policy_id, name, outcome, check in POLICIES:
        reason = check(facts)
        if reason:
            return {'decision': 'DENY', 'access_decision': 0, 'policy_id': policy_id, 'policy_name': name,
                    'outcome': outcome, 'reason': reason}

    minimum = number(facts['entry'].get('minTrustScore'), 0.0)
    return {'decision': 'ALLOW', 'access_decision': 1, 'policy_id': 'P6', 'policy_name': 'Permitted access',
            'outcome': 'ALLOW',
            'reason': (f"Role {', '.join(access_request.get('roles') or [])} may access {access_request.get('resource')}, "
                       f"and trust score {trust_score:.2f} meets the minimum of {minimum:g}")}


# --- Retired -----------------------------------------------------------------------
#
# The original Policy Engine, kept for comparison. It had one trust threshold per role,
# and none for Researcher and Administrator, so they were never denied for low trust.
# It didn't know which resource was requested. See "Why the minimum trust is per
# resource, not per role" in docs/policies.md.
#
# def retired_make_access_decision(user_role, user_trust_score, sign_in_success_rate, policy_configuration):
#     admin_threshold = float(policy_configuration['adminThreshold'])                        # 0.6
#     approver_threshold = float(policy_configuration['approverThreshold'])                  # 0.9
#     security_viewer_threshold = float(policy_configuration['securityViewerThreshold'])     # 0.4
#     sign_in_success_threshold = float(policy_configuration['signInSuccessThreshold'])      # 0.5
#
#     verdict = 1
#     if user_role == 'Approver' and user_trust_score < approver_threshold:
#         verdict = 0
#     elif user_role == 'Security Viewer' and user_trust_score < security_viewer_threshold:
#         verdict = 0
#     elif user_role == 'Policy Administrator' and user_trust_score < admin_threshold:
#         verdict = 0
#
#     if sign_in_success_rate < sign_in_success_threshold:
#         verdict = 0
#
#     return verdict
