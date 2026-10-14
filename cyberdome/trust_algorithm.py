'''

The Trust Engine's score: how much we trust one access request, between 0 and 1.

Seven factors are each scored between 0 and 1 and combined with the weights from
policyConfiguration.yml (trustWeights). Each factor function returns (score, reason),
so the Policy Engine and the logs can show why a score is low.

The factors, weights and reasons are explained in docs/trust-model.md.

'''
from datetime import datetime

from .data_paths import ACCESS_REQUESTS_FILE, USER_DATA_FILE
from .policy import load_policy_configuration
from .trust_signals import (count_recent_access_requests, get_latest_access_request, get_sign_in_success_rate,
                            get_user_identity_data_by_id)

# Used when policyConfiguration.yml has no (or no valid) trustWeights
DEFAULT_WEIGHTS = {
    'loginHistory': 0.20,
    'device': 0.20,
    'accessFrequency': 0.15,
    'location': 0.15,
    'identityStrength': 0.15,
    'accessTime': 0.10,
    'accountAge': 0.05,
}
# Names shown on the policy page
FACTOR_LABELS = {
    'loginHistory': 'Login History',
    'device': 'Device (known or new)',
    'accessFrequency': 'Access Frequency',
    'location': 'Location',
    'identityStrength': 'Identity Strength (verified email, MFA)',
    'accessTime': 'Time of Access',
    'accountAge': 'Account Age',
}
DEFAULT_FREQUENCY_WINDOW_MINUTES = 5
DEFAULT_FREQUENCY_MAX_REQUESTS = 30
DEFAULT_NIGHT_START = '00:00:00'
DEFAULT_NIGHT_END = '06:00:00'

MS_PER_MONTH = 1000 * 60 * 60 * 24 * 30  # a month counted as 30 days


# --- Settings from policyConfiguration.yml ---------------------------------------

def trust_weights(config):
    # The weights from the config. Missing or invalid ones fall back to the default, negative ones count as 0.
    configured = config.get('trustWeights') or {}
    weights = {}
    for factor, default in DEFAULT_WEIGHTS.items():
        try:
            weights[factor] = max(float(configured.get(factor, default)), 0.0)
        except (TypeError, ValueError):
            weights[factor] = default
    if sum(weights.values()) <= 0:
        return dict(DEFAULT_WEIGHTS)
    return weights


def config_number(config, key, default):
    try:
        return float(config.get(key, default))
    except (TypeError, ValueError):
        return default


def config_time(config, key, default):
    try:
        return datetime.strptime(str(config.get(key) or default), '%H:%M:%S').time()
    except ValueError:
        return datetime.strptime(default, '%H:%M:%S').time()


def country_list(config, key):
    # A risk list from the config as upper-case country codes, without empty entries
    return {str(code).strip().upper() for code in (config.get(key) or []) if str(code).strip()}


def is_in_night_window(time_of_day, start, end):
    # The window can cross midnight, for example 22:00 to 06:00
    if start <= end:
        return start <= time_of_day <= end
    return time_of_day >= start or time_of_day <= end


# --- The 7 factors: each returns (score between 0 and 1, reason) --------------------

def login_history_score(sign_in_success_rate):
    if sign_in_success_rate is None:
        return 0.5, 'no login history'
    rate = min(max(sign_in_success_rate, 0.0), 1.0)
    return rate, f'{rate:.0%} of recent logins succeeded'


def device_score(new_device):
    # A missing value counts as a new device (fail safe)
    if new_device is False:
        return 1.0, 'known device'
    return 0.4, 'new device'


def access_frequency_score(recent_requests, window_minutes, max_requests):
    if recent_requests <= max_requests:
        return 1.0, f'{recent_requests} requests in the last {window_minutes:g} minutes'
    return 0.3, f'{recent_requests} requests in the last {window_minutes:g} minutes (more than {max_requests:g})'


def location_score(location, config):
    location = str(location or 'Unknown').strip().upper()
    if location in country_list(config, 'highRiskLocations'):
        return 0.1, f'{location} is a high-risk location'
    if location in country_list(config, 'mediumRiskLocations'):
        return 0.5, f'{location} is a medium-risk location'
    if location == 'LOCAL' or location in country_list(config, 'lowRiskLocations'):
        return 1.0, f'{location} is a low-risk location'
    if location == 'UNKNOWN':
        return 0.5, 'location unknown'
    return 0.7, f'{location} is not in any risk list'


def identity_strength_score(identity_data):
    email_verified = bool(identity_data.get('email_verified'))
    mfa_enabled = bool(identity_data.get('totp_enabled'))
    score = 0.5 * email_verified + 0.5 * mfa_enabled
    reason = f"email {'verified' if email_verified else 'not verified'}, MFA {'on' if mfa_enabled else 'off'}"
    return score, reason


def access_time_score(access_request_time, config):
    start = config_time(config, 'periodStartInput', DEFAULT_NIGHT_START)
    end = config_time(config, 'periodEndInput', DEFAULT_NIGHT_END)
    time_of_day = datetime.strptime(access_request_time, '%Y-%m-%d %H:%M:%S').time()
    window = f"{start.strftime('%H:%M')} to {end.strftime('%H:%M')}"
    if is_in_night_window(time_of_day, start, end):
        return 0.5, f'inside the night window ({window})'
    return 1.0, f'outside the night window ({window})'


def account_age_score(created_timestamp, now=None):
    # created_timestamp is Keycloak's, in milliseconds. The oldest tier is checked first.
    now = now or datetime.now()
    months = (now.timestamp() * 1000 - created_timestamp) / MS_PER_MONTH
    if months >= 6:
        return 1.0, f'account is {months:.0f} months old'
    if months >= 1:
        return 0.7, f'account is {months:.0f} months old'
    return 0.4, f'account is {months * 30:.0f} days old'


# --- The score -------------------------------------------------------------------

def calculate_trust(identity_data, access_request, sign_in_success_rate, recent_requests, config):
    # Scores all 7 factors and combines them. Takes the data directly, so tests can call it without files.
    # Returns {'score': ..., 'factors': {factor: {'score', 'weight', 'reason'}}}
    window_minutes = config_number(config, 'accessFrequencyWindowMinutes', DEFAULT_FREQUENCY_WINDOW_MINUTES)
    max_requests = config_number(config, 'accessFrequencyMaxRequests', DEFAULT_FREQUENCY_MAX_REQUESTS)

    factor_scores = {
        'loginHistory': login_history_score(sign_in_success_rate),
        'device': device_score(access_request.get('new_device')),
        'accessFrequency': access_frequency_score(recent_requests, window_minutes, max_requests),
        'location': location_score(access_request.get('location'), config),
        'identityStrength': identity_strength_score(identity_data),
        'accessTime': access_time_score(access_request['access_request_time'], config),
        'accountAge': account_age_score(identity_data['created_timestamp']),
    }

    weights = trust_weights(config)
    total_weight = sum(weights.values())
    score = sum(weights[factor] * factor_score for factor, (factor_score, _) in factor_scores.items()) / total_weight

    factors = {
        factor: {'score': round(factor_score, 3), 'weight': round(weights[factor] / total_weight, 3), 'reason': reason}
        for factor, (factor_score, reason) in factor_scores.items()
    }
    return {'score': round(score, 4), 'factors': factors}


def calculate_trust_breakdown(user_id, access_request=None):
    # Loads the user's data from data/ and scores this access request.
    # The config is read on every call, so changes on the policy page apply straight away.
    config = load_policy_configuration()
    identity_data = get_user_identity_data_by_id(user_id, USER_DATA_FILE)
    if not identity_data:
        raise ValueError('No identity record for this user')
    access_request = access_request or get_latest_access_request(user_id, ACCESS_REQUESTS_FILE)
    if not access_request:
        raise ValueError('No access request for this user')

    window_minutes = config_number(config, 'accessFrequencyWindowMinutes', DEFAULT_FREQUENCY_WINDOW_MINUTES)
    recent_requests = count_recent_access_requests(user_id, access_request['access_request_time'], window_minutes,
                                                   ACCESS_REQUESTS_FILE, exclude_id=access_request.get('ID'))

    return calculate_trust(identity_data, access_request, get_sign_in_success_rate(user_id), recent_requests, config)


def calculate_overall_trust_score(user_id, access_request=None):
    # Only the number, for callers that don't need the breakdown (for example tests/test.py)
    return calculate_trust_breakdown(user_id, access_request)['score']


# --- Retired factors ---------------------------------------------------------------
#
# The original CyberDome also scored these inputs. We removed them from the score
# (see "Factors we removed" in docs/trust-model.md), and keep the old code here,
# commented out, in case we want to bring one back.
#
# def retired_factor_scores(identity_data, authentication_data, access_request_data):
#     # Role: a role says what a user may do, not how much we trust this request.
#     # Higher scores for admins would trust a stolen admin account more.
#     if identity_data['user_role'] == 'Policy Administrator':
#         user_role_score = 0.9
#     elif identity_data['user_role'] == 'Approver':
#         user_role_score = 0.7
#     else:
#         user_role_score = 0.5
#
#     # Authentication type: every browser login through Keycloak is 'code', so everyone got 0.7.
#     if authentication_data['auth_type'] == 'code':
#         auth_type_score = 0.7
#     else:
#         auth_type_score = 0.5
#
#     # Operating system: Linux scored lower, with no reason given.
#     if 'Linux' in access_request_data['device_OS']:
#         device_os_score = 0.5
#     else:
#         device_os_score = 0.8
#
#     # Device type: mobile scored lower, with no reason given. Known or new device says more.
#     if access_request_data['device_type'] == 'Mobile':
#         device_type_score = 0.5
#     else:
#         device_type_score = 0.8
#
#     # In the original model these were weighted as: role 0.2 of the identity segment,
#     # auth type 0.4 of the authentication segment, OS and device type 0.25 each of the context segment.
#     return {
#         'role': user_role_score,
#         'auth_type': auth_type_score,
#         'device_os': device_os_score,
#         'device_type': device_type_score,
#     }
