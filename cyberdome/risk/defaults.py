'''

The risk model's settings. Each one has a default here, and policyConfiguration.yml
can change it in the riskModel section. A missing or invalid value falls back to the
default, so a typo in the file can't switch a check off.

Why each default has its value is explained in docs/risk-model.md.

'''
import copy

# The order is the order we show the features in (logs, audit entries, the policy page)
FEATURES = (
    'accessFrequency',
    'resourceSequence',
    'sessionDuration',
    'authFailures',
    'timeOfDay',
    'deviceFamiliarity',
    'networkChange',
    'identityAssurance',
    'mfaReaction',
)

FEATURE_LABELS = {
    'accessFrequency': 'F1 Access frequency',
    'resourceSequence': 'F2 Resource-access sequence',
    'sessionDuration': 'F3 Session duration',
    'authFailures': 'F4 Authentication failures',
    'timeOfDay': 'F5 Time of day',
    'deviceFamiliarity': 'F6 Device familiarity',
    'networkChange': 'F7 Network or context change',
    'identityAssurance': 'F8 Identity assurance',
    'mfaReaction': 'F9 Reaction to MFA challenges',
}

LEVELS = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

DEFAULT_RISK_MODEL = {
    # The ARB-ZTA paper's five factors keep the paper's order and ratios, scaled to 0.60 together:
    # accessFrequency and authFailures 0.25 -> 0.15, sessionDuration 0.20 -> 0.12,
    # timeOfDay and mfaReaction 0.15 -> 0.09. The other four share 0.40.
    'weights': {
        'accessFrequency': 0.15,
        'resourceSequence': 0.12,
        'sessionDuration': 0.12,
        'authFailures': 0.15,
        'timeOfDay': 0.09,
        'deviceFamiliarity': 0.10,
        'networkChange': 0.10,
        'identityAssurance': 0.08,
        'mfaReaction': 0.09,
    },
    # A first guess. The final values come from the threshold sweep in the experiments (docs/risk-model.md).
    'thresholds': {'MEDIUM': 0.30, 'HIGH': 0.55, 'CRITICAL': 0.80},
    # Session risk with memory: R_t = max(r_t, R_prev * 0.5 ^ (minutes since R_prev / halfLifeMinutes)).
    # memory: false gives the memoryless model (R_t = r_t), which we compare against.
    'memory': True,
    'halfLifeMinutes': 10,
    # Admin resources are stricter: the level goes up by this many steps before the response is chosen
    'adminLevelBump': 1,
    # A step-up that isn't passed within this time counts as failed (F9)
    'stepUpTimeoutMinutes': 5,
    # The token's acr values that mean MFA was used in the login
    'mfaAcrValues': ['2'],
    # How long risk events are kept in data/risk_events.jsonl (privacy)
    'retentionDays': 30,
    # A user needs this many allowed requests before their own usual behaviour is used (cold start)
    'minHistory': 20,

    'accessFrequency': {
        'windowMinutes': 5,
        'minBaseline': 10,    # requests per window. A user's usual rate is never taken as lower than this
        'capRatio': 4,        # this many times the usual rate (or more) scores 1
    },
    'resourceSequence': {
        'smoothing': 1,       # added to every transition count, so a move never seen before isn't "impossible"
        'adminJump': 0.3,     # added when a user who rarely uses admin resources asks for one
        'rareAdminShare': 0.1,
        'perDenial': 0.25,    # added for each request the role table (P2) denied in the window
        'denialWindowMinutes': 10,
    },
    'sessionDuration': {
        'usualMinutes': 60,   # used until the user has a usual session length of their own
        'capMultiple': 4,     # this many times the usual length (or more) scores 1
    },
    'authFailures': {
        'windowMinutes': 10,
        'cap': 5,             # this many failed logins (or more) score 1
    },
    'timeOfDay': {
        'bandHours': 3,       # the hour of the request, and one hour on each side
        'normalShare': 0.05,  # a band with at least this share of the user's requests is normal
        'nightScore': 0.7,    # used for users without enough history: inside the night window
    },
    'deviceFamiliarity': {
        'newDevice': 0.6,
        'changedInSession': 1.0,
    },
    'networkChange': {
        'changed': 0.7,       # the IP or location is different from the start of the session
        'mediumRiskLocation': 0.5,
        'highRiskLocation': 1.0,
    },
    'identityAssurance': {
        'passwordOnly': 0.5,
        'unverifiedEmail': 0.2,
    },
    'mfaReaction': {
        'cap': 3,             # this many failed step-ups (or more) score 1
    },
    # Strong single signals that can't be averaged away: if the feature's score is at least
    # atLeast, the event risk is at least the threshold of the given level
    'floors': [
        {'feature': 'authFailures', 'atLeast': 1.0, 'level': 'HIGH'},
        {'feature': 'mfaReaction', 'atLeast': 1.0, 'level': 'HIGH'},
        {'feature': 'networkChange', 'atLeast': 1.0, 'level': 'HIGH'},
        {'feature': 'resourceSequence', 'atLeast': 1.0, 'level': 'MEDIUM'},
        {'feature': 'deviceFamiliarity', 'atLeast': 1.0, 'level': 'MEDIUM'},
        {'feature': 'accessFrequency', 'atLeast': 1.0, 'level': 'MEDIUM'},
    ],
}


def number(value, default, minimum=None):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if result != result:  # NaN
        return default
    if minimum is not None and result < minimum:
        return default
    return result


def merge_numbers(defaults, configured, minimum=0.0):
    # A copy of `defaults`, with each number replaced by the configured one if that is valid
    configured = configured if isinstance(configured, dict) else {}
    return {key: number(configured.get(key, default), default, minimum) for key, default in defaults.items()}


def risk_settings(config):
    # The settings for the risk model, from the riskModel section of the configuration
    configured = (config or {}).get('riskModel') or {}
    if not isinstance(configured, dict):
        configured = {}
    defaults = DEFAULT_RISK_MODEL
    settings = copy.deepcopy(defaults)

    weights = merge_numbers(defaults['weights'], configured.get('weights'))
    settings['weights'] = weights if sum(weights.values()) > 0 else dict(defaults['weights'])

    thresholds = merge_numbers(defaults['thresholds'], configured.get('thresholds'))
    ordered = 0 < thresholds['MEDIUM'] < thresholds['HIGH'] < thresholds['CRITICAL'] <= 1
    settings['thresholds'] = thresholds if ordered else dict(defaults['thresholds'])

    for key in ('halfLifeMinutes', 'stepUpTimeoutMinutes', 'retentionDays', 'minHistory', 'adminLevelBump'):
        settings[key] = number(configured.get(key, defaults[key]), defaults[key], minimum=0)
    if settings['halfLifeMinutes'] <= 0:
        settings['halfLifeMinutes'] = defaults['halfLifeMinutes']
    settings['adminLevelBump'] = int(settings['adminLevelBump'])
    settings['minHistory'] = int(settings['minHistory'])
    settings['memory'] = configured.get('memory', defaults['memory']) is not False

    acr_values = configured.get('mfaAcrValues', defaults['mfaAcrValues'])
    if isinstance(acr_values, (list, tuple)):
        settings['mfaAcrValues'] = [str(value) for value in acr_values]

    for feature in FEATURES:
        if isinstance(defaults.get(feature), dict):
            settings[feature] = merge_numbers(defaults[feature], configured.get(feature))

    floors = configured.get('floors', defaults['floors'])
    if isinstance(floors, list):
        settings['floors'] = [floor for floor in floors if isinstance(floor, dict)
                              and floor.get('feature') in FEATURES and floor.get('level') in LEVELS[1:]
                              and number(floor.get('atLeast'), None) is not None]
    return settings
