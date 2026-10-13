'''

The Policy Engine's rules: turn a user's trust score into a verdict.
A verdict is 1 (allow) or 0 (deny). Thresholds come from policyConfiguration.yml.

'''
import yaml

from .data_paths import POLICY_CONFIG_FILE


def load_policy_configuration():
    # Read the file on every call, so changes from the policy page apply straight away
    with open(POLICY_CONFIG_FILE, 'r') as file:
        return yaml.safe_load(file)


def make_access_decision(user_role, user_trust_score, sign_in_risk, policy_configuration=None):
    # Tests can pass a configuration directly instead of reading the file
    if policy_configuration is None:
        policy_configuration = load_policy_configuration()

    # Access specific values from the policy configuration
    admin_threshold = float(policy_configuration['adminThreshold'])
    approver_threshold = float(policy_configuration['approverThreshold'])
    security_viewer_threshold = float(policy_configuration['securityViewerThreshold'])
    sign_in_risk_threshold = float(policy_configuration['signInRiskThreshold'])

    # Initialize verdict
    verdict = 1

    # Determine access decision based on user trust score and role-specific thresholds
    if user_role == 'Approver' and user_trust_score < approver_threshold:
        verdict = 0
    elif user_role == 'Security Viewer' and user_trust_score < security_viewer_threshold:
        verdict = 0
    elif user_role == 'Policy Administrator' and user_trust_score < admin_threshold:
        verdict = 0

    # Determine access decision based on sign-in risk threshold
    if sign_in_risk < sign_in_risk_threshold:
        verdict = 0

    return verdict
