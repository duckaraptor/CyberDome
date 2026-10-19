'''

Reads policyConfiguration.yml, the settings shared by the Trust Engine, the
Policy Engine and the Web UI.

'''
import yaml

from .data_paths import POLICY_CONFIG_FILE


def load_policy_configuration():
    # Read the file on every call, so changes from the policy page apply straight away
    with open(POLICY_CONFIG_FILE, 'r') as file:
        return yaml.safe_load(file) or {}
