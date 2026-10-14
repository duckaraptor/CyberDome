'''

Locations of the files the Web UI and the engines share.
Paths are built from this file's location, so they work no matter which
folder a process is started from.

'''
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_UI_DIR = os.path.join(REPO_ROOT, 'web')

# Runtime data written while the app and engines run (git-ignored)
DATA_DIR = os.path.join(REPO_ROOT, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# One JSON object per line, only appended (see cyberdome/jsonl.py and docs/audit-log.md).
# The older access_requests.json and access_decision.json are no longer written.
ACCESS_REQUESTS_FILE = os.path.join(DATA_DIR, 'access_requests.jsonl')
AUDIT_LOG_FILE = os.path.join(DATA_DIR, 'audit.log')
KEYCLOAK_AUDIT_STATE_FILE = os.path.join(DATA_DIR, 'keycloak_audit_state.json')
AUTH_DATA_FILE = os.path.join(DATA_DIR, 'auth_data.json')
EVENTS_FILE = os.path.join(DATA_DIR, 'events.json')
USER_DATA_FILE = os.path.join(DATA_DIR, 'user_data.json')
PAM_DB_FILE = os.path.join(DATA_DIR, 'privileged_access.db')
KNOWN_DEVICES_FILE = os.path.join(DATA_DIR, 'known_devices.json')

# Configuration, edited by hand or from the policy page
POLICY_CONFIG_FILE = os.path.join(REPO_ROOT, 'policyConfiguration.yml')

# Demo data shown on the protected resource pages
TRANSACTIONS_FILE = os.path.join(WEB_UI_DIR, 'mobile_money_transactions.json')
TOKENS_FILE = os.path.join(WEB_UI_DIR, 'tokens.json')
