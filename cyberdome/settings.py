'''

Settings and secrets for the Web UI, read from environment variables.

A .env file in the repo root is read first, if it exists (copy .env.example to
start). Variables already set in the environment win over the file.

Secrets have no default here. If one is missing, require() stops the Web UI
with a message that names it.

'''
import os

from .data_paths import REPO_ROOT

ENV_FILE = os.path.join(REPO_ROOT, '.env')


def load_env_file(path):
    # Minimal .env reader: KEY=VALUE lines, # comments, optional quotes around the value
    if not os.path.exists(path):
        return
    with open(path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            os.environ.setdefault(key.strip(), value)


def require(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is not set. Add it to {ENV_FILE} (see .env.example) or set it in the environment.")
    return value


load_env_file(ENV_FILE)

# Keycloak: where it runs, and the confidential client the Web UI logs in with
KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080/auth')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'myrealm')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'ZeroTrustPlatform')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')

# Keycloak admin login, used to read users, roles and login events
KEYCLOAK_ADMIN_USERNAME = os.getenv('KEYCLOAK_ADMIN_USERNAME', 'admin')
KEYCLOAK_ADMIN_PASSWORD = os.getenv('KEYCLOAK_ADMIN_PASSWORD')
# admin-cli is a public client, so this is usually left empty
KEYCLOAK_ADMIN_CLIENT_SECRET = os.getenv('KEYCLOAK_ADMIN_CLIENT_SECRET') or None

# Flask signs the session cookie with this. Keep it the same across restarts.
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')

# Optional: Gmail account that emails secret shares to PAM approvers
PAM_EMAIL_SENDER = os.getenv('PAM_EMAIL_SENDER')
PAM_EMAIL_PASSWORD = os.getenv('PAM_EMAIL_PASSWORD')
