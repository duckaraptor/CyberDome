'''

Keycloak URLs for the Web UI. The values themselves (server, realm, client ID and
secret) come from cyberdome/settings.py, which reads them from the environment.

'''
from cyberdome.settings import (KEYCLOAK_ADMIN_CLIENT_SECRET, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET,
                                KEYCLOAK_REALM, KEYCLOAK_SERVER_URL)

ISSUER_URL = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}"
SERVER_URL = f"{ISSUER_URL}/.well-known/openid-configuration"
API_BASE_URL = f"{ISSUER_URL}/protocol/openid-connect"
AUTHORIZATION_URL = f"{API_BASE_URL}/auth"
REGISTRATION_URL = f"{API_BASE_URL}/registrations"
TOKEN_URL = f"{API_BASE_URL}/token"
USERINFO_URL = f"{API_BASE_URL}/userinfo"
INTROSPECTION_URL = f"{API_BASE_URL}/token/introspect"
REVOCATION_URL = f"{API_BASE_URL}/logout"
