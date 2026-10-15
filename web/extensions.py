'''

Shared objects for the Web UI: login (Flask-OIDC), the PAM database, and the
Keycloak clients.

They are created here without an app and connected to it in app.py (init_app),
so every blueprint in routes/ can import them without importing app.py.

'''
from flask_oidc import OpenIDConnect
from flask_sqlalchemy import SQLAlchemy
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakOpenIDConnection

from cyberdome.settings import KEYCLOAK_ADMIN_USERNAME, require
from keycloak_config import (KEYCLOAK_ADMIN_CLIENT_SECRET, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET,
                             KEYCLOAK_REALM, KEYCLOAK_SERVER_URL)

oidc = OpenIDConnect()

db = SQLAlchemy()

# Keycloak admin API, used to read users, roles and login events
keycloak_connection = KeycloakOpenIDConnection(
                        server_url=f"{KEYCLOAK_SERVER_URL}/",
                        username=KEYCLOAK_ADMIN_USERNAME,
                        password=require('KEYCLOAK_ADMIN_PASSWORD'),
                        realm_name=KEYCLOAK_REALM,
                        user_realm_name="master",
                        client_id="admin-cli",
                        client_secret_key=KEYCLOAK_ADMIN_CLIENT_SECRET,
                        verify=False)

keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

# Configure client using the python-keycloak library
keycloak_openid = KeycloakOpenID(server_url=f"{KEYCLOAK_SERVER_URL}/",
                                 client_id=KEYCLOAK_CLIENT_ID,
                                 realm_name=KEYCLOAK_REALM,
                                 client_secret_key=KEYCLOAK_CLIENT_SECRET)
