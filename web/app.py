'''

The CyberDome Web UI. This file creates the Flask app, loads its settings,
connects the shared objects from extensions.py and registers the pages in routes/.

'''
import logging
import os
import sys

# Make the repo root importable (for the shared cyberdome package), wherever app.py is started from
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask

from cyberdome.data_paths import PAM_DB_FILE
from cyberdome.settings import require
from extensions import db, oidc
from keycloak_config import (AUTHORIZATION_URL, INTROSPECTION_URL, ISSUER_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_REALM,
                             TOKEN_URL, USERINFO_URL)
import models  # registers the PAM database tables with db
from proxy_client import stop_node
from request_context import load_device_id, save_device_cookie
from routes import access, auth, monitoring, policy_config, privileged_access, resources

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

'''
This section below contains the configuration of the flask OIDC and the keycloak OIDC
'''

app.config['OIDC_SESSION_TYPE'] = 'null'

# Flask-OIDC client settings (previously client_secrets.json), built from cyberdome/settings.py
OIDC_CLIENT_SETTINGS = {
    'web': {
        'issuer': ISSUER_URL,
        'auth_uri': AUTHORIZATION_URL,
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': require('KEYCLOAK_CLIENT_SECRET'),
        'redirect_uris': ['http://localhost:5000/login'],
        'userinfo_uri': USERINFO_URL,
        'token_uri': TOKEN_URL,
        'token_introspection_uri': INTROSPECTION_URL,
    }
}


app.config.update({
    'SECRET_KEY': require('FLASK_SECRET_KEY'),
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': OIDC_CLIENT_SETTINGS,
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': KEYCLOAK_REALM,
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_TOKEN_TYPE_HINT': 'access_token',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

oidc.init_app(app)

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{PAM_DB_FILE}'
db.init_app(app)

# Every browser gets a device ID cookie on its first visit (see request_context.py)
app.before_request(load_device_id)
app.after_request(save_device_cookie)

# The pages, one blueprint per area
for blueprint_module in (auth, access, resources, policy_config, monitoring, privileged_access):
    app.register_blueprint(blueprint_module.bp)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    try:
        app.run(debug=True)
    finally:
        # Stop the connection to the decision engines, so Ctrl+C exits cleanly
        stop_node()
