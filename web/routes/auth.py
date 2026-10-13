'''

Login, logout (token revocation) and the home page. The home page also
collects the user's identity and Keycloak login events into data/.

'''
import json
import os

from flask import Blueprint, make_response, redirect, render_template, session, url_for
from keycloak import KeycloakAuthenticationError

from cyberdome.data_paths import EVENTS_FILE, USER_DATA_FILE
from cyberdome.trust_signals import load_events_data, process_events, store_keycloak_events
from extensions import keycloak_admin, keycloak_openid, oidc
from keycloak_config import KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, REVOCATION_URL
from keycloak_functions import extract_user_role, revoke_token, token_is_valid

bp = Blueprint('auth', __name__)


#Main route
@bp.route('/')
@oidc.require_login
def index():
    if oidc.user_loggedin and token_is_valid(oidc,keycloak_openid):
        return redirect(url_for('auth.home'))
    else:
        return render_template('index.html')


def normalize_keycloak_user(user, current_user_id, current_user_role):
    return {
        'user_id': user.get('id'),
        'username': user.get('username'),
        'email': user.get('email'),
        'created_timestamp': user.get('createdTimestamp'),
        'email_verified': user.get('emailVerified', False),
        'totp_enabled': user.get('totp', False),
        'user_role': current_user_role if user.get('id') == current_user_id else None
    }

#create a route to revoke an access token and redirect to index.html page for the user to authenticate
@bp.route('/revokeToken')
@oidc.require_login
def revokeToken():
    refresh_token = oidc.get_refresh_token()
    if revoke_token(KEYCLOAK_CLIENT_ID,KEYCLOAK_CLIENT_SECRET,refresh_token, REVOCATION_URL):
        return render_template('index.html')
    else:
        return "<h1>Failed to revoke the access token!<h1>"

#Login Route
@bp.route('/login')
@oidc.require_login
def login():
    token = oidc.get_access_token()
    response = make_response(redirect(url_for('auth.home')))
    if token_is_valid(oidc,keycloak_openid):
        response.set_cookie('access_token', token['access_token'])
        session['access_token'] = token['access_token']
        return response
    else:
        return render_template('index.html')


# The home route where all the available services are located
@bp.route('/home')
def home():
    try:
        if oidc.user_loggedin:

            if token_is_valid(oidc,keycloak_openid):
                if 'oidc_auth_profile' in session:
                    auth_profile = session['oidc_auth_profile']
                    username = auth_profile.get('name')
                    email = auth_profile.get('email')
                    user_id = auth_profile.get('sub')
                    #get the user role
                    user_roles = extract_user_role(oidc,keycloak_openid)
                    user_role = user_roles[0] if user_roles else None

                    #storing keycloak events
                    store_keycloak_events(keycloak_admin)

                    events_file_path = EVENTS_FILE

                    events_data = load_events_data(events_file_path)
                    # Process event data to yield the auth_data
                    if events_data:
                        process_events(events_data)
                    else:
                        print("Failed to load events data.")

                    all_users = keycloak_admin.get_users()

                    # Define the path to the JSON file
                    file_path = USER_DATA_FILE

                    # Extracting user data
                    extracted_data = [
                        normalize_keycloak_user(user, user_id, user_role)
                        for user in all_users
                    ]

                    # Load existing data from the file if it exists
                    existing_data = []
                    if os.path.exists(file_path):
                        with open(file_path, 'r') as json_file:
                            existing_data = json.load(json_file)

                    # Update existing records without overwriting existing roles
                    for existing_user in existing_data:
                        for new_user in extracted_data:
                            if existing_user['user_id'] == new_user['user_id'] and new_user['user_role'] is not None:
                                existing_user['user_role'] = new_user['user_role']
                                break

                    # Combine existing and new data without duplicates
                    user_ids_in_file = {user['user_id'] for user in existing_data}
                    for new_user in extracted_data:
                        if new_user['user_id'] not in user_ids_in_file:
                            existing_data.append(new_user)

                    # Store the updated and new data in the JSON file
                    with open(file_path, 'w') as json_file:
                        json.dump(existing_data, json_file, indent=4)

                    return render_template('home.html', username=username, email=email, user_id=user_id, user_role=user_role)
                else:
                    return "<h1>NOT AUTHORIZED!</h1>"
            else:
                return "<h1>UNAUTHORIZED [INVALID ACCESS TOKEN]!!!</h1>"
        else:
            return redirect(url_for('auth.login'))
    except KeycloakAuthenticationError as e:
        print(f"KeycloakAuthenticationError: {e}")
        return redirect(url_for('auth.index'))
