import json
import os
import sys
import time

# Make the repo root importable (for the shared cyberdome package), wherever app.py is started from
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, g, render_template, request, jsonify, session, url_for, redirect, make_response
import logging
import math
from flask_oidc import OpenIDConnect
from keycloak import KeycloakAuthenticationError, KeycloakOpenID
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import requests
import yaml
from cyberdome.networking import WebUINode
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
import re, uuid
from cyberdome.settings import KEYCLOAK_ADMIN_USERNAME, require
from keycloak_config import (INTROSPECTION_URL, ISSUER_URL, KEYCLOAK_ADMIN_CLIENT_SECRET, KEYCLOAK_CLIENT_ID,
                             KEYCLOAK_CLIENT_SECRET, KEYCLOAK_REALM, KEYCLOAK_SERVER_URL, AUTHORIZATION_URL,
                             REVOCATION_URL, TOKEN_URL, USERINFO_URL)
from pam import PAM
from keycloak_functions import (extract_user_role, get_client_role_members_emails, get_location, get_mac_details,
                                get_public_ip, get_user_id_by_email, revoke_token, token_is_valid)
from pam_mail import send_email_to_approver
from cyberdome.trust_signals import store_keycloak_events,load_events_data,process_events
from cyberdome.data_paths import ACCESS_REQUESTS_FILE, EVENTS_FILE, PAM_DB_FILE, POLICY_CONFIG_FILE, TOKENS_FILE, TRANSACTIONS_FILE, USER_DATA_FILE

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

oidc = OpenIDConnect(app)

# Configure client using the python-kcloak library
keycloak_openid = KeycloakOpenID(server_url=f"{KEYCLOAK_SERVER_URL}/",
                                 client_id=KEYCLOAK_CLIENT_ID,
                                 realm_name=KEYCLOAK_REALM,
                                 client_secret_key=KEYCLOAK_CLIENT_SECRET)

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{PAM_DB_FILE}'
db = SQLAlchemy(app)

# Define the database model for access requests
class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    resource_name = db.Column(db.String(100), nullable=False)
    reason_for_access = db.Column(db.String(250), nullable=False)
    access_duration = db.Column(db.Integer, nullable=False)
    requestor_id = db.Column(db.String(100), nullable=False)
    requestor_username = db.Column(db.String(100), nullable=False)
    time_of_request = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    requestStatus = db.Column(db.String(20), default="pending")


# Create a new database model for approvers
class Approver(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    approverID = db.Column(db.String(100), nullable=False)
    approverEmail = db.Column(db.String(100), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('access_request.id'), nullable=False)
    approver_secret_share = db.Column(db.String(750))
    approver_action = db.Column(db.String(20))


RESOURCE_SECRET_KEY =''

THRESHOLD = None

'''

The section below contains the system views. They contain the various routes in the web UI and the functionalities
that can be performed at each view

'''
#Main route
@app.route('/')
@oidc.require_login
def index():
    if oidc.user_loggedin and token_is_valid(oidc,keycloak_openid):
        return redirect(url_for('home'))
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
@app.route('/revokeToken')
@oidc.require_login
def revokeToken():
    refresh_token = oidc.get_refresh_token()
    if revoke_token(KEYCLOAK_CLIENT_ID,KEYCLOAK_CLIENT_SECRET,refresh_token, REVOCATION_URL):
        return render_template('index.html')
    else:
        return "<h1>Failed to revoke the access token!<h1>"
    
#Login Route 
@app.route('/login')
@oidc.require_login
def login():
    token = oidc.get_access_token()
    response = make_response(redirect(url_for('home')))
    if token_is_valid(oidc,keycloak_openid):
        response.set_cookie('access_token', token['access_token'])
        session['access_token'] = token['access_token']  
        return response
    else:
        return render_template('index.html')
    

# The home route where all the available services are located
@app.route('/home')
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
            return redirect(url_for('login'))
    except KeycloakAuthenticationError as e:
        print(f"KeycloakAuthenticationError: {e}")
        return redirect(url_for('index'))


# Seconds to wait for the Policy Engine's verdict before denying access
ACCESS_DECISION_TIMEOUT = 10

#route to receive an access request and forward it to the AP
@app.route('/receive-access-request', methods = ['POST'])
def receive_and_process_access_request():
    #receive the data from the front end when the resource option is clicked. 
    data = request.json
    #Implement logic for adding the access request in the json file
    file_path = ACCESS_REQUESTS_FILE
    existing_data = []
    new_id = 1

    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                existing_data = json.load(file)
                if existing_data:
                    last_entry = existing_data[-1]
                    new_id = last_entry['ID'] + 1

    except(json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while loading JSON data: {e}")

    access_request = {
        'ID': new_id,
        'user_id': data.pop('userId'),
        'intent': data['intent'],
        'resource_requested': data['resource'],
        'access_request_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'public_ip_address': data['public_ip'],
        'location': data['location'],
        'device_type': data['deviceType'],
        'browser': data['userAgent'],
        'device_mac': data['device_mac'],
        'device_vendor': data['device_vendor'],
        'device_OS': data['operatingSystem']
    }

    existing_data.append(access_request)

    try:
        with open(file_path, 'w') as file:
            json.dump(existing_data, file, indent=4)

    except IOError as e:
        print(f"Error  occured while loading the json data {e}")
    
    #send the access request data to the AP in the peer to peer network of nodes

    #first create the Web UI's node (node 4)
    node4 = WebUINode("127.0.0.1",8004)
    node4.start()
    try:
        node4.connect_with_node('127.0.0.1',8001) #connect with the access proxy
        node4.connect_with_node('127.0.0.1',8003) # connect with the policy engine
        node4.send_message_to_node('1',access_request)  #send access request to access proxy

        # Wait for the verdict for this request, not whatever was decided last
        access_decision = node4.wait_for_access_decision(access_request['ID'], ACCESS_DECISION_TIMEOUT)
    finally:
        node4.stop()

    print(access_decision)

    if access_decision is None:
        # Fail closed: no verdict means no access
        print(f"No verdict for access request {access_request['ID']} within {ACCESS_DECISION_TIMEOUT}s")
        return jsonify({'verdict': 0, 'error': 'No access decision received'}), 504

    policy_engine_verdict = access_decision.get('access_decision')

    print(f"Policy Engine Verdict: {policy_engine_verdict}")

    # Communicate to the frontend that the access request has been verified
    response_data = {'verdict': policy_engine_verdict}
    return jsonify(response_data)

@app.route('/resource-selection')
@oidc.require_login
def resource_selection():
    if 'oidc_auth_profile' in session:
        auth_profile = session['oidc_auth_profile']
        user_id = auth_profile.get('sub')

        #get location, public ip, device mac and device vendor

        location_info = get_location(ip_address=get_public_ip())
        ip = location_info.get('ip')
        city = location_info.get('city')
        country = location_info.get('country')
        location = f"{city}/{country}"

        # Get the device mac and device vendor
        device_mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        device_vendor = get_mac_details(device_mac)

    return render_template('resource_selection.html',user_id=user_id,location=location,public_ip=ip,device_mac=device_mac,device_vendor=device_vendor)

# Function to create or update policyConfiguration.yml file
def update_policy_configurations(data):
    # Get the parent directory path
    file_path = POLICY_CONFIG_FILE
    
    try:
        with open(file_path, 'r') as file:
            existing_data = yaml.safe_load(file)
    except FileNotFoundError:
        existing_data = {}

    existing_data.update(data)

    with open(file_path, 'w') as file:
        yaml.dump(existing_data, file)

@app.route('/receivePolicyConfigurations', methods=['POST'])
def receive_policy_configurations():
    if request.method == 'POST':
        data = request.json  # Get JSON data from the POST request
        print(data)

        #update coinfigurations in the Policy YML file
        update_policy_configurations(data)
        print("Received Policy Configurations:")
        for key, value in data.items():
            print(f"{key}: {value}")
        return 'Received Policy Configurations successfully!', 200
    else:
        return 'Invalid request method', 405

@app.route('/resource-1')
def display_transactions():
    # Load transactions from the JSON file
    with open(TRANSACTIONS_FILE, 'r') as file:
        transactions = json.load(file)
    
    return render_template('transaction_simulation.html', transactions=transactions)

@app.route('/resource-2')
def display_tokens():
    # Load tokens from JSON file
    with open(TOKENS_FILE, 'r') as file:
        tokens = json.load(file)
    
    return render_template('fintech_access_tokens.html', tokens=tokens)

@app.route('/logging')
def access_requests():
    file_path = ACCESS_REQUESTS_FILE
    access_requests_data = []

    # The file is created by the first access request
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            access_requests_data = json.load(file)

    return render_template('logging_and_monitoring.html', access_requests=access_requests_data)



@app.route('/configurePolicies', methods=['POST','GET'])
def configure_policies():
    # Retrieve the access duration from the database for the latest approved request ID

    latest_access_request = AccessRequest.query.order_by(AccessRequest.id.desc()).limit(1).all()  # Adjust 'limit' as needed

    if latest_access_request:

        access_duration = 0

        for request in latest_access_request:
            access_duration = request.access_duration

            # Get the current time
            current_time = datetime.now()
            
            # Calculate the expiration time by adding access duration to the current time
            expiration_time = current_time + timedelta(minutes=access_duration)

            return render_template('policy_configuration.html', expiration_time=expiration_time)

@app.route('/privilegedAccess', methods=['GET', 'POST'])
def privilegedAccess():
    #dynamically query the keycloak API for the list of approvers to display for the requestor
    client_id = keycloak_admin.get_client_id(KEYCLOAK_CLIENT_ID)
    role_name = "Approver"
    email_addresses = get_client_role_members_emails(keycloak_admin,client_id, role_name)

    num_shares = len(email_addresses) #equal to the number of approvers 

    global THRESHOLD

    THRESHOLD = math.floor(num_shares * 0.8) #define at least 80 % of threshold to be met before secret key reconstruction occurs

    secret_key_identifier = PAM.generate_secret_message(4)

    global RESOURCE_SECRET_KEY

    RESOURCE_SECRET_KEY = PAM.generate_secret_message(45)
    
    secret_shares_list = PAM.generate_secret_shares(THRESHOLD,num_shares,RESOURCE_SECRET_KEY,secret_key_identifier)

    if email_addresses is None:
        email_addresses = []

    if request.method == 'POST':
        # Get form data
        resource_name = request.form['resource_name']
        reason_for_access = request.form['reason_for_access']
        access_duration = int(request.form['access_duration'])
        # Get the current user's ID and username from the session
        requestor_id = session['oidc_auth_profile'].get('sub')
        requestor_username = session['oidc_auth_profile'].get('preferred_username')
        # Capture the time of the request
        time_of_request = datetime.now()

        # Extract selected approvers in a list
        selected_approvers = request.form.getlist('approvers')

        # loop through the approvers and Send emails containing the approval details
        for index, approver in enumerate(selected_approvers):
            approver_secret_share = secret_shares_list[index] #obtain the share to send for this approver
            send_email_to_approver(approver,requestor_id,requestor_username,reason_for_access,access_duration,approver_secret_share)

        # Validate the access duration (between 1 and 100 minutes)
        if 1 <= access_duration <= 100:
            # Create a new access request and add it to the database

            new_request = AccessRequest(
                resource_name=resource_name,
                reason_for_access=reason_for_access,
                access_duration=access_duration,
                requestor_id=requestor_id,
                requestor_username=requestor_username,
                time_of_request=time_of_request,
                requestStatus='pending',  # Set the requestStatus to 'pending'
            )

            db.session.add(new_request)
            db.session.commit()

             # Insert approver details to the DB (secret share not to be inserted !!!)
            for approver_email in selected_approvers:
                approver = Approver(
                    approverID=get_user_id_by_email(keycloak_admin,approver_email),
                    approverEmail=approver_email,
                    request_id=new_request.id,
                )
                db.session.add(approver)
                db.session.commit()

            return redirect(url_for('approval_status'))
        else:
            return "Invalid access duration. Please enter a value between 1 and 100 minutes."

    return render_template('privileged_access_management.html',email_addresses=email_addresses)


@oidc.require_login
@app.route('/testing')
def testApproval():
    #extract the approver's details 
    if 'oidc_auth_profile' in session:
        auth_profile = session['oidc_auth_profile']
        username = auth_profile.get('name')
        email = auth_profile.get('email')
        user_id = auth_profile.get('sub')
        user_role = extract_user_role(oidc,keycloak_openid)[0]

    #check if the user is part of the approvers group
    if user_role != "Approver":
        return redirect(url_for('revokeToken'))

    access_requests = AccessRequest.query.order_by(AccessRequest.id.desc()).limit(1).all()  # Adjust 'limit' as needed

    return render_template('approver_page.html', access_requests=access_requests, username=username, email=email, user_id=user_id, user_role=user_role)

@app.route('/approve_request', methods=['POST'])
def approve_request():
    if request.method == 'POST':
        data = request.json

        # Extract details from the request
        action = data.get('action')
        approver_id = data.get('approverId')
        secret_share = data.get('secretShare') #retrieve the secret share for all the approvers for computation

        # Update the Approver record in the database
        approver = Approver.query.filter_by(approverID=approver_id).order_by(Approver.id.desc()).first()
        if approver:
            approver.approver_action = 'approved' if action == 'approve' else 'rejected'
            approver.approver_secret_share  = secret_share
            db.session.commit()

            print("request approved... waiting for processing")
            return 'Request Approved!'

    return 'Invalid Request'

@app.route('/approval_status', methods=['GET','POST'])
def approval_status():

    #check if there is a POST request
    if request.method == 'POST':
         data = request.json
         action = data.get('action')
        #get the latest request
         latest_request = AccessRequest.query.order_by(AccessRequest.id.desc()).first()
         if latest_request:
            latest_request_id = latest_request.id
            approvers_count = Approver.query.filter_by(request_id=latest_request_id).count()
            approved_approvers = Approver.query.filter_by(request_id=latest_request_id, approver_action='approved').count()
            approved_approver_shares = Approver.query.filter_by(request_id=latest_request_id, approver_action='approved').all()
            #check if the requests approved meets the minimum threshold
            if approved_approvers == THRESHOLD and action == 'reconstruct_secret':
                message = 'Threshold for Approval Met! Reconstructing key...'
                #reconstruct the secret key using the threshold value
                secret_shares = [approver.approver_secret_share for approver in approved_approver_shares]
                reconstructed_secret = str(PAM.reconstruct_secret_from_base64_shares(secret_shares))[2:-1]
                latest_request.requestStatus = 'approved'
                db.session.commit()
                return jsonify({'reconstructed_secret': reconstructed_secret})
            else:
                 return jsonify({'ERR_THRESH': 'Minimum Threshold for Secret Key reconstruction Not reached!'})

    latest_request = AccessRequest.query.order_by(AccessRequest.id.desc()).first()

    if latest_request:
        latest_request_id = latest_request.id

        approvers_count = Approver.query.filter_by(request_id=latest_request_id).count()
        approved_approvers = Approver.query.filter_by(request_id=latest_request_id, approver_action='approved').count()
        pending_approvers = approvers_count - approved_approvers

        approval_info = f'{approved_approvers}/{approvers_count} approvers approved, {pending_approvers} pending'

        APPROVAL_TIME = 2

        current_time =datetime.now()

        expiration_time = current_time + timedelta(minutes=APPROVAL_TIME)

        reconstructed_secret = None

        if pending_approvers == 0:
            message = 'All approvers have approved the request'
            # Retrieving secret shares for all approved approvers
            approved_approver_shares = Approver.query.filter_by(request_id=latest_request_id, approver_action='approved').all()
            secret_shares = [approver.approver_secret_share for approver in approved_approver_shares]

            # Reconstructing the secret key from secret shares
            reconstructed_secret = PAM.reconstruct_secret_from_base64_shares(secret_shares)
            latest_request.requestStatus = 'approved'
            db.session.commit() 
        else:
            message = ''

        return render_template('approval_status.html', approval_info=approval_info, message=message, reconstructed_secret=reconstructed_secret,threshold=THRESHOLD,expiration_time=expiration_time)

    return render_template('no_requests.html')  # Render a template if no requests exist


@app.route('/success', methods = ['GET'])
def approval_success():
    return render_template('success.html')

@app.route('/enterSecretKey', methods=['GET', 'POST'])
def process_secret_key():

    if request.method == 'POST':
        # Get the secret key entered by the user
        entered_secret_key = request.form.get('secret_key')

        if entered_secret_key:
            response = requests.post('http://127.0.0.1:5000/hidden_resource',data={'secret_key': entered_secret_key})

            if response.text == 'Valid':
                return redirect('/configurePolicies')
            else:
                return "INVALID SECRET KEY"
            
    return render_template('enter_secret_key.html')

@app.route('/hidden_resource', methods=['POST'])
def hidden_resource():
    entered_secret_key = request.form.get('secret_key')

    print (f"ENTERED SECRET MESSAGE: {entered_secret_key}")
    #extract the randomized secret key from the PAM endpoint

    secret_message = RESOURCE_SECRET_KEY # assign it to the reandomized secret generated at the PAM endpoint

    print(f"SECRET MESSAGE: {secret_message}")

    print(secret_message)
    if entered_secret_key == secret_message:
        return 'Valid'
    else:
        return 'Invalid'

@app.route('/protected_page')
def protected_page():
    # Retrieve the access duration from the database for the latest approved request ID

    latest_access_request = AccessRequest.query.order_by(AccessRequest.id.desc()).limit(1).all()  # Adjust 'limit' as needed

    if latest_access_request:

        access_duration = 0

        for request in latest_access_request:
            access_duration = request.access_duration

            # Get the current time
            current_time = datetime.now()
            
            # Calculate the expiration time by adding access duration to the current time
            expiration_time = current_time + timedelta(minutes=access_duration)

            return render_template('protected_page.html', expiration_time=expiration_time)

    else:
        print("No PAM Requests Found") 
        return "No REQUESTS FOUND!"

@oidc.require_login
@app.route('/viewAccessRequests')
def view_access_requests():
    access_requests = AccessRequest.query.all()
    approvers = Approver.query.all()
    requestor_id = session['oidc_auth_profile'].get('sub')
    print(requestor_id)

    return render_template('view_access_requests.html', access_requests=access_requests, approvers = approvers)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
