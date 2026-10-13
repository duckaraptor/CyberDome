'''

Privileged access management (PAM): a user requests privileged access, the
resource's secret is split into shares for the selected approvers, and the
secret is rebuilt once enough approvers have approved.

'''
import math
from datetime import datetime, timedelta

import requests
from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from extensions import db, keycloak_admin, keycloak_openid, oidc
from keycloak_config import KEYCLOAK_CLIENT_ID
from keycloak_functions import extract_user_role, get_client_role_members_emails, get_user_id_by_email
from models import AccessRequest, Approver
from pam import PAM
from pam_mail import send_email_to_approver

bp = Blueprint('privileged_access', __name__)

# The current PAM request's secret and approval threshold, set by /privilegedAccess
RESOURCE_SECRET_KEY =''

THRESHOLD = None


@bp.route('/privilegedAccess', methods=['GET', 'POST'])
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

            return redirect(url_for('privileged_access.approval_status'))
        else:
            return "Invalid access duration. Please enter a value between 1 and 100 minutes."

    return render_template('privileged_access_management.html',email_addresses=email_addresses)


# Known issue: require_login is above route, so Flask registers this page without the login check.
# Kept as it was during the restructure. To be fixed with the role checks (assignment section 3.1).
@oidc.require_login
@bp.route('/testing')
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
        return redirect(url_for('auth.revokeToken'))

    access_requests = AccessRequest.query.order_by(AccessRequest.id.desc()).limit(1).all()  # Adjust 'limit' as needed

    return render_template('approver_page.html', access_requests=access_requests, username=username, email=email, user_id=user_id, user_role=user_role)

@bp.route('/approve_request', methods=['POST'])
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

@bp.route('/approval_status', methods=['GET','POST'])
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


@bp.route('/success', methods = ['GET'])
def approval_success():
    return render_template('success.html')

@bp.route('/enterSecretKey', methods=['GET', 'POST'])
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

@bp.route('/hidden_resource', methods=['POST'])
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

@bp.route('/protected_page')
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

# Known issue: same decorator order as /testing, so this page has no login check either.
@oidc.require_login
@bp.route('/viewAccessRequests')
def view_access_requests():
    access_requests = AccessRequest.query.all()
    approvers = Approver.query.all()
    requestor_id = session['oidc_auth_profile'].get('sub')
    print(requestor_id)

    return render_template('view_access_requests.html', access_requests=access_requests, approvers = approvers)
