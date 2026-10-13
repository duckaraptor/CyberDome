'''

Zero trust access requests: the resource selection page collects the request
context, and /receive-access-request sends the request through the decision
engines (Access Proxy, Trust Engine, Policy Engine) and returns their verdict.

'''
import json
import os
import re
import uuid
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, session

from cyberdome.data_paths import ACCESS_REQUESTS_FILE
from cyberdome.networking import WebUINode
from extensions import oidc
from keycloak_functions import get_location, get_mac_details, get_public_ip

bp = Blueprint('access', __name__)

# Seconds to wait for the Policy Engine's verdict before denying access
ACCESS_DECISION_TIMEOUT = 10


#route to receive an access request and forward it to the AP
@bp.route('/receive-access-request', methods = ['POST'])
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

@bp.route('/resource-selection')
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
