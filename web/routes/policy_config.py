'''

The policy configuration page, and the endpoint that saves its settings to
policyConfiguration.yml.

'''
from datetime import datetime, timedelta

import yaml
from flask import Blueprint, render_template, request

from authz import require_role
from cyberdome.data_paths import POLICY_CONFIG_FILE
from models import AccessRequest

bp = Blueprint('policy_config', __name__)


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

@bp.route('/receivePolicyConfigurations', methods=['POST'])
@require_role('policy_configuration')
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


@bp.route('/configurePolicies', methods=['POST','GET'])
@require_role('policy_configuration')
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
