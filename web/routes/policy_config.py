'''

The policy configuration page, and the endpoint that saves its settings to
policyConfiguration.yml.

'''
from datetime import datetime, timedelta

import yaml
from flask import Blueprint, render_template, request

from authz import protected_resource
from cyberdome.data_paths import POLICY_CONFIG_FILE
from cyberdome.policy import load_policy_configuration
from cyberdome.trust_algorithm import FACTOR_LABELS, trust_weights
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
@protected_resource('policy_configuration')
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
@protected_resource('policy_configuration')
def configure_policies():
    # The countdown uses the access duration of the latest PAM request. Without one, the page shows without a countdown.
    latest_access_request = AccessRequest.query.order_by(AccessRequest.id.desc()).first()
    expiration_time = None
    if latest_access_request:
        expiration_time = datetime.now() + timedelta(minutes=latest_access_request.access_duration)

    # The fields show the saved settings, so saving doesn't reset anything to defaults
    config = load_policy_configuration()
    return render_template('policy_configuration.html', expiration_time=expiration_time, config=config,
                           weights=trust_weights(config), factor_labels=FACTOR_LABELS)
