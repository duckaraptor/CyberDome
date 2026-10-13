'''

Logging and monitoring: lists the access requests the Web UI has received.

'''
import json
import os

from flask import Blueprint, render_template

from authz import require_role
from cyberdome.data_paths import ACCESS_REQUESTS_FILE

bp = Blueprint('monitoring', __name__)


@bp.route('/logging')
@require_role('logging')
def access_requests():
    file_path = ACCESS_REQUESTS_FILE
    access_requests_data = []

    # The file is created by the first access request
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            access_requests_data = json.load(file)

    return render_template('logging_and_monitoring.html', access_requests=access_requests_data)
