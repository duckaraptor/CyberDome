'''

The resource selection page. Each resource page checks access itself: opening it sends
the request through the decision engines (Access Proxy, Trust Engine, Policy Engine),
see protected_resource in authz.py. So this page only links to the resources.

'''
from flask import Blueprint, render_template

from authz import require_authentication

bp = Blueprint('access', __name__)


@bp.route('/resource-selection')
@require_authentication
def resource_selection():
    return render_template('resource_selection.html')
