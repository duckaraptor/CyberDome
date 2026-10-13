'''

The protected resources: mobile money transactions (Resource 1) and fintech
access tokens (Resource 2).

'''
import json

from flask import Blueprint, render_template

from authz import require_role
from cyberdome.data_paths import TOKENS_FILE, TRANSACTIONS_FILE

bp = Blueprint('resources', __name__)


@bp.route('/resource-1')
@require_role('resource_1')
def display_transactions():
    # Load transactions from the JSON file
    with open(TRANSACTIONS_FILE, 'r') as file:
        transactions = json.load(file)

    return render_template('transaction_simulation.html', transactions=transactions)

@bp.route('/resource-2')
@require_role('resource_2')
def display_tokens():
    # Load tokens from JSON file
    with open(TOKENS_FILE, 'r') as file:
        tokens = json.load(file)

    return render_template('fintech_access_tokens.html', tokens=tokens)
