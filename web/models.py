'''

Database tables for privileged access management (PAM), stored in data/privileged_access.db.

'''
from datetime import datetime

from extensions import db


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
