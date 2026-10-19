'''

The role-to-resource table: which roles may access which protected resource,
and which resources are administrative. The table is the "resources" section of
policyConfiguration.yml, so authorization is driven by configuration, not code.

The Web UI uses these rules to enforce access (web/authz.py). The Policy Engine
will use the same table for its policies.

'''
from .config import load_policy_configuration


def load_resources():
    # Read on every call, so changes to policyConfiguration.yml apply straight away
    return load_policy_configuration().get('resources') or {}


def get_resource(resource):
    # The resource's entry in the table, or None if it isn't a known protected resource
    return load_resources().get(resource)


def allowed_roles(resource):
    entry = get_resource(resource) or {}
    return list(entry.get('allowedRoles') or [])


def is_role_allowed(user_roles, resource):
    # Allowed if any of the user's roles is in the resource's list.
    # Unknown resources and users without roles are denied.
    allowed = set(allowed_roles(resource))
    return bool(allowed & set(user_roles or []))


def may_write(user_roles, resource):
    # Changing the resource (an HTTP POST) needs a role in its writeRoles. Without writeRoles, nobody may.
    entry = get_resource(resource) or {}
    return bool(set(entry.get('writeRoles') or []) & set(user_roles or []))


def is_admin_resource(resource):
    entry = get_resource(resource) or {}
    return bool(entry.get('adminResource'))
