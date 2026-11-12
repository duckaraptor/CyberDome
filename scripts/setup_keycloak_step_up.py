'''

Sets up step-up authentication in Keycloak (Task 2, step 3): a browser login flow
with two levels of authentication.

    level 1  password             a normal login (acr 1)
    level 2  password, then OTP   a step-up (acr 2). The OTP is asked on every step-up.

Keycloak only imports infra/keycloak/myrealm-realm.json when the realm doesn't exist
yet. This script adds the same flow to a realm that already exists, through the admin
API. It reads the Keycloak address and admin login from .env (cyberdome/settings.py).

    python3 scripts/setup_keycloak_step_up.py              add the flow and use it for browser logins
    python3 scripts/setup_keycloak_step_up.py --recreate   delete our flow first and add it again
    python3 scripts/setup_keycloak_step_up.py --undo       go back to Keycloak's own browser flow
    python3 scripts/setup_keycloak_step_up.py --print-json the flow as realm JSON, for the realm file

Why the flow looks like this is explained in docs/step-up.md.

'''
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FLOW_ALIAS = 'browser step-up'
DEFAULT_BROWSER_FLOW = 'browser'

# The flow as a tree: (alias or authenticator, requirement, config, children).
# Children make it a subflow. Config is (alias, {key: value}).
FLOW = [
    ('auth-cookie', 'ALTERNATIVE', None, None),
    ('step-up forms', 'ALTERNATIVE', None, [
        ('step-up level 1', 'CONDITIONAL', None, [
            # Level 1 stays valid for 10 hours, Keycloak's default SSO session maximum
            ('conditional-level-of-authentication', 'REQUIRED',
             ('step-up level 1', {'loa-condition-level': '1', 'loa-max-age': '36000'}), None),
            ('auth-username-password-form', 'REQUIRED', None, None),
        ]),
        ('step-up level 2', 'CONDITIONAL', None, [
            # Max age 0: the OTP is asked again on every step-up, so each one gives a new auth_time
            ('conditional-level-of-authentication', 'REQUIRED',
             ('step-up level 2', {'loa-condition-level': '2', 'loa-max-age': '0'}), None),
            ('auth-otp-form', 'REQUIRED', None, None),
        ]),
    ]),
]


# --- The flow as realm JSON (for infra/keycloak/myrealm-realm.json) ---------------------

def realm_json():
    flows, configs = [], []

    def add_flow(alias, steps, top_level):
        executions = []
        for priority, (name, requirement, config, children) in enumerate(steps):
            execution = {'requirement': requirement, 'priority': (priority + 1) * 10, 'userSetupAllowed': False}
            if children is not None:
                execution.update(authenticatorFlow=True, flowAlias=name)
                add_flow(name, children, False)
            else:
                execution.update(authenticator=name, authenticatorFlow=False)
            if config:
                execution['authenticatorConfig'] = config[0]
                configs.append({'alias': config[0], 'config': config[1]})
            executions.append(execution)
        flows.insert(0, {'alias': alias, 'description': 'CyberDome: password, and an OTP for a step-up' if top_level else '',
                         'providerId': 'basic-flow', 'topLevel': top_level, 'builtIn': False,
                         'authenticationExecutions': executions})

    add_flow(FLOW_ALIAS, FLOW, True)
    return {'browserFlow': FLOW_ALIAS, 'authenticationFlows': flows, 'authenticatorConfig': configs}


# --- The flow through the admin API ---------------------------------------------------

def admin_client():
    from keycloak import KeycloakAdmin, KeycloakOpenIDConnection
    from cyberdome.settings import (KEYCLOAK_ADMIN_CLIENT_SECRET, KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_REALM,
                                    KEYCLOAK_SERVER_URL, require)
    connection = KeycloakOpenIDConnection(server_url=f"{KEYCLOAK_SERVER_URL}/", username=KEYCLOAK_ADMIN_USERNAME,
                                          password=require('KEYCLOAK_ADMIN_PASSWORD'), realm_name=KEYCLOAK_REALM,
                                          user_realm_name='master', client_id='admin-cli',
                                          client_secret_key=KEYCLOAK_ADMIN_CLIENT_SECRET, verify=False)
    return KeycloakAdmin(connection=connection), KEYCLOAK_REALM


def flow_exists(admin, alias):
    return any(flow['alias'] == alias for flow in admin.get_authentication_flows())


def own_executions(admin, flow_alias):
    # The executions directly in this flow (level 0), in order
    return [execution for execution in admin.get_authentication_flow_executions(flow_alias) if execution['level'] == 0]


def add_steps(admin, flow_alias, steps):
    for name, requirement, config, children in steps:
        if children is not None:
            admin.create_authentication_flow_subflow({'alias': name, 'type': 'basic-flow', 'provider': 'registration-page-form',
                                                      'description': ''}, flow_alias)
        else:
            admin.create_authentication_flow_execution({'provider': name}, flow_alias)
        execution = own_executions(admin, flow_alias)[-1]
        # Send back the whole execution with the new requirement, so nothing else changes
        execution['requirement'] = requirement
        admin.update_authentication_flow_executions(execution, flow_alias)
        if config:
            admin.create_execution_config(execution['id'], {'alias': config[0], 'config': config[1]})
        if children is not None:
            add_steps(admin, name, children)


def use_browser_flow(admin, realm, alias):
    admin.update_realm(realm, {'browserFlow': alias})


def delete_flow(admin, alias):
    for flow in admin.get_authentication_flows():
        if flow['alias'] == alias:
            admin.delete_authentication_flow(flow['id'])


def main():
    parser = argparse.ArgumentParser(description='Step-up authentication in Keycloak (Task 2)')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--recreate', action='store_true', help='delete our flow first and add it again')
    group.add_argument('--undo', action='store_true', help="go back to Keycloak's own browser flow")
    group.add_argument('--print-json', action='store_true', help='print the flow as realm JSON')
    args = parser.parse_args()

    if args.print_json:
        print(json.dumps(realm_json(), indent=2))
        return

    admin, realm = admin_client()
    if args.undo or args.recreate:
        use_browser_flow(admin, realm, DEFAULT_BROWSER_FLOW)
        delete_flow(admin, FLOW_ALIAS)
        print(f"Browser logins use Keycloak's '{DEFAULT_BROWSER_FLOW}' flow again, and '{FLOW_ALIAS}' is deleted.")
        if args.undo:
            return

    if flow_exists(admin, FLOW_ALIAS):
        print(f"The flow '{FLOW_ALIAS}' already exists. Use --recreate to add it again.")
    else:
        admin.create_authentication_flow({'alias': FLOW_ALIAS, 'providerId': 'basic-flow', 'topLevel': True,
                                          'builtIn': False, 'description': 'CyberDome: password, and an OTP for a step-up'})
        add_steps(admin, FLOW_ALIAS, FLOW)
        print(f"Added the flow '{FLOW_ALIAS}'.")
    use_browser_flow(admin, realm, FLOW_ALIAS)
    print(f"Browser logins in realm '{realm}' now use '{FLOW_ALIAS}'.")
    for execution in admin.get_authentication_flow_executions(FLOW_ALIAS):
        print(f"  {'  ' * execution['level']}{execution['displayName']}: {execution['requirement']}")


if __name__ == '__main__':
    main()
