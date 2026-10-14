'''

The peer-to-peer nodes that make an access decision, built on p2pnetwork.

Networking is the base class with what every node shares: sending a message to a
node by ID, receiving messages, and printing connection events. Each node type
is a subclass that only handles the messages it expects:

    WebUINode (4) ──► AccessProxyNode (1) ──► TrustEngineNode (2) ──► PolicyEngineNode (3) ──► WebUINode (4)

The access request's ID travels through all of them as request_id, so the Web UI
can match each verdict to its request.

'''
import json
import os
import threading
from datetime import datetime
import traceback
from p2pnetwork.node import Node
from . import trust_algorithm as ta
from .policy import make_access_decision
from .trust_signals import get_latest_access_request, get_sign_in_success_rate, get_user_identity_data_by_id
from .data_paths import ACCESS_DECISIONS_FILE, ACCESS_REQUESTS_FILE, USER_DATA_FILE

ACCESS_PROXY_ID = '1'
TRUST_ENGINE_ID = '2'
POLICY_ENGINE_ID = '3'
WEB_UI_ID = '4'


class Networking(Node):
    #Define a dictionary of the node roles based on their node.id attributes
    NODE_ROLE = {
        ACCESS_PROXY_ID: 'Access Proxy Node',
        TRUST_ENGINE_ID: 'Trust Engine Node',
        POLICY_ENGINE_ID: 'Policy Engine Node',
        WEB_UI_ID: 'Web UI'
    }

    # Each subclass sets its own node ID
    NODE_ID = None

    def __init__(self, host, port, callback=None, max_connections=0):
        super(Networking, self).__init__(host, port, self.NODE_ID, callback, max_connections)
        print(f"\n{self.get_node_role(self.id)} STARTED on {self.host}:{self.port}")

    #Define a function to extract the name of a node based on it's node.id attribute
    def get_node_role(self,node_id):
        return self.NODE_ROLE.get(node_id,'UNKNOWN ROLE')


    def send_message_to_node(self, node_id, message):
        # Find the specific node by its ID
        target_node = None

        for node in self.all_nodes:
            if node.id == node_id:
                target_node = node
                #convert the message to a json object
                json_message = {
                    "senderID": self.id,
                    "messageContent":message
                }
                # Send the message to the specific node
                self.send_to_node(target_node, json_message)
                print(f"Message sent to: {self.get_node_role(node_id)}")
                break
        if target_node is None:
            print(f"Node {node_id} not found in inbound or outbound connections.")

    # Message handlers, one per sender. By default a node only prints the message.
    # Each subclass overrides the handler for the sender it expects.

    def process_message_from_access_proxy(self, sender, message):
        print(f"Received a message from Access Proxy Node [{sender}]: {message}")

    def process_message_from_trust_engine(self, sender, message):
        print(f"Received a message from Trust Engine Node [{sender}]: {message}")

    def process_message_from_policy_engine(self, sender, message):
        print(f"Received a message from Policy Engine Node [{sender}]: {message}")

    def process_message_from_web_ui(self, sender, message):
        print(f"Received a message from Web UI [{sender}]: {message}")

    def print_all_nodes(self):
        print("Outbound Nodes:")
        for node in self.nodes_outbound:
            print(f"Outbound Node ID: {node.id}, Host: {node.host}, Port: {node.port}")

        print("\nInbound Nodes:")
        for node in self.nodes_inbound:
            print(f"Inbound Node ID: {node.id}, Host: {node.host}, Port: {node.port}")


    # The methods below are called when events happen in the network

    def outbound_node_connected(self, node):
        node_role = self.get_node_role(node.id)
        print(f"\n{self.get_node_role(self.id)} Connected to {node_role}")

    def inbound_node_connected(self, node):
        print(f"\n{self.get_node_role(node.id)} Connected to {self.get_node_role(self.id)}")

    def inbound_node_disconnected(self, node):
        print(f"\n{self.get_node_role(node.id)} DISCONNECTED from {self.get_node_role(self.id)}")

    def outbound_node_disconnected(self, node):
        print(f"\n{self.get_node_role(self.id)} DISCONNECTED from {self.get_node_role(node.id)}")

    def node_message(self, node, data):
        sender_id = node.id  # Get the sender's ID
        message_content = data  # Get the message content

        if "senderID" in message_content:
            message_content = message_content["messageContent"]
            #extract other future message atributes like unique hash, and message intent

        handlers = {
            ACCESS_PROXY_ID: self.process_message_from_access_proxy,
            TRUST_ENGINE_ID: self.process_message_from_trust_engine,
            POLICY_ENGINE_ID: self.process_message_from_policy_engine,
            WEB_UI_ID: self.process_message_from_web_ui,
        }

        # Process the message based on the sender's ID.
        # An uncaught error here would end p2pnetwork's receive thread for this
        # connection, and the node would silently stop hearing from that sender.
        try:
            handler = handlers.get(sender_id)
            if handler:
                handler(sender_id, message_content)
            else:
                print(f"Received a message from an unknown sender ({sender_id}): {message_content}")
        except Exception:
            print(f"\n{self.get_node_role(self.id)} failed to process a message from {self.get_node_role(sender_id)}:")
            traceback.print_exc()

    def node_disconnect_with_outbound_node(self, node):
        print(f"\n{self.get_node_role(self.id)} wants to disconnect with {node.id}")

    def node_request_to_stop(self):
        print(f"\nStopping the {self.get_node_role(self.id)} node")


# What the Access Proxy needs in every access request before it passes it on
REQUIRED_REQUEST_FIELDS = ('ID', 'user_id', 'resource', 'action', 'authentication_status')


class AccessProxyNode(Networking):
    '''Node 1: receives access requests from the Web UI, checks they are complete, and passes them to the Trust Engine.'''
    NODE_ID = ACCESS_PROXY_ID

    def process_message_from_web_ui(self, sender, message):
        print(f"Received an Access Request from Web UI [{sender}]: {message}")
        # Check if the 'intent' key has the value 'Access Request'
        if message.get('intent', '').lower() != 'access request':
            print("The intent is not 'Access Request'")
            return

        missing = [field for field in REQUIRED_REQUEST_FIELDS if not message.get(field)]
        if missing:
            # Reject incomplete requests here, and tell the Web UI why
            reason = f"Request rejected by the Access Proxy: missing {', '.join(missing)}"
            print(reason)
            self.send_message_to_node(WEB_UI_ID, {
                'request_id': message.get('ID'),
                'access_decision': 0,
                'decided_by': 'Access Proxy',
                'reason': reason
            })
            return

        # The whole request travels on, so the next engines decide on this request
        access_request = dict(message, mediated_by='Access Proxy', proxy_received_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print(f"Access Proxy: request {access_request['ID']} from {access_request['user_id']} for {access_request['resource']} ({access_request['action']}) is complete, sending it to the Trust Engine")

        data = {
            'user_id': access_request['user_id'],
            # Carried through to the verdict so the Web UI can match it to this request
            'request_id': access_request['ID'],
            'intent': 'request_trust_score',
            'access_request': access_request
        }
        self.send_message_to_node(TRUST_ENGINE_ID,data)


class TrustEngineNode(Networking):
    '''Node 2: calculates the trust score for the request and sends it to the Policy Engine.'''
    NODE_ID = TRUST_ENGINE_ID

    def process_message_from_access_proxy(self, sender, message):
        print(f"Received a message from Access Proxy Node [{sender}]: {message}")
        # check if the intent is 'request_trust_score'
        if message.get('intent') == 'request_trust_score':
            user_id = message.get('user_id')
            access_request = message.get('access_request')
            print(f"Received a Trust Score Request From: {user_id}")
            print(f"Performing Trust Evaluation for the Subject({user_id})...")

            # If scoring fails (for example, no login data for the user yet), the Policy Engine
            # still gets an answer, and denies with this reason, instead of the request timing out
            trust_error = None
            trust_factors = None
            try:
                trust = ta.calculate_trust_breakdown(user_id, access_request)
                user_trust_score, trust_factors = trust['score'], trust['factors']
                print(f"Subject({user_id}) Trust Score: {user_trust_score}")
                for factor, details in trust_factors.items():
                    print(f"    {factor}: {details['score']} x {details['weight']} ({details['reason']})")
            except Exception as e:
                traceback.print_exc()
                user_trust_score = None
                trust_error = f"Trust evaluation failed: {type(e).__name__}: {e}"
                print(trust_error)

            print(f"Sending the subject's trust score to Policy Engine for policy validation...")
            data = {
                'user_id': user_id,
                'request_id': message.get('request_id'),
                'intent': 'request_access_decision',
                'access_request': access_request,
                'user_trust_score': user_trust_score,
                'trust_factors': trust_factors,
                'trust_error': trust_error
            }
            self.send_message_to_node(POLICY_ENGINE_ID,data)


class PolicyEngineNode(Networking):
    '''Node 3: applies the policies to the request, saves the decision and sends it, with a reason, to the Web UI.'''
    NODE_ID = POLICY_ENGINE_ID

    def decide(self, message):
        # Returns (verdict, reason). Fails closed: anything missing means deny.
        user_id = message.get('user_id')
        user_trust_score = message.get('user_trust_score')

        if message.get('trust_error') or user_trust_score is None:
            return 0, message.get('trust_error') or 'No trust score for this request'

        user_identity_data = get_user_identity_data_by_id(user_id,USER_DATA_FILE)
        sign_in_success_rate = get_sign_in_success_rate(user_id)

        print(f"User Identity Data: {user_identity_data}")

        if not user_identity_data:
            return 0, 'No identity record for this user'
        if sign_in_success_rate is None:
            return 0, 'No login history for this user'

        # Retrieving user_role from user_identity_data
        user_role = user_identity_data.get('user_role')
        print(f"User Role: {user_role}")

        # The share of successful logins over the user's last 10 attempts (higher is better)
        print(f"Sign-in success rate: {sign_in_success_rate}")

        # Call the access decision script /function here to return the verdict
        verdict = make_access_decision(user_role,user_trust_score,sign_in_success_rate)
        if verdict:
            reason = f"Allowed: trust score {user_trust_score:.2f} and sign-in success rate {sign_in_success_rate:.2f} meet the policy thresholds for role {user_role}"
        else:
            reason = f"Denied: trust score {user_trust_score:.2f} or sign-in success rate {sign_in_success_rate:.2f} is below the policy threshold for role {user_role}"
        return verdict, reason

    def process_message_from_trust_engine(self, sender, message):
        print(f"Received a message from Trust Engine Node [{sender}]: {message}")
        # check if the message intent is 'request_access_decision'
        if message.get('intent') == 'request_access_decision':
            user_id = message.get('user_id')
            user_trust_score = message.get('user_trust_score')
            # The request being decided, as sent by the Access Proxy
            access_request = message.get('access_request') or get_latest_access_request(user_id, ACCESS_REQUESTS_FILE) or {}
            print(f"Received a Request for Access Decision from Trust Engine for User {user_id}")
            print(f"Current Subject's Trust Score: {user_trust_score}")
            print(f"Checking against security policies...")
            print(f"Access Request being decided: {access_request}")

            # The location is the country code of the user's IP (LOCAL on localhost)
            print(f"Location: {access_request.get('location')}")

            verdict, reason = self.decide(message)

            print(f"Policy Engine Verdict: {verdict} ({reason})")

            file_path = ACCESS_DECISIONS_FILE

            # Check if the file exists to determine the initial ID
            if os.path.exists(file_path):
                with open(file_path, 'r') as file:
                    access_decisions = json.load(file)
                    if access_decisions:
                        last_entry = access_decisions[-1]
                        new_id = last_entry['ID'] + 1
                    else:
                        new_id = 1
            else:
                access_decisions = []
                new_id = 1

            # Prepare the access decision data
            access_decision_data = {
                'ID': new_id,
                'request_id': message.get('request_id'),
                'user_id': user_id,
                'resource': access_request.get('resource'),
                'action': access_request.get('action'),
                'intent': 'request_access_decision',
                'user_trust_score': user_trust_score,
                'trust_factors': message.get('trust_factors'),
                'access_decision': verdict,
                'reason': reason,
                'decided_by': 'Policy Engine',
                'decided_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            self.send_message_to_node(WEB_UI_ID,access_decision_data)

            # Append the new access decision data to the existing list
            access_decisions.append(access_decision_data)

            # Write the updated data to the JSON file
            with open(file_path, 'w') as file:
                json.dump(access_decisions, file, indent=4)


class WebUINode(Networking):
    '''Node 4: the Web UI's node. Sends access requests to the Access Proxy and waits for each request's verdict.'''
    NODE_ID = WEB_UI_ID

    def __init__(self, host, port, callback=None, max_connections=0):
        # Verdicts from the Policy Engine, keyed by access request ID
        self.access_decisions = {}
        self.access_decision_received = threading.Condition()
        super(WebUINode, self).__init__(host, port, callback, max_connections)

    def wait_for_access_decision(self, request_id, timeout):
        # Block until the Policy Engine's verdict for this request arrives; None on timeout
        with self.access_decision_received:
            self.access_decision_received.wait_for(lambda: request_id in self.access_decisions, timeout)
            return self.access_decisions.pop(request_id, None)

    def process_message_from_policy_engine(self, sender, message):
        print(f"Received a message from Policy Engine Node [{sender}]: {message}")
        with self.access_decision_received:
            self.access_decisions[message.get('request_id')] = message
            self.access_decision_received.notify_all()
