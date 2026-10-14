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
from . import policy
from .trust_signals import get_latest_access_request, get_sign_in_success_rate
from . import audit
from .data_paths import ACCESS_REQUESTS_FILE

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
        # Find the specific node by its ID. Newest connections are at the end of the list, so search
        # from the end: after a restart (for example of the Web UI), the old, dead connection to the
        # same ID can still be in the list for a moment, and a message sent to it would be lost.
        target_node = None

        for node in reversed(self.all_nodes):
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
        # A node that connects again with the same ID (for example a restarted Web UI) replaces its
        # old connection. Close the old one, so messages for that ID go to the new connection.
        for old in [other for other in self.nodes_inbound if other.id == node.id and other is not node]:
            print(f"Closing the old connection of {self.get_node_role(old.id)}")
            old.stop()

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

    def decide(self, message, access_request):
        # Applies the policies P1 to P6 (cyberdome/policy.py) to this request.
        # Fails closed: a missing trust score or login history means deny, with the reason.
        user_id = message.get('user_id')
        sign_in_success_rate = get_sign_in_success_rate(user_id)
        # The share of successful logins over the user's last 10 attempts (higher is better)
        print(f"Sign-in success rate: {sign_in_success_rate}")
        return policy.decide(access_request, message.get('user_trust_score'), message.get('trust_factors'),
                             sign_in_success_rate, message.get('trust_error'))

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

            decision = self.decide(message, access_request)

            print(f"Policy Engine Verdict: {decision['decision']} by {decision['policy_id']} {decision['policy_name']} ({decision['reason']})")

            # Log the decision before sending it, so access is never given without an audit entry
            entry = audit.log_decision(decision['outcome'], decision['reason'], 'Policy Engine', request=access_request,
                                       decision=decision, trust_score=user_trust_score,
                                       trust_factors=message.get('trust_factors'))

            # The decision for the Web UI: what it needs to serve or refuse the page
            access_decision_data = {
                'request_id': message.get('request_id'),
                'user_id': user_id,
                'resource': access_request.get('resource'),
                'action': access_request.get('action'),
                'intent': 'request_access_decision',
                'access_decision': decision['access_decision'],
                'decision': decision['decision'],
                'outcome': decision['outcome'],
                'policy_id': decision['policy_id'],
                'policy_name': decision['policy_name'],
                'reason': decision['reason'],
                'user_trust_score': user_trust_score,
                'trust_score': user_trust_score,
                'decided_by': 'Policy Engine',
                'decided_at': entry['time'],
            }

            self.send_message_to_node(WEB_UI_ID,access_decision_data)


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
