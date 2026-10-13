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
import traceback
from p2pnetwork.node import Node
from . import trust_algorithm as ta
from .policy import make_access_decision
from .trust_signals import get_latest_access_request, get_latest_auth_data, get_user_identity_data_by_id
from .data_paths import ACCESS_DECISIONS_FILE, ACCESS_REQUESTS_FILE, AUTH_DATA_FILE, USER_DATA_FILE

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


class AccessProxyNode(Networking):
    '''Node 1: receives access requests from the Web UI and asks the Trust Engine for a score.'''
    NODE_ID = ACCESS_PROXY_ID

    def process_message_from_web_ui(self, sender, message):
        print(f"Received an Access Request from Web UI [{sender}]: {message}")
        # Check if the 'intent' key has the value 'Access Request'
        if message.get('intent', '').lower() == 'access request':
            #access request received, prepare data to send to Trust Engine(node 2)
            user_id = message.get('user_id')
            intent = 'request_trust_score'

            data = {
                'user_id': user_id,
                # Carried through to the verdict so the Web UI can match it to this request
                'request_id': message.get('ID'),
                'intent': intent
            }
            self.send_message_to_node(TRUST_ENGINE_ID,data)
        else:
            print("The intent is not 'Access Request'")


class TrustEngineNode(Networking):
    '''Node 2: calculates the user's trust score and sends it to the Policy Engine.'''
    NODE_ID = TRUST_ENGINE_ID

    def process_message_from_access_proxy(self, sender, message):
        print(f"Received a message from Access Proxy Node [{sender}]: {message}")
        # check if the intent is 'request_trust_score'
        if message.get('intent') == 'request_trust_score':
            user_id = message.get('user_id')
            print(f"Received a Trust Score Request From: {user_id}")
            #get the trust score for this user_id using the trust algorithm
            user_trust_score = ta.calculate_overall_trust_score(user_id)
            print(f"Performing Trust Evaluation for the Subject({user_id})...")
            print(f"Subject({user_id}) Trust Score: {user_trust_score}")
            print(f"Sending the subject's trust score to Policy Engine for policy validation...")
            data = {
                'user_id': user_id,
                'request_id': message.get('request_id'),
                'intent': 'request_access_decision',
                'user_trust_score': user_trust_score
            }
            self.send_message_to_node(POLICY_ENGINE_ID,data)


class PolicyEngineNode(Networking):
    '''Node 3: applies the policies, saves the decision and sends the verdict to the Web UI.'''
    NODE_ID = POLICY_ENGINE_ID

    def process_message_from_trust_engine(self, sender, message):
        print(f"Received a message from Trust Engine Node [{sender}]: {message}")
        # check if the message intent is 'request_access_decision'
        if message.get('intent') == 'request_access_decision':
            user_id = message.get('user_id')
            user_trust_score = message.get('user_trust_score')
            print(f"Received a Request for Access Decision from Trust Engine for User {user_id}")
            print(f"Current Subject's Trust Score: {user_trust_score}")
            print(f"Checking against security policies...")

            user_identity_data = get_user_identity_data_by_id(user_id,USER_DATA_FILE)
            user_auth_data = get_latest_auth_data(user_id, AUTH_DATA_FILE)
            user_access_request = get_latest_access_request(user_id, ACCESS_REQUESTS_FILE)

            print(f"Latest Access Request for the user: {user_access_request}")
            print(f"Latest Authentication Data for the user: {user_auth_data}")
            print(f"User Identity Data: {user_identity_data}")

            # Retrieving user_role from user_identity_data
            user_role = user_identity_data.get('user_role')

            print(f"User Role: {user_role}")

            # Retrieving sign_in_risk from user_auth_data
            sign_in_risk = user_auth_data.get('sign_in_risk')
            print(f"Sign In Risk: {sign_in_risk}")

            # Retrieving country from location in user_access_request
            location = user_access_request.get('location', '')

            country = location.split('/')[-1]

            print(f"Country: {country}")

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

            # Call the access decision script /function here to return the verdict
            verdict = make_access_decision(user_role,user_trust_score,sign_in_risk)

            print(f"Policy Engine Verdict: {verdict}")
             # Prepare the access decision data
            access_decision_data = {
                'ID': new_id,
                'request_id': message.get('request_id'),
                'user_id': user_id,
                'intent': 'request_access_decision',
                'user_trust_score': user_trust_score,
                'access_decision': verdict
            }

            self.send_message_to_node(WEB_UI_ID,access_decision_data)

            # Append the new access decision data to the existing list
            access_decisions.append(access_decision_data)

            # Write the updated data to the JSON file
            with open(file_path, 'w') as file:
                json.dump(access_decisions, file, indent=4)


class WebUINode(Networking):
    '''Node 4: started by the Web UI for one access request. Waits for the Policy Engine's verdict.'''
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
