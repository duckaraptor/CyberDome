'''

The Web UI's connection to the decision engines.

One long-lived Web UI node (node 4) is shared by all requests. It is started on the
first access request, so that with Flask's debug reloader only the process that
serves requests holds its port. Each request waits for the verdict with its own
request ID.

'''
import json
import os
import threading

from cyberdome.data_paths import ACCESS_REQUESTS_FILE
from cyberdome.networking import ACCESS_PROXY_ID, POLICY_ENGINE_ID, WebUINode

HOST = '127.0.0.1'
WEB_UI_PORT = 8004
ACCESS_PROXY_PORT = 8001
POLICY_ENGINE_PORT = 8003

# Seconds to wait for the Policy Engine's verdict before denying access
ACCESS_DECISION_TIMEOUT = 10

_node = None
_node_lock = threading.Lock()
_request_log_lock = threading.Lock()


def connected_to(node, node_id):
    return any(peer.id == node_id for peer in node.all_nodes)


def get_node():
    # Start node 4 once, and (re)connect to the Access Proxy and Policy Engine when needed,
    # for example after the engines were restarted
    global _node
    with _node_lock:
        if _node is None:
            node = WebUINode(HOST, WEB_UI_PORT)
            node.start()
            _node = node
        if not connected_to(_node, ACCESS_PROXY_ID):
            _node.connect_with_node(HOST, ACCESS_PROXY_PORT)
        if not connected_to(_node, POLICY_ENGINE_ID):
            # The Policy Engine sends the verdict back over this connection
            _node.connect_with_node(HOST, POLICY_ENGINE_PORT)
        return _node


def stop_node():
    # Stop node 4 and its connection threads. Without this, they keep the Python process
    # running after the Web UI (or a test) is stopped. p2pnetwork can take up to 10 seconds.
    global _node
    with _node_lock:
        if _node is not None:
            print("Stopping the Web UI node (can take up to 10 seconds)...")
            _node.stop()
            _node.join(timeout=15)
            _node = None


def record_access_request(access_request):
    # Give the request the next ID and append it to data/access_requests.json.
    # The lock keeps IDs unique when several requests arrive at the same time.
    with _request_log_lock:
        existing_data = []
        try:
            if os.path.exists(ACCESS_REQUESTS_FILE):
                with open(ACCESS_REQUESTS_FILE, 'r') as file:
                    existing_data = json.load(file)
        except json.JSONDecodeError as e:
            print(f"Error occurred while loading JSON data: {e}")

        access_request['ID'] = existing_data[-1]['ID'] + 1 if existing_data else 1
        existing_data.append(access_request)

        with open(ACCESS_REQUESTS_FILE, 'w') as file:
            json.dump(existing_data, file, indent=4)
    return access_request


def request_access_decision(access_request):
    # Send the request through Access Proxy -> Trust Engine -> Policy Engine and wait for its verdict.
    # Returns the decision (a dict with access_decision, user_trust_score, reason, ...) or None.
    record_access_request(access_request)
    node = get_node()

    if not connected_to(node, ACCESS_PROXY_ID):
        # Fail closed straight away, instead of waiting for a verdict that can't come
        reason = 'The Access Proxy is not reachable, so the request could not be checked'
        print(f"{reason} (access request {access_request['ID']})")
        return {'request_id': access_request['ID'], 'access_decision': 0, 'reason': reason, 'decided_by': 'Web UI', 'http_status': 503}

    node.send_message_to_node(ACCESS_PROXY_ID, access_request)
    decision = node.wait_for_access_decision(access_request['ID'], ACCESS_DECISION_TIMEOUT)
    if decision is None:
        print(f"No verdict for access request {access_request['ID']} within {ACCESS_DECISION_TIMEOUT}s")
    return decision
