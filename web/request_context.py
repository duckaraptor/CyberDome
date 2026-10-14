'''

Builds the access request record for a protected page, on the server.

The record comes from things the server controls: the checked token (user, roles,
authentication status), the page (resource, action), the HTTP connection (source IP)
and the browser's User-Agent header (device type, OS). Values sent by the browser in a
request body are not used, because the user can change them.

Not finished yet (assignment section 3.2, step 3): the device ID, and location, public IP
and MAC, which are still the Flask server's own values, as in the original code.

'''
import functools
import re
import uuid
from datetime import datetime

from flask import g, request, session

from keycloak_functions import get_location, get_mac_details, get_public_ip


@functools.lru_cache(maxsize=1)
def server_network_context():
    # The Flask server's public IP, location and MAC, looked up once per process.
    # (These describe the server, not the user. Kept from the original code until step 3.)
    try:
        location_info = get_location(ip_address=get_public_ip())
        public_ip = location_info.get('ip') or 'Unknown'
        location = f"{location_info.get('city')}/{location_info.get('country')}"
    except Exception as e:
        print(f"Location lookup failed: {e}")
        public_ip, location = 'Unknown', 'Unknown/Unknown'

    device_mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    return {
        'public_ip_address': public_ip,
        'location': location,
        'device_mac': device_mac,
        'device_vendor': get_mac_details(device_mac),
    }


def device_from_user_agent(user_agent):
    # Device type and operating system from the browser's User-Agent header
    device_type = 'Mobile' if re.search(r'Mobile|iP(hone|od)|Android|BlackBerry|IEMobile', user_agent) else 'Desktop'
    if 'Windows' in user_agent:
        device_os = 'Windows'
    elif 'Android' in user_agent:
        device_os = 'Android'
    elif re.search(r'iPhone|iPad|iPod', user_agent):
        device_os = 'iOS'
    elif 'Mac OS X' in user_agent or 'Macintosh' in user_agent:
        device_os = 'MacIntel'
    elif 'Linux' in user_agent:
        device_os = 'Linux'
    else:
        device_os = 'Unknown'
    return device_type, device_os


def build_access_request(resource):
    # Call after the authentication check, which sets g.token_info and g.user_roles
    user_agent = request.headers.get('User-Agent', '')
    device_type, device_os = device_from_user_agent(user_agent)
    profile = session.get('oidc_auth_profile', {})

    access_request = {
        'user_id': g.token_info.get('sub') or profile.get('sub'),
        'username': g.token_info.get('preferred_username') or profile.get('preferred_username'),
        'roles': list(g.user_roles),
        'intent': 'Access Request',
        'resource': resource,
        'resource_requested': resource,
        'path': request.path,
        'action': 'read' if request.method in ('GET', 'HEAD') else 'write',
        'access_request_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'authentication_status': 'authenticated' if g.token_info.get('active') else 'unauthenticated',
        'source_ip': request.remote_addr,
        'browser': user_agent,
        'device_type': device_type,
        'device_OS': device_os,
    }
    access_request.update(server_network_context())
    return access_request
