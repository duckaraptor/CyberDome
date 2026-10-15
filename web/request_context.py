'''

Builds the access request record for a protected page, on the server.

The record comes from things the server controls: the checked token (user, roles,
authentication status), the page (resource, action), the HTTP connection (source IP
and its location), the device ID cookie and the browser's User-Agent header (device
type, OS). Values sent by the browser in a request body are not used, because the
user can change them.

'''
import functools
import ipaddress
import json
import os
import re
import threading
import uuid
from datetime import datetime

import requests
from flask import g, request, session

from cyberdome.data_paths import KNOWN_DEVICES_FILE

DEVICE_COOKIE = 'cyberdome_device_id'
DEVICE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60  # one year, in seconds

_known_devices_lock = threading.Lock()


# --- Device ID -----------------------------------------------------------------

def load_device_id():
    # Runs before every request (registered in app.py). Reads the device ID cookie,
    # or makes a new random ID if the browser has none (or an invalid one).
    device_id = request.cookies.get(DEVICE_COOKIE, '')
    try:
        g.device_id = str(uuid.UUID(device_id))
        g.new_device_cookie = False
    except ValueError:
        g.device_id = str(uuid.uuid4())
        g.new_device_cookie = True


def save_device_cookie(response):
    # Runs after every request (registered in app.py). Gives a new browser its device ID cookie.
    # HttpOnly: page scripts can't read it. SameSite=Lax: other sites can't send it in their requests.
    if g.get('new_device_cookie'):
        response.set_cookie(DEVICE_COOKIE, g.device_id, max_age=DEVICE_COOKIE_MAX_AGE, httponly=True, samesite='Lax')
    return response


def read_known_devices():
    # data/known_devices.json: {username: [device IDs the user was allowed access from]}
    try:
        with open(KNOWN_DEVICES_FILE, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def is_new_device(username, device_id):
    with _known_devices_lock:
        return device_id not in read_known_devices().get(username, [])


def remember_device(username, device_id):
    # Called after an "allow" decision, so a device only becomes known once access was allowed from it
    with _known_devices_lock:
        known_devices = read_known_devices()
        devices = known_devices.setdefault(username, [])
        if device_id not in devices:
            devices.append(device_id)
            with open(KNOWN_DEVICES_FILE, 'w') as file:
                json.dump(known_devices, file, indent=4)


# --- Location ------------------------------------------------------------------

@functools.lru_cache(maxsize=1024)
def location_of(ip):
    # The country code of an IP address (for example 'SE'), the same format as the
    # risk lists in policyConfiguration.yml. Each IP is looked up once per process.
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return 'Unknown'
    if address.is_loopback or address.is_private:
        return 'LOCAL'  # localhost or a local network, which have no country
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=3)
        return response.json().get('country') or 'Unknown'
    except (requests.RequestException, ValueError) as e:
        print(f"Location lookup failed for {ip}: {e}")
        return 'Unknown'


# --- Device type and OS ----------------------------------------------------------

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


# --- The record ------------------------------------------------------------------

def build_access_request(resource):
    # Call after the authentication check, which sets g.token_info and g.user_roles
    user_agent = request.headers.get('User-Agent', '')
    device_type, device_os = device_from_user_agent(user_agent)
    profile = session.get('oidc_auth_profile', {})
    username = g.token_info.get('preferred_username') or profile.get('preferred_username')

    return {
        'user_id': g.token_info.get('sub') or profile.get('sub'),
        'username': username,
        'roles': list(g.user_roles),
        'intent': 'Access Request',
        'resource': resource,
        'resource_requested': resource,
        'path': request.path,
        'action': 'read' if request.method in ('GET', 'HEAD') else 'write',
        'access_request_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'authentication_status': 'authenticated' if g.token_info.get('active') else 'unauthenticated',
        'source_ip': request.remote_addr,
        'location': location_of(request.remote_addr),
        'device_id': g.device_id,
        'new_device': is_new_device(username, g.device_id),
        'browser': user_agent,
        'device_type': device_type,
        'device_OS': device_os,
    }
