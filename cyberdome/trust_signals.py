'''
This file will have the functions related to collecting trust signals, processing them and storing them in json files 

'''

'''
HANDLING PROCESSING OF AUTH_DATA
'''

import json
import os
from datetime import datetime, timedelta

from .data_paths import AUTH_DATA_FILE, EVENTS_FILE

# How many of the user's most recent login attempts count for the sign-in success rate
LOGIN_HISTORY_SIZE = 10


def success_rate(auth_statuses):
    # Share of successful logins (auth_status 1) among the given attempts, between 0 and 1.
    # None if there are no attempts.
    recent = list(auth_statuses)[-LOGIN_HISTORY_SIZE:]
    if not recent:
        return None
    return sum(1 for status in recent if status == 1) / len(recent)


def add_sign_in_success_rates(auth_data):
    # Give each login attempt the user's success rate over their last attempts, up to and including this one.
    # (This replaces the original "Markov chain" prediction, which started each user's history with a
    # made-up 0 and could give values up to 1.5.)
    history = {}
    for entry in sorted(auth_data, key=lambda entry: entry['time'] or 0):
        statuses = history.setdefault(entry['user_id'], [])
        statuses.append(entry['auth_status'])
        entry['sign_in_success_rate'] = success_rate(statuses)
    return auth_data

def process_events(events_data):
    cleaned_data = []

    for event in events_data:
        if event['user_id'] is not None:  # Skip entries with null user_id
            cleaned_event = {
                'time': event.get('time', None),
                'type': event.get('type', None),
                'user_id': event.get('user_id', None),
                'ip_address': event.get('ip_address', None),
                'auth_type': event.get('auth_type', None),
                'auth_status': 1 if event.get('type') == 'LOGIN' else 0
            }

            # Skip records not matching criteria
            if cleaned_event['auth_status'] == 0 and event.get('type') != 'LOGIN_ERROR':
                continue

            cleaned_data.append(cleaned_event)

    # Each login attempt gets the user's sign-in success rate at that moment
    auth_data = add_sign_in_success_rates(cleaned_data[:])

    # File handling to store events in a JSON file
    file_path = AUTH_DATA_FILE

    try:
        existing_data = []
        new_id = 1

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                existing_data = json.load(file)
                if existing_data:
                    last_entry = existing_data[-1]
                    new_id = last_entry.get('ID', 0) + 1  # Check if 'ID' exists, otherwise set new_id to 1

        # Filter out events that already exist in the JSON file (same user and time).
        # New logins are added, so each user's latest sign-in value stays current.
        existing_keys = {(entry.get('user_id'), entry.get('time')) for entry in existing_data}
        auth_data_to_add = [event for event in auth_data if (event['user_id'], event['time']) not in existing_keys]

        for i, event in enumerate(auth_data_to_add, start=new_id):
            event['ID'] = i
            existing_data.append(event)

        # Write the updated data to the JSON file
        with open(file_path, 'w') as file:
            json.dump(existing_data, file, indent=4)

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while handling the JSON file: {e}")

    except IOError as e:
        print(f"Error occurred while writing JSON data: {e}")


def load_events_data(file_path):
    try:
        with open(file_path, 'r') as file:
            events_data = json.load(file)
        return events_data
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON file: {e}")
        return None

'''

HANDLING PROCESSING AND STORAGE OF EVENTS DATA

'''

def store_keycloak_events(keycloak_admin):
    # No date range: fetch the most recent login events, whatever the year
    query_params = {
        "max": 10000,
    }

    events_data = keycloak_admin.get_events(query=query_params)
    cleaned_data = []

    for event in events_data:
        cleaned_event = {
            'time': event.get('time', None),
            'type': event.get('type', None),
            'user_id': event.get('userId', None),
            'ip_address': event.get('ipAddress', None)
        }

        if 'details' in event:
            details = event['details']
            cleaned_event['auth_type'] = details.get('auth_type', None)
            cleaned_event['token_id'] = details.get('token_id', None)

        cleaned_event['session_id'] = event.get('sessionId', None)

        cleaned_data.append(cleaned_event)

    file_path = EVENTS_FILE

    try:
        existing_data = []
        new_id = 1

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                existing_data = json.load(file)
                if existing_data:
                    last_entry = existing_data[-1]
                    new_id = last_entry['ID'] + 1

        for i, event in enumerate(cleaned_data, start=new_id):
            event_exists = False
            for existing_event in existing_data:
                if event['time'] == existing_event['time'] and event['user_id'] == existing_event['user_id']:
                    event_exists = True
                    break

            if not event_exists:
                event['ID'] = i
                existing_data.append(event)

        with open(file_path, 'w') as file:
            json.dump(existing_data, file, indent=4)

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while handling the JSON file: {e}")

    except IOError as e:
        print(f"Error occurred while writing JSON data: {e}")

#get the latest access request data for a particular user_id

def get_latest_access_request(user_id, access_requests):
    with open(access_requests, 'r') as file:
        data = json.load(file)

    latest_request = None
    for request in data:
        if request['user_id'] == user_id:
            if latest_request is None or request['access_request_time'] > latest_request['access_request_time']:
                latest_request = request

    return latest_request

#get the latest auth data for the particular user_id
def get_latest_auth_data(user_id, auth_data):
    with open(auth_data, 'r') as file:
        data = json.load(file)

    latest_data = None
    for entry in data:
        if entry['user_id'] == user_id:
            if latest_data is None or entry['time'] > latest_data['time']:
                latest_data = entry

    return latest_data

#get user identity information
def get_user_identity_data_by_id(user_id, user_data_file):
    with open(user_data_file, 'r') as file:
        user_data = json.load(file)

    for user in user_data:
        if user['user_id'] == user_id:
            return user

    return None  # Return None if user_id not found


def get_sign_in_success_rate(user_id, auth_data_file=AUTH_DATA_FILE):
    # The user's share of successful logins over their last LOGIN_HISTORY_SIZE attempts, or None without any
    try:
        with open(auth_data_file, 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    attempts = sorted((entry for entry in data if entry.get('user_id') == user_id), key=lambda entry: entry.get('time') or 0)
    return success_rate(entry.get('auth_status') for entry in attempts)


def count_recent_access_requests(user_id, request_time, minutes, access_requests_file, exclude_id=None):
    # How many access requests the user sent in the `minutes` before request_time (a 'YYYY-MM-DD HH:MM:SS' string).
    # The request being scored (exclude_id) isn't counted.
    try:
        with open(access_requests_file, 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0
    end = datetime.strptime(request_time, '%Y-%m-%d %H:%M:%S')
    start = end - timedelta(minutes=minutes)
    count = 0
    for request in data:
        if request.get('user_id') != user_id or (exclude_id is not None and request.get('ID') == exclude_id):
            continue
        try:
            sent = datetime.strptime(request.get('access_request_time', ''), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
        if start <= sent <= end:
            count += 1
    return count
