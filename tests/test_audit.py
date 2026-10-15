'''

Tests for the audit log (assignment section 3.5, docs/audit-log.md) and the
one-JSON-object-per-line files it uses (cyberdome/jsonl.py).

They write to a temporary folder, so they don't need Keycloak, the engines or the
files in data/. Each test is a function named test_..., so pytest can run them too.

Run from anywhere:  python3 tests/test_audit.py

'''
import json
import os
import sys
import tempfile
import threading
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from cyberdome import audit  # noqa: E402  (needs the path above)
from cyberdome.jsonl import append_record, append_with_next_id, read_records, read_records_backwards  # noqa: E402

REQUEST = {
    'ID': 7, 'username': 'bob', 'user_id': 'u-bob', 'roles': ['Researcher'], 'resource': 'resource_2', 'action': 'read',
    'path': '/resource-2', 'device_id': 'device-1', 'new_device': False, 'source_ip': '127.0.0.1', 'location': 'LOCAL',
    'authentication_status': 'authenticated',
}
DECISION = {'policy_id': 'P2', 'policy_name': 'Unauthorized resource'}


class TempFolder:
    # A temporary folder that is removed afterwards: `with TempFolder() as folder: ...`
    def __enter__(self):
        self.folder = tempfile.TemporaryDirectory()
        return self.folder.name

    def __exit__(self, *exc):
        self.folder.cleanup()


# --- JSON Lines files -----------------------------------------------------------------

def test_records_are_read_newest_first():
    with TempFolder() as folder:
        path = os.path.join(folder, 'log.jsonl')
        for number in range(5):
            append_record(path, {'n': number})
        assert [record['n'] for record in read_records_backwards(path)] == [4, 3, 2, 1, 0]
        assert [record['n'] for record in read_records(path)] == [0, 1, 2, 3, 4]


def test_reading_backwards_works_across_blocks():
    # Lines longer than in real use, so the file is many 64 KB blocks long
    with TempFolder() as folder:
        path = os.path.join(folder, 'log.jsonl')
        for number in range(3000):
            append_record(path, {'n': number, 'padding': 'x' * 200})
        numbers = [record['n'] for record in read_records_backwards(path)]
        assert numbers == list(range(2999, -1, -1))


def test_a_broken_line_is_skipped():
    with TempFolder() as folder:
        path = os.path.join(folder, 'log.jsonl')
        append_record(path, {'n': 1})
        with open(path, 'a') as file:
            file.write('{"n": 2, "broken\n')  # for example after a crash in the middle of a write
        append_record(path, {'n': 3})
        assert [record['n'] for record in read_records_backwards(path)] == [3, 1]


def test_a_missing_file_has_no_records():
    with TempFolder() as folder:
        assert list(read_records_backwards(os.path.join(folder, 'missing.jsonl'))) == []


def test_ids_are_unique_when_written_at_the_same_time():
    with TempFolder() as folder:
        path = os.path.join(folder, 'requests.jsonl')
        threads = [threading.Thread(target=append_with_next_id, args=(path, {'user': 'bob'})) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        ids = [record['ID'] for record in read_records(path)]
        assert sorted(ids) == list(range(1, 21)), ids


def test_appending_stays_fast_when_the_file_is_big():
    # The old JSON files were rewritten in full on every request, so each request got slower as they grew.
    # Appending one line should take about the same time however big the file is.
    with TempFolder() as folder:
        path = os.path.join(folder, 'audit.log')
        with open(path, 'w') as file:
            file.writelines(json.dumps(dict(REQUEST, n=number)) + '\n' for number in range(20000))
        start = time.perf_counter()
        for _ in range(100):
            append_with_next_id(path, dict(REQUEST))
        milliseconds_each = (time.perf_counter() - start) * 1000 / 100
        assert milliseconds_each < 5, f'{milliseconds_each:.2f} ms per append'


# --- Audit entries ---------------------------------------------------------------------

def test_entry_has_the_task_data_model_fields():
    entry = audit.build_entry('POLICY_VIOLATION', 'Role Researcher may not access resource_2', 'Policy Engine',
                              request=REQUEST, decision=DECISION, trust_score=0.9)
    # Section 4 of the task: the request ...
    assert {key: entry[key] for key in ('user', 'role', 'resource', 'action', 'device_id', 'source_ip')} == {
        'user': 'bob', 'role': 'Researcher', 'resource': 'resource_2', 'action': 'read',
        'device_id': 'device-1', 'source_ip': '127.0.0.1'}
    # ... and the decision, the trust score and the reason
    assert (entry['decision'], entry['trust_score'], entry['reason']) == ('DENY', 0.9, 'Role Researcher may not access resource_2')
    assert (entry['outcome'], entry['policy_id'], entry['decided_by'], entry['request_id']) == ('POLICY_VIOLATION', 'P2', 'Policy Engine', 7)


def test_only_allow_is_an_allow_decision():
    assert audit.build_entry('ALLOW', 'ok', 'Policy Engine')['decision'] == 'ALLOW'
    for outcome in ('DENY', 'AUTHENTICATION_FAILURE', 'POLICY_VIOLATION'):
        assert audit.build_entry(outcome, 'no', 'Web UI')['decision'] == 'DENY'


def test_unknown_outcome_is_refused():
    try:
        audit.build_entry('MAYBE', 'no', 'Web UI')
    except ValueError:
        return
    raise AssertionError('an unknown outcome was accepted')


def test_several_roles_are_joined():
    entry = audit.build_entry('ALLOW', 'ok', 'Policy Engine', request=dict(REQUEST, roles=['Approver', 'Administrator']))
    assert entry['role'] == 'Approver, Administrator' and entry['roles'] == ['Approver', 'Administrator']


def test_an_entry_without_a_user_has_empty_fields():
    entry = audit.build_entry('AUTHENTICATION_FAILURE', 'Not logged in', 'Web UI',
                              request={'path': '/resource-1', 'source_ip': '127.0.0.1'})
    assert entry['user'] is None and entry['role'] is None and entry['trust_score'] is None


def test_read_entries_filters_by_outcome_and_user():
    with TempFolder() as folder:
        path = os.path.join(folder, 'audit.log')
        audit.log_decision('ALLOW', 'ok', 'Policy Engine', path=path, request=REQUEST)
        audit.log_decision('POLICY_VIOLATION', 'no', 'Policy Engine', path=path, request=REQUEST)
        audit.log_decision('AUTHENTICATION_FAILURE', 'no', 'Web UI', path=path, request=dict(REQUEST, username='alice', user_id='u-alice'))
        assert len(audit.read_entries(path=path)) == 3
        assert [entry['outcome'] for entry in audit.read_entries(path=path, user='bob')] == ['POLICY_VIOLATION', 'ALLOW']
        assert [entry['user'] for entry in audit.read_entries(path=path, outcome='AUTHENTICATION_FAILURE')] == ['alice']
        assert len(audit.read_entries(path=path, limit=1)) == 1


def test_find_entry_finds_the_policy_engine_decision():
    with TempFolder() as folder:
        path = os.path.join(folder, 'audit.log')
        audit.log_decision('POLICY_VIOLATION', 'no', 'Policy Engine', path=path, request=REQUEST, decision=DECISION)
        audit.log_decision('ALLOW', 'ok', 'Policy Engine', path=path, request=dict(REQUEST, ID=8))
        assert audit.find_entry(7, path=path)['policy_id'] == 'P2'
        assert audit.find_entry(99, path=path) is None


# --- Failed logins from Keycloak --------------------------------------------------------

EVENTS = [
    {'time': 1000, 'type': 'LOGIN', 'user_id': 'u-bob', 'ip_address': '172.19.0.1'},
    {'time': 2000, 'type': 'LOGIN_ERROR', 'user_id': 'u-bob', 'username': 'bob', 'error': 'invalid_user_credentials',
     'ip_address': '172.19.0.1'},
    {'time': 3000, 'type': 'LOGIN_ERROR', 'user_id': None, 'username': 'mallory', 'error': 'user_not_found',
     'ip_address': '172.19.0.5'},
]


def test_failed_logins_are_copied_once():
    with TempFolder() as folder:
        path, state = os.path.join(folder, 'audit.log'), os.path.join(folder, 'state.json')
        assert audit.import_keycloak_login_errors(EVENTS, path=path, state_file=state) == 2
        assert audit.import_keycloak_login_errors(EVENTS, path=path, state_file=state) == 0  # nothing new
        entries = audit.read_entries(path=path)
        assert [entry['outcome'] for entry in entries] == ['AUTHENTICATION_FAILURE'] * 2
        assert all(entry['decided_by'] == 'Keycloak' for entry in entries)
        newest = entries[0]
        assert newest['user'] == 'mallory' and newest['source_ip'] == '172.19.0.5' and 'user_not_found' in newest['reason']


def test_a_newer_failed_login_is_copied_later():
    with TempFolder() as folder:
        path, state = os.path.join(folder, 'audit.log'), os.path.join(folder, 'state.json')
        audit.import_keycloak_login_errors(EVENTS, path=path, state_file=state)
        newer = EVENTS + [{'time': 4000, 'type': 'LOGIN_ERROR', 'user_id': 'u-bob', 'username': 'bob', 'ip_address': '172.19.0.1'}]
        assert audit.import_keycloak_login_errors(newer, path=path, state_file=state) == 1


if __name__ == '__main__':
    tests = [(name, test) for name, test in sorted(globals().items()) if name.startswith('test_') and callable(test)]
    failed = 0
    for name, test in tests:
        try:
            test()
            print(f"PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {name}  {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
