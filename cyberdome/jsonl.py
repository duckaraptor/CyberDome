'''

Files with one JSON object per line ("JSON Lines"), used for the audit log and the
access requests.

New records are only appended, never rewritten, so writing takes the same time however
big the file is. A file lock (fcntl.flock) stops the Web UI and the engines, which are
separate processes, from writing at the same moment. Reading goes backwards from the end
of the file, so the newest records can be read without loading the whole file.

'''
import fcntl
import json
import os

BLOCK_SIZE = 64 * 1024


def append_record(path, record):
    # Add one record as one line at the end of the file
    line = json.dumps(record) + '\n'
    with open(path, 'a') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        try:
            file.write(line)
            file.flush()
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)
    return record


def append_with_next_id(path, record, id_key='ID'):
    # Give the record the ID after the last record's ID, and append it. The lock is held from reading
    # the last ID to writing, so two processes can't give out the same ID.
    with open(path, 'a+') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        try:
            last = next(read_records_backwards(path), None)
            record[id_key] = (last or {}).get(id_key, 0) + 1
            file.write(json.dumps(record) + '\n')
            file.flush()
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)
    return record


def read_lines_backwards(path):
    # The file's lines from the last to the first, read in blocks from the end
    if not os.path.exists(path):
        return
    with open(path, 'rb') as file:
        file.seek(0, os.SEEK_END)
        position = file.tell()
        rest = b''
        while position > 0:
            size = min(BLOCK_SIZE, position)
            position -= size
            file.seek(position)
            block = file.read(size) + rest
            lines = block.split(b'\n')
            rest = lines.pop(0)  # may be the end of a line that continues in the previous block
            for line in reversed(lines):
                if line.strip():
                    yield line.decode('utf-8')
        if rest.strip():
            yield rest.decode('utf-8')


def read_records_backwards(path):
    # The records from the newest to the oldest. A broken line (for example after a crash) is skipped.
    for line in read_lines_backwards(path):
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def read_records(path):
    # All records, oldest first
    return list(reversed(list(read_records_backwards(path))))
