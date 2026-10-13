#!/bin/bash
# Settings and secrets come from the repo root's env file (see cyberdome/settings.py)
cd "$(dirname "$0")/../web" || exit 1
python3 app.py
