#!/bin/bash
# Flask-OIDC reads client_secrets.json from the current folder, so start in ZeroTrustWebUI
cd "$(dirname "$0")/../ZeroTrustWebUI" || exit 1
python3 app.py
