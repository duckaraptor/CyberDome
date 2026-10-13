#!/bin/bash
cd "$(dirname "$0")/.." || exit 1
python3 engines/access_proxy.py
