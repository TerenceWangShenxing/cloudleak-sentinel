#!/bin/bash
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python3 -m pip install -q -r requirements.txt
exec uvicorn sentinel.api:app --host 127.0.0.1 --port 8000 --reload
