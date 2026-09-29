#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf /tmp/cloudleak-history-demo /tmp/cloudleak-demo-artifacts
python3 scripts/create_demo_git_repo.py /tmp/cloudleak-history-demo >/dev/null
python3 scripts/create_demo_packages.py /tmp/cloudleak-demo-artifacts >/dev/null

echo "[1/5] local synthetic config"
python3 -m sentinel.cli scan /tmp/cloudleak-demo-artifacts/demo-local.env >/dev/null

echo "[2/5] Git credential lifecycle"
python3 -m sentinel.cli scan-git-history /tmp/cloudleak-history-demo --max-commits 20 >/dev/null

echo "[3/5] Docker image layers"
python3 -m sentinel.cli scan-docker /tmp/cloudleak-demo-artifacts/demo-image.tar >/dev/null

echo "[4/5] APK"
python3 -m sentinel.cli scan-mobile /tmp/cloudleak-demo-artifacts/demo-app.apk >/dev/null

echo "[5/5] mini-program package"
python3 -m sentinel.cli scan-mobile /tmp/cloudleak-demo-artifacts/demo-miniprogram.zip >/dev/null

echo "Done. Open http://127.0.0.1:8000/ while the API server is running."
