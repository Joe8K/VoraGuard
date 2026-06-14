#!/usr/bin/env bash
# Start VoraGuard web dashboard
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/load_env.sh" 2>/dev/null || true
echo "Starting VoraGuard Web Dashboard..."
echo "Open browser: http://localhost:5000"
python3 voraguard.py --web
