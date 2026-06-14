#!/usr/bin/env bash
# VoraGuard Scan Launcher v3.0
# Usage:
#   ./scan.sh example.com              ← domain scan (active)
#   ./scan.sh example.com --passive    ← domain scan (passive, no nmap)
#   ./scan.sh 45.33.32.156             ← IP scan (auto-detected)
#   ./scan.sh --ip 45.33.32.156        ← IP scan (explicit)
#   ./scan.sh example.com --json       ← JSON output

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source load_env.sh 2>/dev/null || true

if [[ -z "$1" ]]; then
    echo ""
    echo "  Usage:"
    echo "    ./scan.sh example.com              # Domain scan (active)"
    echo "    ./scan.sh example.com --passive    # Domain scan (passive)"
    echo "    ./scan.sh 45.33.32.156             # IP address scan"
    echo "    ./scan.sh --ip 45.33.32.156        # IP scan (explicit)"
    echo "    ./scan.sh example.com --json       # JSON output"
    echo ""
    exit 1
fi

# Auto-detect if first arg is IP address
TARGET="$1"
shift
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    python3 voraguard.py --ip "$TARGET" "$@"
elif [[ "$TARGET" == "--ip" ]]; then
    python3 voraguard.py --ip "$1" "${@:2}"
else
    python3 voraguard.py --domain "$TARGET" "$@"
fi
