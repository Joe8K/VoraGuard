#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV="$DIR/.env"
if [[ ! -f "$ENV" ]]; then
    echo "⚠  .env not found at $ENV"
    return 1
fi
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue
    [[ "$line" != *"="* ]] && continue
    key="${line%%=*}"
    val="${line#*=}"
    val="$(echo "$val" | sed 's/[[:space:]]*#.*$//' | tr -d '\r' | xargs 2>/dev/null || echo "$val")"
    [[ -z "$val" ]] && continue
    export "${key}=${val}" 2>/dev/null || true
done < "$ENV"
echo "✓ VoraGuard environment loaded"
