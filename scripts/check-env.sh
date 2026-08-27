#!/usr/bin/env bash
# Specula pre-flight environment check.
#
# Validates that all REQUIRED environment variables are present and non-empty
# before running the stack. Source the resulting `.env` first, or run as-is
# after copying `.env.example` to `.env`.
#
# Usage:
#   ./scripts/check-env.sh            # checks .env file in repo root
#   MONGO_USERNAME=... ./scripts/check-env.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# If a .env file exists, export it so the required-variable checks below see it.
if [ -f "$ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
fi

REQUIRED_VARS=(
    "MONGO_USERNAME"
    "MONGO_PASSWORD"
    "API_KEY"
)

FAIL=0
for var in "${REQUIRED_VARS[@]}"; do
    val="${!var:-}"
    if [ -z "$val" ]; then
        echo "MISSING: $var"
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then
    echo
    echo "One or more required environment variables are missing."
    echo "Copy .env.example to .env and fill in the values, then re-run."
    echo "Generate an API_KEY with: openssl rand -hex 32"
    exit 1
fi

echo "All required environment variables present."
exit 0
