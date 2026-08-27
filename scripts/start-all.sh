#!/bin/bash

# Specula Startup Script (local development, non-Docker)
# Starts all services in the correct order.
#
# NOTE: The recommended way to run Specula is `docker-compose up` after copying
# `.env.example` to `.env` and filling in credentials. This script is an
# alternative for running the services directly on the host.

set -e

echo "Specula Platform starting..."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Resolve the repository root regardless of the current working directory.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load local environment (credentials) if present.
if [ -f "$ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
fi

# MongoDB credentials and API key are required (production-safe fail-fast).
if [ -z "${MONGO_USERNAME:-}" ] || [ -z "${MONGO_PASSWORD:-}" ]; then
    echo -e "${RED}MONGO_USERNAME and MONGO_PASSWORD must be set (see .env.example).${NC}" >&2
    exit 1
fi
if [ -z "${API_KEY:-}" ]; then
    echo -e "${RED}API_KEY must be set (see .env.example).${NC}" >&2
    exit 1
fi
export MONGO_URI="mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@localhost:27017/specula?authSource=admin"
export API_KEY

echo -e "${YELLOW}Checking MongoDB...${NC}"
if ! pgrep -x "mongod" > /dev/null; then
    echo -e "${YELLOW}Starting MongoDB with auth...${NC}"
    mkdir -p "$ROOT/data/db"
    mongod --dbpath "$ROOT/data/db" --fork --logpath "$ROOT/data/mongod.log" --auth
    sleep 2
fi

start_service() {
    local name=$1
    local dir=$2
    local command=$3
    echo -e "${YELLOW}Starting ${name}...${NC}"
    (cd "$dir" && eval "$command") &
    echo -e "${GREEN}${name} started${NC}"
}

start_service "Network Service" "$ROOT/backend/services/network" "python3 app.py"
start_service "Code Service" "$ROOT/backend/services/code" "python3 app.py"
start_service "DAST Service" "$ROOT/backend/services/dast" "python3 app.py"

sleep 3

start_service "Gateway" "$ROOT/backend/gateway" "npm start"

sleep 2

echo ""
echo -e "${GREEN}All services started!${NC}"
echo ""
echo "Dashboard: http://localhost:3001"
echo "Gateway API: http://localhost:3000"
echo "Network Service: http://localhost:5001"
echo "Code Service: http://localhost:5002"
echo "DAST Service: http://localhost:5003"
echo ""
echo "Press Ctrl+C to stop all services"

cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping all services...${NC}"
    kill $(jobs -p) 2>/dev/null || true
    echo -e "${GREEN}All services stopped${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

wait
