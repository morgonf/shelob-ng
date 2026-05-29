#!/usr/bin/env bash
# 00_check.sh — verify all prerequisites before running scenarios
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; FAILED=1; }

FAILED=0
echo "=== shelob-ng prerequisite check ==="
echo ""

# Go
if command -v go &>/dev/null; then
    VER=$(go version | awk '{print $3}')
    ok "Go: $VER"
else
    fail "Go not found. Install from https://go.dev/dl/"
fi

# Docker
if command -v docker &>/dev/null; then
    VER=$(docker --version | awk '{print $3}' | tr -d ',')
    ok "Docker: $VER"
else
    fail "Docker not found. Install from https://docs.docker.com/get-docker/"
fi

# Docker Compose
if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    VER=$(docker compose version --short 2>/dev/null || echo "v2.x")
    ok "Docker Compose: $VER"
elif command -v docker-compose &>/dev/null; then
    VER=$(docker-compose --version | awk '{print $3}' | tr -d ',')
    ok "docker-compose (v1): $VER"
    warn "Prefer Docker Compose v2 (docker compose)"
else
    fail "Docker Compose not found."
fi

# curl
if command -v curl &>/dev/null; then
    VER=$(curl --version | head -1 | awk '{print $2}')
    ok "curl: $VER"
else
    fail "curl not found. Install via package manager."
fi

# jq (optional but nice)
if command -v jq &>/dev/null; then
    ok "jq: $(jq --version)"
else
    warn "jq not found (optional, used by report.sh for pretty output)"
fi

# python3 (optional, used for JSON pretty-print fallback)
if command -v python3 &>/dev/null; then
    ok "python3: $(python3 --version 2>&1 | awk '{print $2}')"
else
    warn "python3 not found (optional, used for JSON pretty-print)"
fi

echo ""
# Disk space
AVAILABLE=$(df -BG . | awk 'NR==2 {print $4}' | tr -d 'G')
if [ "${AVAILABLE:-0}" -ge 2 ]; then
    ok "Disk space: ${AVAILABLE}G available (need ~1G for Docker image)"
else
    warn "Low disk space: ${AVAILABLE}G available. Docker image is ~400MB."
fi

# Check if Juice Shop is already running
if curl -s --connect-timeout 2 "http://localhost:3000/rest/admin/application-configuration" &>/dev/null; then
    ok "Juice Shop: already running at http://localhost:3000"
else
    warn "Juice Shop: not running. Run 'make start' or 'docker compose up -d'"
fi

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo -e "${RED}Some prerequisites are missing. Fix them before continuing.${NC}"
    exit 1
else
    echo -e "${GREEN}All required prerequisites satisfied.${NC}"
fi
