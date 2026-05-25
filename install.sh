#!/bin/bash
set -e

GREEN="[0;32m"
YELLOW="[0;33m"
RED="[0;31m"
NC="[0m"

HERMES_SKILLS_DIR="${HERMES_HOME:-$HOME/.hermes}/skills"

echo ""
echo -e "${GREEN}EntropyGuard for Hermes${NC} - Security Skill Installer"
echo ""

if ! command -v hermes &> /dev/null; then
    echo -e "${RED}Error:${NC} hermes not found. Install Hermes first."
    exit 1
fi

echo -e "${GREEN}OK${NC} Hermes found"

if curl -s http://127.0.0.1:8000/api/health --connect-timeout 3 | grep -q "healthy"; then
    echo -e "${GREEN}OK${NC} EntropyGuard is healthy"
else
    echo -e "${YELLOW}WARN${NC} EntropyGuard not reachable at http://127.0.0.1:8000"
    echo "  Commands will be blocked until EntropyGuard is started (Fail-Closed)."
fi

echo -e "${GREEN}->${NC} Installing entropy-guard skill..."
mkdir -p "$HERMES_SKILLS_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR/skills/entropy-guard" "$HERMES_SKILLS_DIR/"

echo -e "${GREEN}OK${NC} Skill installed to $HERMES_SKILLS_DIR/entropy-guard/"
echo ""
echo -e "${GREEN}Installation complete.${NC}"
echo "Test: hermes -z Check if rm -rf is safe using entropy_guard_check"
echo ""
