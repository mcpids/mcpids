#!/usr/bin/env bash
# run-threat-scenarios.sh - executes all 8 threat scenario unit tests.
# Usage: ./scripts/run-threat-scenarios.sh
set -euo pipefail

echo "Running MCPIDS threat scenario tests..."
echo ""

cd "$(git rev-parse --show-toplevel)"

go test -v -run "TestThreatScenarios" ./tests/unit/... 2>&1

echo ""
echo "All threat scenario tests complete."
