#!/usr/bin/env bash
# Run every test: unit scenarios, edge cases, in-process smoke.
set -euo pipefail
cd "$(dirname "$0")"
echo "=== RFC 8032 / primitive correctness is exercised inside the suites ==="
python3 tests/smoke_e2e.py
python3 -m unittest tests.test_ceremonies tests.test_edge tests.test_authz tests.test_drills tests.test_archive tests.test_transparency tests.test_budgets
echo "=== HTTP e2e (login gates + four-eyes tickets + concurrent approve) ==="
python3 tests/http_e2e.py "${1:-8301}"
echo "=== cross-region DR drill HTTP e2e (scan/blueprint/resume/mirror/lease/evidence) ==="
python3 tests/drill_http_e2e.py "${2:-8302}"
echo "=== transparency HTTP e2e (proofs + browser recomputation + split freeze/resolve) ==="
python3 tests/transparency_http_e2e.py "${3:-8303}"
echo "=== signing-quota budget HTTP e2e (orders/reservation/takeover/archive) ==="
python3 tests/budget_http_e2e.py "${5:-8305}"
echo "=== transparency browser e2e (badge/member-path/chain/reload/tamper/fork recovery) ==="
python3 tests/transparency_browser_e2e.py "${4:-8304}"
echo "ALL TESTS PASSED"
