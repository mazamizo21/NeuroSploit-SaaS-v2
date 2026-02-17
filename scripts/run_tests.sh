#!/usr/bin/env bash
# ============================================================================
# run_tests.sh — TazoSploit test runner
# ============================================================================
# Usage:
#   ./scripts/run_tests.sh              # Run all tests (unit + integration)
#   ./scripts/run_tests.sh unit         # Run only unit tests
#   ./scripts/run_tests.sh integration  # Run only integration tests
#   ./scripts/run_tests.sh e2e          # Run only E2E tests (needs services)
#   ./scripts/run_tests.sh all          # Run everything including E2E
#   ./scripts/run_tests.sh --coverage   # Run with coverage report
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Activate venv ────────────────────────────────────────────────────────────
if [[ -f "$VENV_DIR/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    echo -e "${CYAN}🐍 Activated venv: $(python3 --version) at $VENV_DIR${NC}"
else
    echo -e "${YELLOW}⚠️  No venv found at $VENV_DIR — using system Python${NC}"
fi

# ── Ensure pytest is available ───────────────────────────────────────────────
if ! command -v pytest &>/dev/null && ! python3 -m pytest --version &>/dev/null 2>&1; then
    echo -e "${RED}❌ pytest not found. Install: pip install pytest pytest-cov${NC}"
    exit 1
fi

# ── Parse arguments ──────────────────────────────────────────────────────────
SUITE="${1:-default}"
COVERAGE=false
PYTEST_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --coverage|-c)
            COVERAGE=true
            ;;
        unit|integration|e2e|all|default)
            SUITE="$arg"
            ;;
        *)
            PYTEST_ARGS+=("$arg")
            ;;
    esac
done

# ── Build pytest command ─────────────────────────────────────────────────────
cd "$PROJECT_ROOT"

PYTEST_CMD=(python3 -m pytest)
PYTEST_CMD+=(-v --tb=short -x)

# Add paths based on suite
case "$SUITE" in
    unit)
        echo -e "${CYAN}🧪 Running UNIT tests...${NC}"
        PYTEST_CMD+=(tests/unit/)
        ;;
    integration)
        echo -e "${CYAN}🧪 Running INTEGRATION tests...${NC}"
        PYTEST_CMD+=(tests/integration/)
        ;;
    e2e)
        echo -e "${CYAN}🧪 Running E2E tests...${NC}"
        PYTEST_CMD+=(tests/e2e/ -m e2e)
        ;;
    all)
        echo -e "${CYAN}🧪 Running ALL tests (unit + integration + e2e)...${NC}"
        PYTEST_CMD+=(tests/)
        ;;
    default)
        echo -e "${CYAN}🧪 Running unit + integration tests (skip E2E)...${NC}"
        PYTEST_CMD+=(tests/unit/ tests/integration/)
        ;;
esac

# Add coverage if requested
if [[ "$COVERAGE" == "true" ]]; then
    PYTEST_CMD+=(
        --cov=kali-executor/open-interpreter
        --cov=control-plane
        --cov-report=term-missing
        --cov-report=html:htmlcov
        --cov-config=.coveragerc
    )
    echo -e "${CYAN}📊 Coverage reporting enabled${NC}"
fi

# Add any extra args
PYTEST_CMD+=("${PYTEST_ARGS[@]}")

# ── Run ──────────────────────────────────────────────────────────────────────
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Command: ${PYTEST_CMD[*]}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

EXIT_CODE=0
"${PYTEST_CMD[@]}" || EXIT_CODE=$?

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
else
    echo -e "${RED}❌ Tests failed (exit code: $EXIT_CODE)${NC}"
fi

if [[ "$COVERAGE" == "true" && $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}📊 Coverage report: htmlcov/index.html${NC}"
fi
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exit $EXIT_CODE
