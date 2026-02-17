#!/usr/bin/env bash
# ============================================================================
# lint_no_target_specific.sh — CI lint to prevent target-specific cheating
# ============================================================================
# TazoSploit is a general-purpose SaaS pentest platform. Production code
# must NEVER contain hardcoded references to specific vulnerable applications.
#
# This script scans production source code for known target-specific terms
# and fails if any are found. Add new terms as needed.
#
# Usage: ./scripts/lint_no_target_specific.sh [--fix]
#   --fix  Show the offending lines (for manual fixing)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Target-specific terms to check ──────────────────────────────────────────
# Case-insensitive patterns. Add new vulnerable apps/CTF platforms here.
PATTERNS=(
    "juice.shop"
    "juiceshop"
    "juice_shop"
    "owasp.juice"
    "bkimminich"          # Juice Shop creator/default user
    "juice-sh\.op"        # Juice Shop email domain
    "dvwa"
    "damn.vulnerable"
    "dvna"
    "webgoat"
    "metasploitable"
    "hackthebox"
    "vulnhub"
    "tryhackme"
    "pentesterlab"
)

# ── Production directories to scan ──────────────────────────────────────────
PROD_DIRS=(
    "kali-executor/open-interpreter"
    "control-plane"
    "frontend/src"
)

# ── Excluded paths (tests, configs, docs) ───────────────────────────────────
EXCLUDE_PATTERNS=(
    "*/tests/*"
    "*/test_*"
    "*/__pycache__/*"
    "*/node_modules/*"
    "*/.git/*"
    "*/vulnerable-lab/*"
    "*/venv/*"
    "*/.venv*"
    "*/CONTRIBUTING.md"
    "*/lint_no_target_specific.sh"
)

# ── Build grep pattern ──────────────────────────────────────────────────────
GREP_PATTERN=""
for p in "${PATTERNS[@]}"; do
    if [[ -z "$GREP_PATTERN" ]]; then
        GREP_PATTERN="$p"
    else
        GREP_PATTERN="$GREP_PATTERN|$p"
    fi
done

# ── Build exclude args ──────────────────────────────────────────────────────
EXCLUDE_ARGS=""
for e in "${EXCLUDE_PATTERNS[@]}"; do
    EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude=$e"
done

# ── Scan ────────────────────────────────────────────────────────────────────
FOUND=0
TOTAL_HITS=0

echo "🔍 Scanning production code for target-specific references..."
echo ""

for dir in "${PROD_DIRS[@]}"; do
    full_path="$PROJECT_ROOT/$dir"
    if [[ ! -d "$full_path" ]]; then
        continue
    fi

    # grep for patterns, excluding test files and known exceptions
    HITS=$(grep -rn -i -E "$GREP_PATTERN" "$full_path" \
        --include="*.py" --include="*.ts" --include="*.tsx" --include="*.js" \
        --include="*.jsx" --include="*.json" --include="*.yaml" --include="*.yml" \
        ${EXCLUDE_ARGS} \
        2>/dev/null || true)

    if [[ -n "$HITS" ]]; then
        COUNT=$(echo "$HITS" | wc -l | tr -d ' ')
        TOTAL_HITS=$((TOTAL_HITS + COUNT))
        FOUND=1
        echo "❌ Found $COUNT target-specific reference(s) in $dir:"
        echo "$HITS" | while IFS= read -r line; do
            echo "   $line"
        done
        echo ""
    fi
done

# ── Result ──────────────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FOUND -eq 1 ]]; then
    echo "❌ FAILED: Found $TOTAL_HITS target-specific reference(s) in production code."
    echo ""
    echo "TazoSploit is a general-purpose SaaS pentest platform."
    echo "Production code must NOT contain hardcoded references to specific"
    echo "vulnerable applications (Juice Shop, DVWA, etc)."
    echo ""
    echo "See CONTRIBUTING.md for guidelines on writing general pentest logic."
    echo ""
    echo "Checked patterns: ${PATTERNS[*]}"
    exit 1
else
    echo "✅ PASSED: No target-specific references found in production code."
    exit 0
fi
