#!/usr/bin/env bash
# verify-tools.sh — Verify all Sliver C2 + evasion tools are present and working.
# Used by Docker HEALTHCHECK and by the agent before starting jobs.
# Exit 0 = all good, Exit 1 = something missing.

set -euo pipefail

PASS=0
FAIL=0
WARN=0

check_bin() {
    local name="$1"
    local path="$2"
    if [ -x "$path" ]; then
        echo "  [OK]   $name  ($path)"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name  ($path not found or not executable)"
        FAIL=$((FAIL + 1))
    fi
}

check_dir() {
    local name="$1"
    local path="$2"
    if [ -d "$path" ]; then
        echo "  [OK]   $name  ($path)"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name  ($path not found)"
        FAIL=$((FAIL + 1))
    fi
}

check_python_module() {
    local name="$1"
    if python3 -c "import $name" 2>/dev/null; then
        echo "  [OK]   Python: $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] Python: $name (import failed)"
        FAIL=$((FAIL + 1))
    fi
}

check_version() {
    local name="$1"
    local cmd="$2"
    local output
    if output=$(eval "$cmd" 2>&1); then
        echo "  [OK]   $name version: $output"
        PASS=$((PASS + 1))
    else
        echo "  [WARN] $name version check failed (binary exists but may need config)"
        WARN=$((WARN + 1))
    fi
}

echo "============================================="
echo "  TazoSploit Tool Verification"
echo "  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================="
echo ""

# --- Sliver C2 ---
echo "[Sliver C2]"
check_bin "sliver-client" "/usr/local/bin/sliver-client"
check_version "sliver-client" "sliver-client version 2>/dev/null | head -1"
echo ""

# --- Go Toolchain ---
echo "[Go Toolchain]"
check_bin "go" "/usr/local/go/bin/go"
check_version "go" "go version | awk '{print \$3}'"
echo ""

# --- ScareCrow ---
echo "[ScareCrow (EDR Bypass)]"
check_bin "ScareCrow" "/usr/local/bin/ScareCrow"
check_dir "ScareCrow source" "/opt/ScareCrow"
echo ""

# --- Donut ---
echo "[Donut (PE-to-Shellcode)]"
check_bin "donut" "/usr/local/bin/donut"
check_dir "Donut source" "/opt/donut"
echo ""

# --- SharpCollection ---
echo "[SharpCollection (.NET Offensive Tools)]"
check_dir "SharpCollection" "/opt/sharp-collection"
echo ""

# --- Python Modules ---
echo "[Python Modules]"
check_python_module "sliver"
check_python_module "grpc"
check_python_module "google.protobuf"
check_python_module "donut"
echo ""

# --- Directory Structure ---
echo "[Directory Structure]"
check_dir "Golden implants (windows/x64)" "/opt/sliver/golden/windows/x64"
check_dir "Golden implants (linux/x64)" "/opt/sliver/golden/linux/x64"
check_dir "Golden implants (shellcode)" "/opt/sliver/golden/shellcode"
check_dir "Sliver configs" "/opt/sliver/configs"
check_dir "Evasion scripts" "/opt/tazosploit/evasion"
echo ""

# --- Cross-compilation deps ---
echo "[Cross-Compilation Dependencies]"
check_bin "x86_64-w64-mingw32-gcc" "$(command -v x86_64-w64-mingw32-gcc 2>/dev/null || echo /usr/bin/x86_64-w64-mingw32-gcc)"
check_bin "osslsigncode" "$(command -v osslsigncode 2>/dev/null || echo /usr/bin/osslsigncode)"
echo ""

# --- Summary ---
echo "============================================="
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings"
echo "============================================="

if [ "$FAIL" -gt 0 ]; then
    echo "  STATUS: UNHEALTHY — $FAIL tool(s) missing"
    exit 1
fi

if [ "$WARN" -gt 0 ]; then
    echo "  STATUS: DEGRADED — tools present but $WARN version check(s) failed"
    exit 0
fi

echo "  STATUS: HEALTHY — all tools verified"
exit 0
