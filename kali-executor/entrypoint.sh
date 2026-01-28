#!/bin/bash
# TazoSploit SaaS v2 - Kali Executor Entrypoint
# Initializes Open Interpreter and waits for jobs

set -e

echo "=============================================="
echo "TazoSploit Kali Executor Starting..."
echo "=============================================="

# Log system info
echo "[INFO] Hostname: $(hostname)"
echo "[INFO] Date: $(date)"
echo "[INFO] Kernel: $(uname -r)"

# Verify critical tools are installed
echo "[INFO] Verifying tool installation..."

CRITICAL_TOOLS=(
    "nmap"
    "sqlmap"
    "hydra"
    "metasploit-framework"
    "nikto"
    "gobuster"
    "crackmapexec"
)

for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null || dpkg -l | grep -q "$tool"; then
        echo "[OK] $tool"
    else
        echo "[WARN] $tool not found"
    fi
done

# Initialize Metasploit database (if installed)
if command -v msfconsole &> /dev/null; then
    mkdir -p /root/.msf4 2>/dev/null || true
    if [ ! -f /root/.msf4/db_initialized ]; then
        echo "[INFO] Initializing Metasploit database..."
        msfdb init 2>/dev/null || true
        touch /root/.msf4/db_initialized 2>/dev/null || true
    fi
fi

# Configure Open Interpreter
echo "[INFO] Configuring Open Interpreter..."
export INTERPRETER_OFFLINE=${INTERPRETER_OFFLINE:-true}
export INTERPRETER_AUTO_RUN=${INTERPRETER_AUTO_RUN:-false}  # Safety: require approval by default

# Set LLM configuration
if [ -n "$LLM_API_BASE" ]; then
    echo "[INFO] LLM API Base: $LLM_API_BASE"
    echo "[INFO] LLM Model: ${LLM_MODEL:-openai/gpt-oss-120b}"
fi

# Create log directory
mkdir -p /pentest/logs

# Start logging
exec > >(tee -a /pentest/logs/executor.log) 2>&1

echo "[INFO] Kali Executor ready for jobs"
echo "=============================================="

# Execute the command passed to docker run
exec "$@"
