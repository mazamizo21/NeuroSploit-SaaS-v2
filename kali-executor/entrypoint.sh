#!/bin/bash
# TazoSploit SaaS v2 - Kali Executor Entrypoint
# Supports two modes:
#   --server  : Start the agent API server (for HTTP-based job dispatch)
#   (default) : Keep container alive for exec-into mode

set -e

echo "=============================================="
echo "TazoSploit Kali Executor Starting..."
echo "=============================================="

# Log system info
echo "[INFO] Hostname: $(hostname)"
echo "[INFO] Date: $(date)"
echo "[INFO] Kernel: $(uname -r)"
echo "[INFO] Mode: ${1:-exec-into}"

# ── Install Python Dependencies ──────────────────────────────────────────────
echo "[INFO] Installing Python dependencies..."
pip3 install --quiet --no-cache-dir --break-system-packages \
    requests httpx litellm openai anthropic \
    beautifulsoup4 lxml \
    2>/dev/null || {
    echo "[WARN] pip install failed — some features may be limited"
}

# Ensure open-interpreter deps are available
if [ -f /opt/open-interpreter/requirements.txt ]; then
    pip3 install --quiet --no-cache-dir --break-system-packages -r /opt/open-interpreter/requirements.txt 2>/dev/null || true
fi

# ── Verify Critical Tools ────────────────────────────────────────────────────
echo "[INFO] Verifying tool installation..."

CRITICAL_TOOLS=(
    "nmap"
    "sqlmap"
    "nikto"
    "gobuster"
    "curl"
    "python3"
)

OPTIONAL_TOOLS=(
    "hydra"
    "metasploit-framework"
    "crackmapexec"
    "searchsploit"
)

for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "[OK]   $tool"
    else
        echo "[MISS] $tool — attempting install..."
        apt-get install -y "$tool" 2>/dev/null || echo "[WARN] Could not install $tool"
    fi
done

for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null || dpkg -l 2>/dev/null | grep -q "$tool"; then
        echo "[OK]   $tool"
    else
        echo "[SKIP] $tool (optional)"
    fi
done

# ── Initialize Metasploit Database (if installed) ────────────────────────────
if command -v msfconsole &> /dev/null; then
    mkdir -p /root/.msf4 2>/dev/null || true
    if [ ! -f /root/.msf4/db_initialized ]; then
        echo "[INFO] Initializing Metasploit database..."
        msfdb init 2>/dev/null || true
        touch /root/.msf4/db_initialized 2>/dev/null || true
    fi
fi

# ── Configure LLM ───────────────────────────────────────────────────────────
echo "[INFO] LLM Configuration:"
echo "[INFO]   API Base: ${LLM_API_BASE:-not set}"
echo "[INFO]   Model: ${LLM_MODEL:-not set}"

# ── Create Working Directories ──────────────────────────────────────────────
mkdir -p /pentest/logs /pentest/output /pentest/evidence /pentest/memory

# ── Start Logging ───────────────────────────────────────────────────────────
exec > >(tee -a /pentest/logs/executor.log) 2>&1

echo "[INFO] Kali Executor ready"
echo "=============================================="

# ── Mode Selection ──────────────────────────────────────────────────────────
case "${1:-}" in
    --server)
        echo "[INFO] Starting agent API server on port 9000..."
        # Start a simple HTTP server that accepts job requests
        python3 -c "
import http.server
import json
import subprocess
import threading

class AgentHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/execute':
            content_len = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(content_len))
            
            target = body.get('target', '')
            objective = body.get('objective', 'Full security assessment')
            output_dir = body.get('output_dir', '/pentest/output')
            max_iters = body.get('max_iterations', 25)
            
            cmd = [
                'python3', '/opt/open-interpreter/dynamic_agent.py',
                '--target', target,
                '--objective', objective,
                '--output-dir', output_dir,
                '--max-iterations', str(max_iters)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            response = {
                'stdout': result.stdout[-5000:],
                'stderr': result.stderr[-2000:],
                'exit_code': result.returncode
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
    
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')

server = http.server.HTTPServer(('0.0.0.0', 9000), AgentHandler)
print('[INFO] Agent API server listening on :9000')
server.serve_forever()
" &
        # Also keep the container alive
        exec tail -f /dev/null
        ;;
    "")
        # Default: exec-into mode — just keep the container alive
        echo "[INFO] Running in exec-into mode. Container will stay alive."
        echo "[INFO] Use: docker exec <container> python3 /opt/open-interpreter/dynamic_agent.py --target <ip> --objective '...'"
        exec tail -f /dev/null
        ;;
    *)
        # Execute whatever was passed
        exec "$@"
        ;;
esac
