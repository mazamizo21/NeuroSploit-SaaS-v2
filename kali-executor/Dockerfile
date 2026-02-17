# TazoSploit  v2 - Kali Executor Container
# 150+ Pentest Tools + Open Interpreter + LM Studio Support

FROM kalilinux/kali-rolling:latest

LABEL maintainer="TazoSploit "
LABEL description="Kali Linux with 150+ tools for AI-powered pentesting"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# =============================================================================
# SYSTEM UPDATES AND BASE PACKAGES
# =============================================================================

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    curl wget git vim tmux screen \
    python3 python3-pip python3-venv \
    build-essential libssl-dev libffi-dev \
    rustc cargo \
    && apt-get clean

# =============================================================================
# RECONNAISSANCE TOOLS (25+)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network Scanning
    nmap masscan unicornscan netdiscover arp-scan \
    # DNS Enumeration
    dnsrecon dnsenum fierce dnsmap dnsutils \
    # Subdomain Discovery
    subfinder amass sublist3r \
    # OSINT
    theharvester recon-ng maltego \
    # Web Reconnaissance
    whatweb wafw00f \
    # Information Gathering
    whois dmitry p0f \
    && apt-get clean

# =============================================================================
# VULNERABILITY SCANNING TOOLS (20+)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Web Vulnerability Scanners
    nikto wpscan joomscan \
    # Application Scanners
    sqlmap commix \
    # SSL/TLS Testing
    sslscan sslyze \
    # Fuzzing
    wfuzz ffuf gobuster dirb dirbuster \
    && apt-get clean

# Install nuclei from apt (Kali has it)
RUN apt-get update && apt-get install -y nuclei || true

# =============================================================================
# EXPLOITATION TOOLS (30+)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Frameworks
    metasploit-framework \
    # Web Exploitation
    burpsuite zaproxy \
    # Network Exploitation
    responder bettercap ettercap-common \
    # Exploit Tools
    exploitdb \
    # Wireless (if needed)
    aircrack-ng wifite reaver \
    # Password Attacks
    hydra medusa ncrack crowbar patator \
    && apt-get clean

# =============================================================================
# POST-EXPLOITATION TOOLS (25+)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Remote Access
    crackmapexec evil-winrm \
    smbclient \
    # Impacket Suite
    impacket-scripts python3-impacket \
    # Persistence
    weevely \
    && apt-get clean

# =============================================================================
# CREDENTIAL ATTACK TOOLS (15+)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Password Cracking
    john hashcat hashid hash-identifier \
    # Wordlist Generation
    cewl crunch cupp \
    # Hash Tools
    hashcat-utils ophcrack \
    && apt-get clean

# =============================================================================
# FORENSICS & ANALYSIS TOOLS (20+)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Memory Forensics
    # volatility (via pip/git usually)
    # Disk Forensics
    sleuthkit foremost scalpel testdisk \
    # Network Forensics
    wireshark-common tcpdump tshark \
    # Malware Analysis
    yara clamav radare2 binwalk \
    # Log Analysis
    logwatch \
    && apt-get clean

# =============================================================================
# UTILITY TOOLS (15+)
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Networking
    netcat-traditional ncat socat proxychains4 tor \
    # Fonts for PDF report generation
    fonts-dejavu-core \
    # Scripting
    ruby perl \
    # File Transfer
    openssh-client rsync \
    # Misc
    jq xmlstarlet \
    && apt-get clean

# =============================================================================
# PYTHON TOOLS AND LIBRARIES
# =============================================================================

# Fix for Python 3.13 / PyO3 / tiktoken compatibility
ENV PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1

RUN pip3 install --break-system-packages --ignore-installed --no-cache-dir \
    # Open Interpreter
    open-interpreter \
    # Pentest Libraries
    pwntools impacket scapy paramiko \
    requests beautifulsoup4 lxml \
    # Credential Tools
    pypykatz lsassy \
    # Utilities
    colorama tqdm rich \
    httpx aiohttp \
    redis \
    # Knowledge graph (Sprint 2)
    neo4j \
    # LLM Integration
    litellm openai "anthropic>=0.45.0" \
    # Skills metadata parsing
    pyyaml \
    # TOON compact serialization (~40% token savings)
    toon-format \
    # Professional PDF report generation
    fpdf2

# =============================================================================
# ADDITIONAL TOOLS FROM GITHUB
# =============================================================================

# PEASS-ng (linpeas, winpeas)
RUN git clone --depth=1 https://github.com/carlospolop/PEASS-ng.git /opt/PEASS-ng

# LaZagne (password recovery)
RUN git clone --depth=1 https://github.com/AlessandroZ/LaZagne.git /opt/LaZagne

# Windows Exploit Suggester
RUN git clone --depth=1 https://github.com/bitsadmin/wesng.git /opt/wesng

# Linux Exploit Suggester
RUN git clone --depth=1 https://github.com/mzet-/linux-exploit-suggester.git /opt/linux-exploit-suggester

# SecLists wordlists
RUN git clone --depth=1 https://github.com/danielmiessler/SecLists.git /opt/SecLists && \
    ln -sf /opt/SecLists /usr/share/seclists

# PayloadsAllTheThings
RUN git clone --depth=1 https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/PayloadsAllTheThings

# =============================================================================
# WORDLISTS SETUP
# =============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends wordlists 2>/dev/null || true && \
    gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true && \
    apt-get clean

# =============================================================================
# TAZOSPLOIT AI AGENT
# =============================================================================

# Copy default credential wordlists (small, fast — no brute-force)
COPY wordlists/ /opt/tazosploit/wordlists/

# Copy ALL files from open-interpreter/ into the image
COPY open-interpreter/ /opt/tazosploit/

# Verify the copy got everything (build will fail if dynamic_agent.py is missing)
RUN ls -la /opt/tazosploit/ && \
    test -f /opt/tazosploit/dynamic_agent.py && \
    test -f /opt/tazosploit/llm_providers.py && \
    test -f /opt/tazosploit/config.py && \
    echo "✓ All agent files present"

# Symlink for backward compat (both paths work)
RUN ln -sf /opt/tazosploit /opt/open-interpreter

# Make agent executable
RUN chmod +x /opt/tazosploit/dynamic_agent.py

# Expose helper tools expected by the agent prompt
RUN ln -sf /opt/tazosploit/tools/websearch.py /usr/local/bin/websearch && \
    ln -sf /opt/tazosploit/tools/docslookup.py /usr/local/bin/docslookup && \
    ln -sf /opt/tazosploit/tools/download.py /usr/local/bin/download

# Install any agent-specific requirements
RUN if [ -f /opt/tazosploit/requirements.txt ]; then \
        pip3 install --break-system-packages --no-cache-dir -r /opt/tazosploit/requirements.txt; \
    fi

# =============================================================================
# SLIVER C2 CLIENT (v1.7.1 — arm64)
# =============================================================================

RUN curl -sSL -o /usr/local/bin/sliver-client \
    "https://github.com/BishopFox/sliver/releases/download/v1.7.1/sliver-client_linux-arm64" && \
    chmod +x /usr/local/bin/sliver-client && \
    echo "✓ Sliver client v1.7.1 (linux-arm64) installed"

# =============================================================================
# SLIVER PYTHON (gRPC programmatic interaction)
# =============================================================================

RUN pip3 install --break-system-packages --no-cache-dir \
    sliver-py grpcio protobuf && \
    echo "✓ sliver-py + gRPC installed"

# =============================================================================
# GO TOOLCHAIN (1.22.12 — needed for ScareCrow build)
# =============================================================================

ENV GO_VERSION=1.22.12
RUN curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" | tar -C /usr/local -xzf - && \
    echo "✓ Go ${GO_VERSION} (linux-arm64) installed"
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# =============================================================================
# SCARECROW (EDR bypass loader — built from source with Go)
# =============================================================================

# mingw-w64 + osslsigncode needed for ScareCrow's Windows DLL cross-compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    mingw-w64 osslsigncode openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/Tylous/ScareCrow.git /opt/ScareCrow && \
    cd /opt/ScareCrow && \
    go build -o /usr/local/bin/ScareCrow . && \
    echo "✓ ScareCrow built and installed"

# =============================================================================
# DONUT (PE → shellcode converter with AMSI/ETW bypass)
# =============================================================================

RUN arch="$(uname -m)" && \
    git clone --depth=1 https://github.com/TheWover/donut.git /opt/donut && \
    cd /opt/donut && \
    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then \
        make && \
        cp /opt/donut/donut /usr/local/bin/donut && \
        chmod +x /usr/local/bin/donut && \
        echo "✓ Donut compiled and installed"; \
    else \
        echo "⚠️ Donut build skipped on arch=$arch (upstream ships x86_64-only aplib libs; arm64 build fails)"; \
    fi

# Donut Python module (for programmatic shellcode generation)
RUN arch="$(uname -m)" && \
    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then \
        pip3 install --break-system-packages --no-cache-dir donut-shellcode && \
        echo "✓ donut-shellcode Python module installed"; \
    else \
        echo "⚠️ donut-shellcode skipped on arch=$arch (no arm64 wheel; build fails due to x86_64-only aplib libs)"; \
    fi

# =============================================================================
# SHARP COLLECTION (pre-compiled .NET offensive tools for execute-assembly)
# =============================================================================

RUN git clone --depth=1 https://github.com/Flangvik/SharpCollection.git /opt/sharp-collection && \
    echo "✓ SharpCollection cloned to /opt/sharp-collection"

# =============================================================================
# GOLDEN IMPLANTS DIRECTORY (pre-built implant library)
# =============================================================================

RUN mkdir -p \
    /opt/sliver/golden/windows/x64 \
    /opt/sliver/golden/windows/x86 \
    /opt/sliver/golden/linux/x64 \
    /opt/sliver/golden/linux/arm64 \
    /opt/sliver/golden/shellcode \
    /opt/sliver/configs && \
    echo "✓ Golden implants directory structure created"

# =============================================================================
# EVASION SCRIPTS DIRECTORY
# =============================================================================

RUN mkdir -p /opt/tazosploit/evasion && \
    echo "✓ Evasion scripts directory created"

# =============================================================================
# TOOL VERIFICATION SCRIPTS
# =============================================================================

COPY scripts/verify-tools.sh /opt/tazosploit/scripts/verify-tools.sh
COPY scripts/tools-update.sh /opt/tazosploit/scripts/tools-update.sh

# C2 helper scripts (referenced by C2PhaseGate + DynamicAgent policy prompts)
COPY scripts/*.py /opt/tazosploit/scripts/

RUN chmod +x /opt/tazosploit/scripts/*.sh /opt/tazosploit/scripts/*.py

# =============================================================================
# SLIVER + EVASION TOOLCHAIN VERIFICATION (build fails if anything missing)
# =============================================================================

RUN echo "=== Verifying Sliver + Evasion Toolchain ===" && \
    arch="$(uname -m)" && \
    test -x /usr/local/bin/sliver-client && echo "  ✓ sliver-client" && \
    test -x /usr/local/bin/ScareCrow     && echo "  ✓ ScareCrow" && \
    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then \
        test -x /usr/local/bin/donut && echo "  ✓ donut"; \
    else \
        echo "  ⚠️ donut skipped (arch=$arch)"; \
    fi && \
    test -x /usr/local/go/bin/go         && echo "  ✓ Go toolchain" && \
    test -d /opt/sharp-collection        && echo "  ✓ SharpCollection" && \
    test -d /opt/ScareCrow               && echo "  ✓ ScareCrow source" && \
    test -d /opt/donut                   && echo "  ✓ Donut source" && \
    test -d /opt/sliver/golden           && echo "  ✓ Golden implants dir" && \
    test -d /opt/tazosploit/evasion      && echo "  ✓ Evasion scripts dir" && \
    python3 -c "import sliver; print('  ✓ sliver-py')" && \
    python3 -c "import grpc; print('  ✓ grpcio')" && \
    if [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; then \
        python3 -c "import donut; print('  ✓ donut-shellcode')"; \
    else \
        echo "  ⚠️ donut-shellcode skipped (arch=$arch)"; \
    fi && \
    sliver-client version 2>/dev/null || true && \
    go version && \
    echo "=== All Sliver + Evasion tools verified ==="

# =============================================================================
# ENTRYPOINT AND WORKING DIRECTORY
# =============================================================================

WORKDIR /pentest

# Create output directories
RUN mkdir -p /pentest/output /pentest/logs /pentest/artifacts

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
