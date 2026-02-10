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
    # LLM Integration
    litellm openai "anthropic>=0.45.0" \
    # Skills metadata parsing
    pyyaml

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
RUN git clone --depth=1 https://github.com/danielmiessler/SecLists.git /opt/SecLists

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
