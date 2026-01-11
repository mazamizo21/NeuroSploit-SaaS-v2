# NeuroSploit SaaS v2 - Kali Executor Container
# 150+ Pentest Tools + Open Interpreter + LM Studio Support

FROM kalilinux/kali-rolling:latest

LABEL maintainer="NeuroSploit SaaS"
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
    smbclient rpcclient \
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
    volatility3 \
    # Disk Forensics
    sleuthkit foremost scalpel photorec \
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

RUN pip3 install --break-system-packages --no-cache-dir \
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
    litellm openai anthropic

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

RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# =============================================================================
# NEUROSPLOIT AI AGENT
# =============================================================================

COPY open-interpreter/config.py /opt/neurosploit/config.py
COPY open-interpreter/agent_wrapper.py /opt/neurosploit/agent_wrapper.py
COPY open-interpreter/dynamic_agent.py /opt/neurosploit/dynamic_agent.py
COPY open-interpreter/llm_client.py /opt/neurosploit/llm_client.py

# Make agent executable
RUN chmod +x /opt/neurosploit/dynamic_agent.py

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
