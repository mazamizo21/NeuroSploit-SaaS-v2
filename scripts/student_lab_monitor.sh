#!/bin/bash
# Student Lab Remote Desktop Detection Script
# For educational integrity monitoring

LOG_FILE="/var/log/student_lab_monitor.log"
NETWORK_RANGE="192.168.1.0/24"

echo "=== Student Lab Remote Desktop Monitor ===" | tee -a "$LOG_FILE"
echo "Scan started: $(date)" | tee -a "$LOG_FILE"

# Network scan for remote desktop services
echo "Scanning network for remote desktop services..." | tee -a "$LOG_FILE"
nmap -sS -p 3389,5900-5999 "$NETWORK_RANGE" | tee -a "$LOG_FILE"

# Check for running remote desktop processes
echo "Checking for remote desktop processes..." | tee -a "$LOG_FILE"
ps aux | grep -E "(vnc|rdp|teamviewer|anydesk|chrome-remote-desktop)" | grep -v grep | tee -a "$LOG_FILE"

# Monitor network connections
echo "Active remote desktop connections:" | tee -a "$LOG_FILE"
netstat -tuln | grep -E "(3389|590[0-9])" | tee -a "$LOG_FILE"

# Check for installed remote desktop software
echo "Installed remote desktop software:" | tee -a "$LOG_FILE"
find /usr/bin /usr/local/bin -name "*vnc*" -o -name "*teamviewer*" -o -name "*anydesk*" 2>/dev/null | tee -a "$LOG_FILE"

echo "Scan completed: $(date)" | tee -a "$LOG_FILE"
echo "=========================================" | tee -a "$LOG_FILE"
