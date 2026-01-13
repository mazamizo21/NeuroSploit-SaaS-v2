#!/usr/bin/env python3
"""
Student Lab Remote Desktop Detection Dashboard
For educational integrity monitoring
"""

import subprocess
import json
import time
from datetime import datetime
import socket
import threading

class StudentLabMonitor:
    def __init__(self):
        self.suspicious_activities = []
        self.monitoring = True
        
    def scan_remote_desktop_ports(self, network_range="192.168.1.0/24"):
        """Scan for open remote desktop ports"""
        try:
            result = subprocess.run(
                f"nmap -sS -p 3389,5900-5999 {network_range}",
                shell=True, capture_output=True, text=True, timeout=60
            )
            return result.stdout
        except Exception as e:
            return f"Error scanning: {e}"
    
    def check_processes(self):
        """Check for remote desktop processes"""
        try:
            result = subprocess.run(
                "ps aux | grep -E '(vnc|rdp|teamviewer|anydesk|chrome-remote-desktop)' | grep -v grep",
                shell=True, capture_output=True, text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error checking processes: {e}"
    
    def monitor_network_connections(self):
        """Monitor active remote desktop connections"""
        try:
            result = subprocess.run(
                "netstat -tuln | grep -E '(3389|590[0-9])'",
                shell=True, capture_output=True, text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error monitoring connections: {e}"
    
    def log_suspicious_activity(self, activity_type, details):
        """Log suspicious activity"""
        timestamp = datetime.now().isoformat()
        activity = {
            "timestamp": timestamp,
            "type": activity_type,
            "details": details
        }
        self.suspicious_activities.append(activity)
        
        # Also log to file
        with open("/var/log/student_lab_suspicious.log", "a") as f:
            f.write(f"{json.dumps(activity)}\n")
    
    def continuous_monitor(self):
        """Continuous monitoring loop"""
        while self.monitoring:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Check processes
            processes = self.check_processes()
            if processes.strip():
                self.log_suspicious_activity("remote_desktop_process", processes)
            
            # Check network connections
            connections = self.monitor_network_connections()
            if connections.strip():
                self.log_suspicious_activity("remote_desktop_connection", connections)
            
            time.sleep(30)  # Check every 30 seconds
    
    def generate_report(self):
        """Generate detection report"""
        report = {
            "scan_time": datetime.now().isoformat(),
            "total_suspicious_activities": len(self.suspicious_activities),
            "activities": self.suspicious_activities
        }
        return json.dumps(report, indent=2)

if __name__ == "__main__":
    monitor = StudentLabMonitor()
    
    print("Starting Student Lab Remote Desktop Monitor...")
    print("Press Ctrl+C to stop monitoring")
    
    # Start continuous monitoring in background
    monitor_thread = threading.Thread(target=monitor.continuous_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.monitoring = False
        print("Final Report:")
        print(monitor.generate_report())
