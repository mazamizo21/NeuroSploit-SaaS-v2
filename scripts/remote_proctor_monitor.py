#!/usr/bin/env python3
"""
Remote Student Proctoring Monitor
For detecting cheating during remote exams
"""

import psutil
import subprocess
import time
import json
from datetime import datetime
import threading
import requests
from pathlib import Path

class RemoteProctorMonitor:
    def __init__(self):
        self.suspicious_activities = []
        self.monitoring = True
        self.start_time = datetime.now()
        
    def check_running_processes(self):
        """Check for suspicious remote desktop processes"""
        suspicious_processes = [
            'teamviewer', 'anydesk', 'chrome-remote-desktop', 
            'vnc', 'rdp', 'remmina', 'nomachine', 'splashtop',
            'gotoassist', 'logmein', 'ammyy', 'supremo'
        ]
        
        found_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                
                for suspicious in suspicious_processes:
                    if suspicious in proc_name or suspicious in cmdline:
                        found_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': proc_info['cmdline'],
                            'detected_at': datetime.now().isoformat()
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return found_processes
    
    def check_network_connections(self):
        """Check for remote desktop network connections"""
        suspicious_ports = [3389, 5900, 5999, 5500, 5656, 5901, 5902]
        suspicious_connections = []
        
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                if conn.raddr.port in suspicious_ports:
                    suspicious_connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status,
                        'detected_at': datetime.now().isoformat()
                    })
        
        return suspicious_connections
    
    def check_browser_tabs(self):
        """Check for remote desktop web services"""
        # This would require browser extension or API access
        # For now, check common remote desktop URLs in browser history
        remote_desktop_urls = [
            'teamviewer.com', 'anydesk.com', 'chrome.google.com/webstore/detail/chrome-remote-desktop',
            'remotedesktop.google.com', 'gotoassist.com', 'logmein.com'
        ]
        
        detected_urls = []
        
        # Check Chrome history (Linux/Mac)
        try:
            chrome_history = Path.home() / ".config/google-chrome/Default/History"
            if chrome_history.exists():
                result = subprocess.run(
                    f"sqlite3 {chrome_history} \"SELECT url FROM urls WHERE url LIKE '%teamviewer%' OR url LIKE '%anydesk%' OR url LIKE '%remotedesktop%'\"",
                    shell=True, capture_output=True, text=True
                )
                if result.stdout.strip():
                    detected_urls.extend(result.stdout.strip().split('\n'))
        except Exception as e:
            pass
            
        return detected_urls
    
    def check_screen_recording(self):
        """Check for screen recording software"""
        recording_processes = [
            'obs', 'screenrecord', 'captura', 'camtasia', 
            'snagit', 'bandicam', 'camstudio', 'screencast'
        ]
        
        found_recording = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                
                for recording in recording_processes:
                    if recording in proc_name or recording in cmdline:
                        found_recording.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': proc_info['cmdline'],
                            'detected_at': datetime.now().isoformat()
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return found_recording
    
    def log_violation(self, violation_type, details):
        """Log violation with timestamp"""
        timestamp = datetime.now().isoformat()
        violation = {
            'timestamp': timestamp,
            'type': violation_type,
            'details': details,
            'session_duration': str(datetime.now() - self.start_time)
        }
        self.suspicious_activities.append(violation)
        
        # Save to log file
        with open("/tmp/student_proctor_log.json", "a") as f:
            f.write(json.dumps(violation) + "\n")
    
    def continuous_monitor(self):
        """Continuous monitoring during exam"""
        while self.monitoring:
            # Check processes
            suspicious_procs = self.check_running_processes()
            if suspicious_procs:
                self.log_violation("remote_desktop_process", suspicious_procs)
            
            # Check network connections
            suspicious_conns = self.check_network_connections()
            if suspicious_conns:
                self.log_violation("remote_desktop_connection", suspicious_conns)
            
            # Check screen recording
            recording_procs = self.check_screen_recording()
            if recording_procs:
                self.log_violation("screen_recording", recording_procs)
            
            time.sleep(10)  # Check every 10 seconds
    
    def generate_proctor_report(self):
        """Generate comprehensive proctoring report"""
        report = {
            'exam_session': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration': str(datetime.now() - self.start_time)
            },
            'total_violations': len(self.suspicious_activities),
            'violation_types': list(set(v['type'] for v in self.suspicious_activities)),
            'violations': self.suspicious_activities,
            'recommendations': self._generate_recommendations()
        }
        return json.dumps(report, indent=2)
    
    def _generate_recommendations(self):
        """Generate recommendations based on violations"""
        recommendations = []
        
        violation_types = set(v['type'] for v in self.suspicious_activities)
        
        if 'remote_desktop_process' in violation_types:
            recommendations.append("Student was running remote desktop software - requires investigation")
        
        if 'remote_desktop_connection' in violation_types:
            recommendations.append("Active remote desktop connections detected - possible external assistance")
        
        if 'screen_recording' in violation_types:
            recommendations.append("Screen recording software detected - possible session sharing")
        
        if not violation_types:
            recommendations.append("No suspicious activity detected")
        
        return recommendations

if __name__ == "__main__":
    print("🎓 Remote Student Proctoring Monitor")
    print("=" * 50)
    print("This monitor will detect:")
    print("• Remote desktop software")
    print("• Remote desktop connections")
    print("• Screen recording software")
    print("• Browser-based remote access")
    print("\nPress Ctrl+C to stop monitoring")
    
    monitor = RemoteProctorMonitor()
    
    # Start monitoring in background
    monitor_thread = threading.Thread(target=monitor.continuous_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nGenerating final report...")
        print("=" * 50)
        print(monitor.generate_proctor_report())
        
        # Save report to file
        with open("/tmp/proctor_report.json", "w") as f:
            f.write(monitor.generate_proctor_report())
        print(f"\nReport saved to: /tmp/proctor_report.json")
