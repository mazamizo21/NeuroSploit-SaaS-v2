#!/usr/bin/env python3
"""
Advanced Mac VNC Connection Manager
For UltraVNC connections with various options
"""

import subprocess
import sys
import json
from pathlib import Path

class MacVNCManager:
    def __init__(self):
        self.connections = self.load_connections()
    
    def load_connections(self):
        """Load saved connections"""
        config_file = Path.home() / ".vnc_connections.json"
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_connections(self):
        """Save connections to file"""
        config_file = Path.home() / ".vnc_connections.json"
        with open(config_file, 'w') as f:
            json.dump(self.connections, f, indent=2)
    
    def connect_builtin(self, ip, port=5900, password=None):
        """Connect using macOS built-in Screen Sharing"""
        try:
            url = f"vnc://{ip}:{port}"
            subprocess.run(['open', url], check=True)
            print(f"Connected to {ip}:{port} using built-in Screen Sharing")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to connect: {e}")
            return False
    
    def connect_tigervnc(self, ip, port=5900, password=None):
        """Connect using TigerVNC viewer"""
        try:
            cmd = ['vncviewer', f'{ip}::{port}']
            if password:
                cmd.extend(['-password', password])
            subprocess.run(cmd, check=True)
            print(f"Connected to {ip}:{port} using TigerVNC")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to connect: {e}")
            return False
    
    def test_connection(self, ip, port=5900):
        """Test if VNC port is accessible"""
        try:
            result = subprocess.run(
                ['nc', '-zv', ip, str(port)],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                print(f"✅ Port {port} is open on {ip}")
                return True
            else:
                print(f"❌ Port {port} is closed on {ip}")
                return False
        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            return False
    
    def scan_vnc_ports(self, ip_range):
        """Scan for VNC services on network"""
        print(f"Scanning {ip_range} for VNC services...")
        
        # Split IP range (simple /24 scanning)
        base_ip = '.'.join(ip_range.split('.')[:-1])
        
        open_ports = []
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if self.test_connection(ip):
                open_ports.append(ip)
        
        return open_ports
    
    def save_connection(self, name, ip, port=5900, password=None):
        """Save connection details"""
        self.connections[name] = {
            'ip': ip,
            'port': port,
            'password': password
        }
        self.save_connections()
        print(f"Saved connection '{name}'")
    
    def list_connections(self):
        """List saved connections"""
        if not self.connections:
            print("No saved connections")
            return
        
        print("Saved VNC Connections:")
        print("-" * 40)
        for name, details in self.connections.items():
            print(f"{name}: {details['ip']}:{details['port']}")
    
    def quick_connect(self, name):
        """Quick connect to saved connection"""
        if name not in self.connections:
            print(f"Connection '{name}' not found")
            return False
        
        details = self.connections[name]
        return self.connect_builtin(details['ip'], details['port'])
    
    def create_connection_script(self, name, ip, port=5900):
        """Create a double-clickable connection script"""
        script_content = f'''#!/bin/bash
# Auto-connect to {name}
open "vnc://{ip}:{port}"
'''
        
        script_path = Path.home() / f"connect_{name.lower().replace(' ', '_')}.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Make executable
        script_path.chmod(0o755)
        print(f"Created connection script: {script_path}")

def main():
    manager = MacVNCManager()
    
    if len(sys.argv) < 2:
        print("Mac VNC Connection Manager")
        print("Usage:")
        print("  python3 mac_vnc_advanced.py connect <IP> [PORT]")
        print("  python3 mac_vnc_advanced.py test <IP> [PORT]")
        print("  python3 mac_vnc_advanced.py scan <IP_RANGE>")
        print("  python3 mac_vnc_advanced.py save <NAME> <IP> [PORT]")
        print("  python3 mac_vnc_advanced.py list")
        print("  python3 mac_vnc_advanced.py quick <NAME>")
        return
    
    command = sys.argv[1]
    
    if command == "connect":
        if len(sys.argv) < 3:
            print("Usage: connect <IP> [PORT]")
            return
        ip = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 5900
        manager.connect_builtin(ip, port)
    
    elif command == "test":
        if len(sys.argv) < 3:
            print("Usage: test <IP> [PORT]")
            return
        ip = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 5900
        manager.test_connection(ip, port)
    
    elif command == "scan":
        if len(sys.argv) < 3:
            print("Usage: scan <IP_RANGE>")
            return
        ip_range = sys.argv[2]
        open_ports = manager.scan_vnc_ports(ip_range)
        if open_ports:
            print("Found VNC services:")
            for ip in open_ports:
                print(f"  {ip}")
    
    elif command == "save":
        if len(sys.argv) < 4:
            print("Usage: save <NAME> <IP> [PORT]")
            return
        name = sys.argv[2]
        ip = sys.argv[3]
        port = int(sys.argv[4]) if len(sys.argv) > 4 else 5900
        manager.save_connection(name, ip, port)
    
    elif command == "list":
        manager.list_connections()
    
    elif command == "quick":
        if len(sys.argv) < 3:
            print("Usage: quick <NAME>")
            return
        name = sys.argv[2]
        manager.quick_connect(name)
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
