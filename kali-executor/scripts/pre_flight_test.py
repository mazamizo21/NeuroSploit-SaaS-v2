#!/usr/bin/env python3
"""pre_flight_test.py — Pre-flight payload testing before delivery.

Tests a payload against ThreatCheck, entropy analysis, and optional
Defender scan before sending it to the target. Prevents wasting
exploits on payloads that will be immediately caught.

Usage:
    python3 pre_flight_test.py /tmp/payload.dll
    python3 pre_flight_test.py /tmp/payload.exe --strict
    python3 pre_flight_test.py /tmp/payload.bin --json

Outputs:
    - Pass/fail verdict with details
    - Optional JSON report
"""

# This is a standalone script; its functions are named `test_*` as payload checks,
# not as pytest tests. When collected by pytest it errors due to missing fixtures.
if __name__ != "__main__":
    try:
        import sys as _sys

        if "pytest" in _sys.modules:
            import pytest  # type: ignore

            pytest.skip(
                "Standalone script (not a pytest module). Run directly: python3 pre_flight_test.py <payload>",
                allow_module_level=True,
            )
    except Exception:
        pass

import argparse
import json
import logging
import math
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("pre_flight_test")

# Entropy thresholds
ENTROPY_WARN = 7.5   # Elevated — heuristics may flag
ENTROPY_FAIL = 7.9   # Almost certainly flagged by heuristic engines

# File size thresholds (suspiciously small payloads)
MIN_PAYLOAD_SIZE = 1024  # 1KB — anything smaller is probably broken


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def test_threatcheck(payload_path: str) -> dict:
    """Run ThreatCheck against the payload."""
    result = {
        "tool": "ThreatCheck",
        "status": "skipped",
        "output": "",
    }

    threatcheck_bin = None
    for candidate in ["/usr/local/bin/ThreatCheck", "/opt/ThreatCheck/ThreatCheck"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            threatcheck_bin = candidate
            break

    if not threatcheck_bin:
        log.info("ThreatCheck not found, skipping")
        return result

    try:
        proc = subprocess.run(
            [threatcheck_bin, "-f", payload_path, "-e", "AMSI"],
            capture_output=True, text=True, timeout=60,
        )
        result["output"] = proc.stdout.strip()
        result["stderr"] = proc.stderr.strip()

        if "No threat found" in proc.stdout or proc.returncode == 0:
            result["status"] = "clean"
            log.info("ThreatCheck: CLEAN")
        else:
            result["status"] = "detected"
            # Try to extract the detection offset
            for line in proc.stdout.splitlines():
                if "offset" in line.lower() or "byte" in line.lower():
                    result["detection_detail"] = line.strip()
                    break
            log.warning(f"ThreatCheck: DETECTED — {result.get('detection_detail', 'see output')}")
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        log.warning("ThreatCheck timed out")
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log.warning(f"ThreatCheck error: {e}")

    return result


def test_entropy(payload_path: str) -> dict:
    """Analyze file entropy to predict heuristic detection."""
    result = {
        "tool": "entropy_analysis",
        "status": "skipped",
    }

    try:
        with open(payload_path, "rb") as f:
            data = f.read()

        entropy = calculate_entropy(data)
        result["entropy"] = entropy
        result["file_size"] = len(data)

        if len(data) < MIN_PAYLOAD_SIZE:
            result["status"] = "warn"
            result["note"] = f"Payload suspiciously small ({len(data)} bytes)"
            log.warning(f"Entropy: {entropy} — file too small ({len(data)} bytes)")
        elif entropy > ENTROPY_FAIL:
            result["status"] = "fail"
            result["note"] = f"Entropy {entropy} > {ENTROPY_FAIL} — will likely trigger heuristics"
            log.warning(f"Entropy: {entropy} — HIGH (likely flagged)")
        elif entropy > ENTROPY_WARN:
            result["status"] = "warn"
            result["note"] = f"Entropy {entropy} > {ENTROPY_WARN} — may trigger heuristics"
            log.info(f"Entropy: {entropy} — elevated but may pass")
        else:
            result["status"] = "clean"
            result["note"] = f"Entropy {entropy} — within normal range"
            log.info(f"Entropy: {entropy} — OK")

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log.error(f"Entropy analysis error: {e}")

    return result


def test_file_signature(payload_path: str) -> dict:
    """Check for known bad signatures in the payload header."""
    result = {
        "tool": "signature_check",
        "status": "clean",
        "findings": [],
    }

    try:
        with open(payload_path, "rb") as f:
            header = f.read(4096)

        # Check for obvious patterns that AV signatures catch
        bad_patterns = [
            (b"This program cannot be run in DOS mode", "DOS stub detected (normal for PE)"),
            (b"MZARUH", "Suspicious MZ+shellcode header pattern"),
        ]

        # Check for UPX packing (heavily signatured)
        if b"UPX0" in header or b"UPX1" in header or b"UPX!" in header:
            result["findings"].append("UPX packing detected — heavily signatured by AV")
            result["status"] = "warn"

        for pattern, note in bad_patterns:
            if pattern in header:
                result["findings"].append(note)

        # Check for Metasploit patterns (common AV sigs)
        msf_patterns = [
            b"\xfc\xe8\x82\x00\x00\x00",  # Metasploit shellcode stub
            b"\xfc\xe8\x89\x00\x00\x00",  # Metasploit reverse_tcp
        ]
        for p in msf_patterns:
            if p in header:
                result["findings"].append("Metasploit shellcode signature detected")
                result["status"] = "detected"
                break

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def test_payload(
    payload_path: str,
    strict: bool = False,
) -> dict:
    """Run all pre-flight tests on a payload.

    Returns a comprehensive test report with an overall verdict.
    """
    start_time = time.time()

    report = {
        "payload_path": payload_path,
        "payload_size": os.path.getsize(payload_path) if os.path.isfile(payload_path) else 0,
        "tests": {},
        "verdict": "UNKNOWN",
        "tested_at": datetime.now(timezone.utc).isoformat(),
    }

    if not os.path.isfile(payload_path):
        report["verdict"] = "ERROR"
        report["error"] = f"Payload file not found: {payload_path}"
        return report

    # Run tests
    log.info(f"Pre-flight testing: {payload_path}")

    report["tests"]["threatcheck"] = test_threatcheck(payload_path)
    report["tests"]["entropy"] = test_entropy(payload_path)
    report["tests"]["signatures"] = test_file_signature(payload_path)

    # Determine verdict
    has_detection = False
    has_warning = False

    for test_name, test_result in report["tests"].items():
        status = test_result.get("status", "skipped")
        if status == "detected":
            has_detection = True
        elif status == "fail":
            has_detection = True
        elif status == "warn":
            has_warning = True

    if has_detection:
        report["verdict"] = "FAIL"
    elif has_warning and strict:
        report["verdict"] = "FAIL"
    elif has_warning:
        report["verdict"] = "WARN"
    else:
        report["verdict"] = "CLEAN"

    report["test_time_s"] = round(time.time() - start_time, 2)

    log.info(f"Pre-flight verdict: {report['verdict']} ({report['test_time_s']}s)")
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Pre-flight test a payload before delivery to target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Verdicts:
  CLEAN    — All tests passed, safe to deliver
  WARN     — Some warnings but may still succeed
  FAIL     — Payload will likely be detected, regenerate with different evasion
  ERROR    — Test infrastructure issue

Examples:
  %(prog)s /tmp/payload.dll
  %(prog)s /tmp/payload.exe --strict --json
  %(prog)s /tmp/shellcode.bin --save-report /pentest/output/job1/preflight.json
        """,
    )

    parser.add_argument("payload", help="Path to the payload to test")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as failures")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--save-report", default=None,
                        help="Save test report to specified path")

    args = parser.parse_args()
    report = test_payload(args.payload, strict=args.strict)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        verdict = report["verdict"]
        symbol = {"CLEAN": "[+]", "WARN": "[!]", "FAIL": "[-]", "ERROR": "[X]"}.get(verdict, "[?]")
        print(f"\n{symbol} Pre-Flight Verdict: {verdict}")
        print(f"    Payload: {report['payload_path']}")
        print(f"    Size: {report['payload_size']} bytes")
        print(f"    Test Time: {report.get('test_time_s', '?')}s")

        for test_name, test_result in report.get("tests", {}).items():
            status = test_result.get("status", "skipped")
            icon = {"clean": "+", "detected": "!", "fail": "!", "warn": "~", "skipped": "-"}.get(status, "?")
            print(f"    [{icon}] {test_name}: {status}")
            if test_result.get("entropy"):
                print(f"        Entropy: {test_result['entropy']}")
            if test_result.get("note"):
                print(f"        {test_result['note']}")
            if test_result.get("detection_detail"):
                print(f"        Detail: {test_result['detection_detail']}")
            if test_result.get("findings"):
                for f in test_result["findings"]:
                    print(f"        - {f}")

        if verdict == "FAIL":
            print("\n    Recommendation: Regenerate payload with different evasion techniques.")
        elif verdict == "WARN":
            print("\n    Recommendation: Proceed with caution, or regenerate for higher confidence.")

    # Save report
    if args.save_report:
        os.makedirs(os.path.dirname(args.save_report) or ".", exist_ok=True)
        with open(args.save_report, "w") as f:
            json.dump(report, f, indent=2)
        log.info(f"Report saved to {args.save_report}")

    # Exit code based on verdict
    if report["verdict"] == "FAIL":
        sys.exit(1)
    elif report["verdict"] == "ERROR":
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
