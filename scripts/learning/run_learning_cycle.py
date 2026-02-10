#!/usr/bin/env python3
"""
Run the full daily learning cycle:
1) Run the lab benchmark and write learning gate
2) Reflect on short-term memory and promote long-term learnings
"""

import json
import os
import subprocess
import sys


def _script_path(name: str) -> str:
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(here, name)


def main():
    env = os.environ.copy()

    benchmark_script = _script_path("daily_benchmark.py")
    reflect_script = _script_path("reflect_memory.py")

    result = {"benchmark": None, "reflection": None}

    bench = subprocess.run([sys.executable, benchmark_script], env=env, capture_output=True, text=True)
    if bench.returncode != 0:
        print(bench.stderr.strip() or bench.stdout.strip())
        raise SystemExit(bench.returncode)
    try:
        result["benchmark"] = json.loads(bench.stdout.strip().splitlines()[-1])
    except Exception:
        result["benchmark"] = {"raw_output": bench.stdout.strip()}

    reflect = subprocess.run([sys.executable, reflect_script], env=env, capture_output=True, text=True)
    if reflect.returncode != 0:
        print(reflect.stderr.strip() or reflect.stdout.strip())
        raise SystemExit(reflect.returncode)
    try:
        result["reflection"] = json.loads(reflect.stdout.strip().splitlines()[-1])
    except Exception:
        result["reflection"] = {"raw_output": reflect.stdout.strip()}

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
