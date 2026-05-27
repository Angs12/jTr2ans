#!/usr/bin/env python3
"""
Batch extract all BinaryCorp small_test binaries using the r2 pipeline.
Generates _extract.pkl files for all 1584 binaries, then runs pairdata().

Usage:
    python3 datautils/batch_r2.py [--out /path/to/output]
"""
import os
import sys
import subprocess
import multiprocessing
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from datautils.util.pairdata import pairdata

BIN_DIR = "BinaryCorp-Binaries/small_test"
STRIP_DIR = "/tmp/r2_batch_strip"
R2_SCRIPT = "datautils/r2_process.py"


def process_one(binary_path: str, out_dir: str) -> tuple:
    """Run r2_process.py on a single binary. Returns (filename, status)."""
    name = os.path.basename(binary_path)
    os.makedirs(STRIP_DIR, exist_ok=True)
    stripped = os.path.join(STRIP_DIR, name + ".strip")

    try:
        subprocess.run(
            ["strip", "-s", binary_path, "-o", stripped],
            check=True, capture_output=True, timeout=30
        )
    except Exception as e:
        return name, f"STRIP_FAIL: {e}"

    try:
        result = subprocess.run(
            ["python3", R2_SCRIPT, stripped, binary_path, out_dir],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return name, f"R2_FAIL: {result.stderr.strip()[:200]}"
        return name, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return name, "TIMEOUT"
    except Exception as e:
        return name, f"ERROR: {e}"
    finally:
        if os.path.exists(stripped):
            os.remove(stripped)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/tmp/r2_small_test_extract",
                        help="Output directory for _extract.pkl files")
    parser.add_argument("--workers", type=int, default=8,
                        help="Number of parallel workers")
    parser.add_argument("--skip-extract", action="store_true",
                        help="Skip extraction and only run pairdata")
    args = parser.parse_args()

    out_dir = os.path.abspath(args.out)
    bin_dir = os.path.abspath(BIN_DIR)
    r2_script = os.path.abspath(R2_SCRIPT)

    os.makedirs(out_dir, exist_ok=True)
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

    if not args.skip_extract:
        binaries = sorted([
            f for f in os.listdir(bin_dir)
            if os.path.isfile(os.path.join(bin_dir, f))
        ])
        print(f"[+] Found {len(binaries)} binaries in {bin_dir}")

        with multiprocessing.Pool(args.workers) as pool:
            results = pool.starmap(
                process_one,
                [(os.path.join(bin_dir, b), out_dir) for b in binaries]
            )

        # Report results
        ok = [r for r in results if "(+)" in r[1] or "saved" in r[1].lower()]
        fail = [r for r in results if r not in ok]
        print(f"[+] Done: {len(ok)} succeeded, {len(fail)} failed")

        if fail:
            print("[!] Failures:")
            for name, reason in fail[:20]:
                print(f"    {name}: {reason}")

    # Run pairdata
    print("[+] Running pairdata...")
    pairdata(out_dir)
    print(f"[+] Output: {out_dir}/")


if __name__ == "__main__":
    main()
