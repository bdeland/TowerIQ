#!/usr/bin/env python3
"""
stop_emulator.py

Cleanly shuts down a running Android emulator used for TowerIQ testing.

Usage:
    python scripts/stop_emulator.py [--serial emulator-5554]

If --serial is omitted, the first online emulator-* device found in
`adb devices` is targeted.

Environment:
    ANDROID_HOME  – root of Android SDK installation (default: ~/android-sdk)

Exit codes:
    0  emulator stopped (or was not running)
    1  error during shutdown
"""

import argparse
import os
import subprocess
import sys


def _resolve_adb(android_home: str) -> str:
    candidate = os.path.join(android_home, "platform-tools", "adb")
    return candidate if os.path.isfile(candidate) else "adb"


def _adb(*args, android_home: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_resolve_adb(android_home), *args],
        capture_output=True,
        text=True,
    )


def _find_emulator_serial(android_home: str) -> str | None:
    result = _adb("devices", android_home=android_home)
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("emulator-") and parts[1] == "device":
            return parts[0]
    return None


def main():
    parser = argparse.ArgumentParser(description="Stop Android emulator used for TowerIQ testing.")
    parser.add_argument("--serial", default=None, help="ADB serial of emulator to stop (default: auto-detect)")
    args = parser.parse_args()

    android_home = os.environ.get("ANDROID_HOME", os.path.expanduser("~/android-sdk"))

    serial = args.serial or _find_emulator_serial(android_home)
    if not serial:
        print("[stop_emulator] No running emulator found — nothing to do.", file=sys.stderr)
        return 0

    print(f"[stop_emulator] Sending 'emu kill' to {serial}...", file=sys.stderr)
    result = _adb("-s", serial, "emu", "kill", android_home=android_home)
    if result.returncode != 0:
        print(f"[stop_emulator] ERROR: {result.stderr.strip()}", file=sys.stderr)
        return 1

    print(f"[stop_emulator] {serial} stopped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
