#!/usr/bin/env python3
"""
start_emulator.py

Starts the TowerIQ_Test AVD headlessly and waits until the device has fully
booted before exiting.  Prints the ADB serial (e.g. "emulator-5554") to stdout
on success so callers can capture it.

Usage:
    python scripts/start_emulator.py [--avd NAME] [--timeout SECONDS]

Environment:
    ANDROID_HOME  – root of Android SDK installation (default: ~/android-sdk)

Exit codes:
    0  emulator booted successfully
    1  emulator failed to start or timed out
"""

import argparse
import os
import subprocess
import sys
import time

# ── Configuration ─────────────────────────────────────────────────────────────
DEFAULT_AVD = "TowerIQ_Test"
DEFAULT_TIMEOUT = 180  # seconds
POLL_INTERVAL = 3      # seconds between boot-complete checks
ADB_PORT = 5554        # default emulator ADB port


def _resolve_binary(name: str, android_home: str) -> str:
    """Return the full path to an Android SDK binary, or the bare name if not found."""
    candidates = [
        os.path.join(android_home, "emulator", name),
        os.path.join(android_home, "platform-tools", name),
        os.path.join(android_home, "cmdline-tools", "latest", "bin", name),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return name  # fall back to PATH lookup


def _adb(*args, android_home: str) -> subprocess.CompletedProcess:
    adb = _resolve_binary("adb", android_home)
    return subprocess.run([adb, *args], capture_output=True, text=True)


def _is_booted(serial: str, android_home: str) -> bool:
    result = _adb("-s", serial, "shell", "getprop", "sys.boot_completed", android_home=android_home)
    return result.returncode == 0 and result.stdout.strip() == "1"


def _find_emulator_serial(android_home: str) -> str | None:
    """Return the serial of the first online emulator device, or None."""
    result = _adb("devices", android_home=android_home)
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("emulator-") and parts[1] == "device":
            return parts[0]
    return None


def main():
    parser = argparse.ArgumentParser(description="Start Android emulator for TowerIQ testing.")
    parser.add_argument("--avd", default=DEFAULT_AVD, help="AVD name to start")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Boot timeout in seconds")
    args = parser.parse_args()

    android_home = os.environ.get("ANDROID_HOME", os.path.expanduser("~/android-sdk"))
    emulator_bin = _resolve_binary("emulator", android_home)

    # ── Check if an emulator is already running ───────────────────────────────
    existing = _find_emulator_serial(android_home)
    if existing:
        print(f"[start_emulator] Emulator already running: {existing}", file=sys.stderr)
        print(existing)
        return 0

    # ── Launch emulator ───────────────────────────────────────────────────────
    print(f"[start_emulator] Starting AVD '{args.avd}'...", file=sys.stderr)
    env = {**os.environ, "ANDROID_HOME": android_home}
    emulator_proc = subprocess.Popen(
        [
            emulator_bin,
            "-avd", args.avd,
            "-no-window",
            "-no-audio",
            "-no-snapshot",
            "-no-boot-anim",
            "-gpu", "swiftshader_indirect",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # ── Wait for ADB to recognise the device ─────────────────────────────────
    deadline = time.monotonic() + args.timeout
    serial: str | None = None

    print("[start_emulator] Waiting for device to appear in adb devices...", file=sys.stderr)
    while time.monotonic() < deadline:
        serial = _find_emulator_serial(android_home)
        if serial:
            break
        time.sleep(POLL_INTERVAL)
    else:
        print(f"[start_emulator] ERROR: Emulator did not appear within {args.timeout}s.", file=sys.stderr)
        emulator_proc.terminate()
        return 1

    # ── Wait for full boot ────────────────────────────────────────────────────
    print(f"[start_emulator] Device {serial} found. Waiting for boot to complete...", file=sys.stderr)
    while time.monotonic() < deadline:
        if _is_booted(serial, android_home):
            print(f"[start_emulator] {serial} is ready.", file=sys.stderr)
            print(serial)  # <- stdout: captured by callers / pytest fixture
            return 0
        time.sleep(POLL_INTERVAL)

    print(f"[start_emulator] ERROR: Boot did not complete within {args.timeout}s.", file=sys.stderr)
    emulator_proc.terminate()
    return 1


if __name__ == "__main__":
    sys.exit(main())
