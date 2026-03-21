# Emulator Setup for TowerIQ Testing

This document covers two paths for running TowerIQ against an Android emulator:

1. **Linux (CI / Claude autonomous testing)** – Android SDK AVD (headless)
2. **Windows (your dev machine)** – MuMu Player 12

---

## Linux – Android SDK AVD

The AVD is a transparent substitute for MuMu Player.  TowerIQ's ADB layer
connects to both the same way.

### Prerequisites

| Tool | Notes |
|------|-------|
| Java 11+ | `sudo apt install openjdk-17-jdk` |
| curl, unzip | Standard distro packages |
| KVM acceleration | `sudo apt install qemu-kvm && sudo usermod -aG kvm $USER` (log out/in) |

### One-time setup

```bash
bash scripts/setup_android_sdk.sh
```

This downloads the Android SDK command-line tools, installs `platform-tools`
(adb), the `emulator`, and an `x86_64 Android 30` system image, and creates an
AVD named **TowerIQ_Test**.

After setup, add to `~/.bashrc` (or `~/.zshrc`):

```bash
export ANDROID_HOME="$HOME/android-sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
```

### Start the emulator

```bash
python scripts/start_emulator.py
# Prints the ADB serial when the device is ready, e.g.:  emulator-5554
```

### Stop the emulator

```bash
python scripts/stop_emulator.py
```

### Run integration tests against the live emulator

```bash
pytest -m adb -v
```

The `live_emulator` session fixture in `tests/conftest.py` auto-starts the AVD
and tears it down after the test session.  If the Android SDK is not installed,
those tests are automatically **skipped** (not failed).

---

## Windows – MuMu Player 12

### Install MuMu Player

Download from the official MuMu Player website and install normally.

### Find the ADB port

MuMu Player 12 exposes each emulator instance on a fixed TCP port:

| Instance | ADB port |
|----------|----------|
| First (default) | 16384 |
| Second | 16386 |
| Third | 16388 |

Older MuMu versions used **7555**.

You can verify the port in MuMu Player → Settings → ADB Debugging.

### Connect TowerIQ to MuMu Player

```cmd
# In a Command Prompt / PowerShell:
adb connect 127.0.0.1:16384
adb devices          # should show 127.0.0.1:16384  device
```

TowerIQ will discover the device automatically on the next refresh
(`POST /api/devices/refresh`) because network devices in `ip:port` format are
already supported by `EmulatorService`.

### ADB path for MuMu Player

MuMu Player ships its own `adb.exe`. Add it to `PATH`, or use the one from the
Android SDK:

```
C:\Program Files\MuMu\emulator\nemu\vmonitor\bin\adb_server.exe
```

---

## Compatibility: Linux AVD vs Windows MuMu Player

TowerIQ communicates with the emulator exclusively through:

1. **ADB** – identical protocol on both platforms
2. **Frida** – the frida-server binary is downloaded per-architecture
   (`x86_64` for the Linux AVD, `x86_64` for MuMu Player on a 64-bit Windows
   host); `FridaManager` handles this automatically
3. **Shell commands** – same Android shell regardless of host OS

Any behaviour verified against the Linux AVD will work identically against
MuMu Player, because the underlying Android OS and ADB/Frida interfaces are
the same.  The only difference is **how you connect** (TCP port).

### Credentials and the game

Installing the game and logging in with your Google / game account is a
**manual, one-time step** performed inside the emulator UI — it cannot and
should not be automated through TowerIQ.  Once the game is installed and
you are logged in, TowerIQ attaches to the running process via Frida and
reads data without touching your credentials.

Steps:
1. Start MuMu Player (Windows) or `python scripts/start_emulator.py` (Linux)
2. Inside the emulator, open Google Play and install **The Tower**
3. Log in with your game account
4. In TowerIQ, refresh devices and connect to the emulator
5. Select the `com.TowerKeeper` (or equivalent) process and activate the hook
