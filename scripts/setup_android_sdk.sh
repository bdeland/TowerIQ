#!/usr/bin/env bash
# setup_android_sdk.sh
#
# One-time setup script: downloads Android SDK command-line tools, installs
# platform-tools (adb), the emulator, and an x86_64 Android 30 system image,
# then creates an AVD named "TowerIQ_Test" for headless CI testing.
#
# Idempotent: safe to run multiple times; already-installed components are skipped.
#
# Usage:
#   bash scripts/setup_android_sdk.sh
#
# After running, add the following to your shell profile (or export before use):
#   export ANDROID_HOME="$HOME/android-sdk"
#   export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
CMDLINE_TOOLS_ZIP="/tmp/cmdline-tools.zip"
SDK_MANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
AVD_MANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
AVD_NAME="TowerIQ_Test"
SYSTEM_IMAGE="system-images;android-30;google_apis;x86_64"

# ── Helpers ──────────────────────────────────────────────────────────────────
info()  { echo "[setup_android_sdk] $*"; }
error() { echo "[setup_android_sdk] ERROR: $*" >&2; exit 1; }

require_cmd() {
    command -v "$1" &>/dev/null || error "Required command '$1' not found. Install it and retry."
}

# ── Pre-flight checks ────────────────────────────────────────────────────────
require_cmd curl
require_cmd unzip
require_cmd java   # Java 11+ required by sdkmanager

JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d. -f1)
if [[ "$JAVA_VERSION" -lt 11 ]]; then
    error "Java 11+ is required (found Java $JAVA_VERSION). Install OpenJDK 11+ and retry."
fi

# ── Install cmdline-tools ────────────────────────────────────────────────────
if [[ -f "$SDK_MANAGER" ]]; then
    info "sdkmanager already present at $SDK_MANAGER — skipping download."
else
    info "Downloading Android cmdline-tools..."
    curl -fsSL "$CMDLINE_TOOLS_URL" -o "$CMDLINE_TOOLS_ZIP"

    info "Extracting to $ANDROID_HOME/cmdline-tools/latest ..."
    mkdir -p "$ANDROID_HOME/cmdline-tools"
    unzip -q "$CMDLINE_TOOLS_ZIP" -d "$ANDROID_HOME/cmdline-tools/tmp"
    # Google zips contain a 'cmdline-tools' subdirectory; rename it to 'latest'
    mv "$ANDROID_HOME/cmdline-tools/tmp/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
    rm -rf "$ANDROID_HOME/cmdline-tools/tmp" "$CMDLINE_TOOLS_ZIP"
    info "cmdline-tools installed."
fi

export ANDROID_HOME
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

# ── Accept licenses ──────────────────────────────────────────────────────────
info "Accepting SDK licenses..."
yes | "$SDK_MANAGER" --licenses > /dev/null 2>&1 || true

# ── Install SDK packages ──────────────────────────────────────────────────────
install_if_missing() {
    local pkg="$1"
    if "$SDK_MANAGER" --list_installed 2>/dev/null | grep -q "$pkg"; then
        info "Already installed: $pkg"
    else
        info "Installing: $pkg"
        yes | "$SDK_MANAGER" "$pkg"
    fi
}

install_if_missing "platform-tools"
install_if_missing "emulator"
install_if_missing "$SYSTEM_IMAGE"

# ── Create AVD ───────────────────────────────────────────────────────────────
if "$AVD_MANAGER" list avd 2>/dev/null | grep -q "Name: $AVD_NAME"; then
    info "AVD '$AVD_NAME' already exists — skipping creation."
else
    info "Creating AVD '$AVD_NAME' (Android 30, x86_64)..."
    echo "no" | "$AVD_MANAGER" create avd \
        --name "$AVD_NAME" \
        --package "$SYSTEM_IMAGE" \
        --device "pixel_3a" \
        --force
    info "AVD '$AVD_NAME' created."
fi

# ── Done ─────────────────────────────────────────────────────────────────────
info ""
info "Setup complete!"
info ""
info "To use the SDK tools, add the following to your shell profile:"
info "  export ANDROID_HOME=\"$ANDROID_HOME\""
info "  export PATH=\"\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/emulator:\$PATH\""
info ""
info "To start the emulator:"
info "  python scripts/start_emulator.py"
info ""
info "To stop the emulator:"
info "  python scripts/stop_emulator.py"
