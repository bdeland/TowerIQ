#!/usr/bin/env python3
"""
Test script to check device connectivity and ADB functionality
"""

import asyncio
import sys
import subprocess
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def test_device_connectivity():
    """Test device connectivity and ADB functionality."""
    
    print("=== Device Connectivity Test ===")
    
    # 1. Test ADB devices command
    print("\n1. Testing ADB devices...")
    try:
        result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
        print(f"   ADB Exit Code: {result.returncode}")
        print(f"   ADB Output: {result.stdout}")
        if result.stderr:
            print(f"   ADB Error: {result.stderr}")
    except Exception as e:
        print(f"   ADB Error: {e}")
    
    # 2. Test specific device connectivity
    print("\n2. Testing device connectivity...")
    device_id = "127.0.0.1:5556"
    try:
        # Test shell command
        result = subprocess.run(['adb', '-s', device_id, 'shell', 'echo', 'test'], 
                              capture_output=True, text=True, timeout=10)
        print(f"   Shell Test Exit Code: {result.returncode}")
        print(f"   Shell Test Output: {result.stdout.strip()}")
        if result.stderr:
            print(f"   Shell Test Error: {result.stderr}")
    except Exception as e:
        print(f"   Shell Test Error: {e}")
    
    # 3. Test device architecture
    print(f"\n3. Testing device architecture for {device_id}...")
    try:
        result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.product.cpu.abi'], 
                              capture_output=True, text=True, timeout=10)
        print(f"   Architecture Exit Code: {result.returncode}")
        print(f"   Architecture: {result.stdout.strip()}")
        if result.stderr:
            print(f"   Architecture Error: {result.stderr}")
    except Exception as e:
        print(f"   Architecture Error: {e}")
    
    # 4. Test if frida-server exists on device
    print(f"\n4. Testing frida-server existence on {device_id}...")
    try:
        result = subprocess.run(['adb', '-s', device_id, 'shell', 'ls', '/data/local/tmp/frida-server'], 
                              capture_output=True, text=True, timeout=10)
        print(f"   Frida-server Check Exit Code: {result.returncode}")
        print(f"   Frida-server Check Output: {result.stdout.strip()}")
        if result.stderr:
            print(f"   Frida-server Check Error: {result.stderr}")
    except Exception as e:
        print(f"   Frida-server Check Error: {e}")
    
    # 5. Test if frida-server is running
    print(f"\n5. Testing frida-server process on {device_id}...")
    try:
        result = subprocess.run(['adb', '-s', device_id, 'shell', 'pidof', 'frida-server'], 
                              capture_output=True, text=True, timeout=10)
        print(f"   Frida-server Process Exit Code: {result.returncode}")
        print(f"   Frida-server Process Output: {result.stdout.strip()}")
        if result.stderr:
            print(f"   Frida-server Process Error: {result.stderr}")
    except Exception as e:
        print(f"   Frida-server Process Error: {e}")
    
    print("\n=== Device Connectivity Test Complete ===")

if __name__ == "__main__":
    asyncio.run(test_device_connectivity())
