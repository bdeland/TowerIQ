#!/usr/bin/env python3
"""
Debug script to test each step of frida-provision individually
"""

import asyncio
import sys
import requests
import json
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def debug_frida_provision():
    """Debug each step of the frida-provision process."""
    
    base_url = "http://127.0.0.1:8000"
    
    print("=== Frida Provision Debug ===")
    
    # 1. Test basic connectivity
    print("\n1. Testing basic connectivity...")
    try:
        response = requests.get(f"{base_url}/")
        print(f"   ✓ API Health: {response.status_code}")
    except Exception as e:
        print(f"   ✗ API Health Error: {e}")
        return
    
    # 2. Test device discovery
    print("\n2. Testing device discovery...")
    try:
        response = requests.get(f"{base_url}/api/devices")
        if response.status_code == 200:
            data = response.json()
            devices = data.get('devices', [])
            print(f"   ✓ Found {len(devices)} devices")
            for device in devices:
                print(f"     - {device.get('serial', 'Unknown')} ({device.get('architecture', 'Unknown')})")
        else:
            print(f"   ✗ Device discovery failed: {response.status_code} - {response.text}")
            return
    except Exception as e:
        print(f"   ✗ Device discovery error: {e}")
        return
    
    if not devices:
        print("   ✗ No devices found")
        return
    
    device_id = devices[0]['serial']
    print(f"   Using device: {device_id}")
    
    # 3. Test Frida health
    print("\n3. Testing Frida health...")
    try:
        response = requests.get(f"{base_url}/api/health/frida")
        if response.status_code == 200:
            health_data = response.json()
            print(f"   ✓ Controller Available: {health_data.get('controller_available', False)}")
            print(f"   ✓ Emulator Service Available: {health_data.get('emulator_service_available', False)}")
            print(f"   ✓ Frida Manager Available: {health_data.get('frida_manager_available', False)}")
            print(f"   ✓ Frida Library Available: {health_data.get('frida_library_available', False)}")
            print(f"   ✓ Devices Available: {health_data.get('devices_available', False)}")
            print(f"   ✓ Device Count: {health_data.get('device_count', 0)}")
        else:
            print(f"   ✗ Frida health check failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"   ✗ Frida health error: {e}")
    
    # 4. Test frida-status endpoint
    print(f"\n4. Testing frida-status for {device_id}...")
    try:
        response = requests.get(f"{base_url}/api/devices/{device_id}/frida-status")
        if response.status_code == 200:
            status_data = response.json()
            print(f"   ✓ Frida Status: {status_data}")
        else:
            print(f"   ✗ Frida status failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"   ✗ Frida status error: {e}")
    
    # 5. Test frida-provision with detailed error handling
    print(f"\n5. Testing frida-provision for {device_id}...")
    try:
        response = requests.post(f"{base_url}/api/devices/{device_id}/frida-provision", timeout=60)
        print(f"   Response Status: {response.status_code}")
        print(f"   Response Headers: {dict(response.headers)}")
        print(f"   Response Body: {response.text}")
        
        if response.status_code == 200:
            print("   ✓ Frida provision successful!")
        else:
            print("   ✗ Frida provision failed")
            try:
                error_data = response.json()
                print(f"   Error Detail: {error_data.get('detail', 'Unknown error')}")
            except:
                print(f"   Raw Error: {response.text}")
    except requests.exceptions.Timeout:
        print("   ✗ Frida provision timed out (60 seconds)")
    except Exception as e:
        print(f"   ✗ Frida provision error: {e}")
    
    print("\n=== Debug Complete ===")

if __name__ == "__main__":
    asyncio.run(debug_frida_provision())

