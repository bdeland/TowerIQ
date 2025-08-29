#!/usr/bin/env python3
"""
Test script to diagnose frida-provision issues
"""

import asyncio
import sys
import requests
import json
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

async def test_frida_provision():
    """Test the frida-provision endpoint and related functionality."""
    
    base_url = "http://127.0.0.1:8000"
    
    print("=== TowerIQ Frida Provision Test ===")
    
    # 1. Test basic API health
    print("\n1. Testing API health...")
    try:
        response = requests.get(f"{base_url}/")
        print(f"   API Health: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"   API Health Error: {e}")
        return
    
    # 2. Test backend status
    print("\n2. Testing backend status...")
    try:
        response = requests.get(f"{base_url}/api/status")
        print(f"   Backend Status: {response.status_code}")
        if response.status_code == 200:
            status_data = response.json()
            print(f"   Loading Complete: {status_data.get('loading_complete', False)}")
            print(f"   Session: {status_data.get('session', {})}")
    except Exception as e:
        print(f"   Backend Status Error: {e}")
    
    # 3. Test Frida health
    print("\n3. Testing Frida health...")
    try:
        response = requests.get(f"{base_url}/api/health/frida")
        print(f"   Frida Health: {response.status_code}")
        if response.status_code == 200:
            health_data = response.json()
            print(f"   Controller Available: {health_data.get('controller_available', False)}")
            print(f"   Emulator Service Available: {health_data.get('emulator_service_available', False)}")
            print(f"   Frida Manager Available: {health_data.get('frida_manager_available', False)}")
            print(f"   Frida Library Available: {health_data.get('frida_library_available', False)}")
            print(f"   Devices Available: {health_data.get('devices_available', False)}")
            print(f"   Device Count: {health_data.get('device_count', 0)}")
            if health_data.get('device_serials'):
                print(f"   Device Serials: {health_data['device_serials']}")
            if 'device_discovery_error' in health_data:
                print(f"   Device Discovery Error: {health_data['device_discovery_error']}")
    except Exception as e:
        print(f"   Frida Health Error: {e}")
    
    # 4. Test device discovery
    print("\n4. Testing device discovery...")
    try:
        response = requests.get(f"{base_url}/api/devices")
        print(f"   Device Discovery: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            devices = data.get('devices', [])
            print(f"   Found {len(devices)} devices")
            for device in devices:
                print(f"   - {device.get('serial', 'Unknown')} ({device.get('architecture', 'Unknown')})")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Device Discovery Error: {e}")
    
    # 5. Test frida-provision with a specific device
    print("\n5. Testing frida-provision...")
    try:
        # First get available devices
        response = requests.get(f"{base_url}/api/devices")
        if response.status_code == 200:
            data = response.json()
            devices = data.get('devices', [])
            if devices:
                device_id = devices[0]['serial']
                print(f"   Testing with device: {device_id}")
                
                # Test frida-provision
                provision_response = requests.post(f"{base_url}/api/devices/{device_id}/frida-provision")
                print(f"   Frida Provision: {provision_response.status_code}")
                if provision_response.status_code == 200:
                    print(f"   Success: {provision_response.json()}")
                else:
                    print(f"   Error: {provision_response.text}")
            else:
                print("   No devices available for testing")
        else:
            print(f"   Cannot get devices: {response.text}")
    except Exception as e:
        print(f"   Frida Provision Error: {e}")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    asyncio.run(test_frida_provision())
