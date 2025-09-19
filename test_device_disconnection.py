#!/usr/bin/env python3
"""
Quick test script for device disconnection handling.
Run this while TowerIQ is connected to a device to simulate disconnection.
"""

import requests
import time
import sys

def test_device_disconnection():
    """Test device disconnection simulation."""
    base_url = "http://localhost:8000"
    
    print("🧪 Testing Device Disconnection Handling")
    print("=" * 50)
    
    try:
        # Check if backend is running
        print("1. Checking backend status...")
        response = requests.get(f"{base_url}/api/status")
        if response.status_code != 200:
            print("❌ Backend not running or not responding")
            return False
        
        status = response.json()
        print(f"   ✅ Backend running (loading complete: {status.get('loading_complete')})")
        
        # Check if device is connected
        if not status.get('session', {}).get('is_connected'):
            print("❌ No device connected - please connect a device first")
            return False
        
        device = status.get('session', {}).get('current_device')
        print(f"   ✅ Device connected: {device}")
        
        # Trigger simulation
        print("\n2. Triggering device disconnection simulation...")
        response = requests.post(f"{base_url}/api/test/simulate-device-disconnection")
        
        if response.status_code == 200:
            print("   ✅ Simulation triggered successfully")
        else:
            print(f"   ❌ Failed to trigger simulation: {response.status_code} - {response.text}")
            return False
        
        # Monitor status changes
        print("\n3. Monitoring status changes...")
        for i in range(20):  # Monitor for up to 20 seconds
            time.sleep(1)
            try:
                response = requests.get(f"{base_url}/api/status")
                if response.status_code == 200:
                    status = response.json()
                    session = status.get('session', {})
                    
                    print(f"   [{i+1:2d}s] Connected: {session.get('is_connected')}, "
                          f"State: {session.get('connection_state')}, "
                          f"Error: {session.get('last_error', {}).get('code') if session.get('last_error') else 'None'}")
                    
                    # Check if disconnection was detected
                    if not session.get('is_connected') and session.get('last_error'):
                        error = session.get('last_error', {})
                        if error.get('code') == 'device_disconnected':
                            print(f"\n   ✅ SUCCESS! Disconnection detected:")
                            print(f"      Message: {error.get('message')}")
                            print(f"      Recovery suggestions: {error.get('recovery_suggestions')}")
                            return True
                            
            except requests.RequestException as e:
                print(f"   [ERROR] Request failed: {e}")
        
        print("\n   ⚠️  Timeout - disconnection may not have been detected")
        return False
        
    except requests.RequestException as e:
        print(f"❌ Connection error: {e}")
        print("   Make sure TowerIQ backend is running on localhost:8000")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def main():
    print("TowerIQ Device Disconnection Test")
    print("Make sure you have:")
    print("1. TowerIQ backend running (start_toweriq.py)")
    print("2. A device connected and monitoring active")
    print()
    
    input("Press Enter to start the test...")
    
    success = test_device_disconnection()
    
    if success:
        print("\n🎉 Test completed successfully!")
        print("The device disconnection handling is working properly.")
    else:
        print("\n❌ Test failed or timed out.")
        print("Check the logs for more details.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
