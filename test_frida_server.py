#!/usr/bin/env python3
"""
Test script for Frida server functionality.
This script tests the Frida server management features to ensure they work correctly.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from tower_iq.services.emulator_service import EmulatorService
from tower_iq.services.frida_manager import FridaServerManager
from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging

async def test_frida_server_functionality():
    """Test the Frida server functionality."""
    
    # Setup logging
    logger = setup_logging()
    
    # Initialize services
    config = ConfigurationManager()
    emulator_service = EmulatorService(config, logger)
    
    print("🔍 Testing Frida Server Functionality")
    print("=" * 50)
    
    # Test 1: Discover devices
    print("\n1. Discovering devices...")
    try:
        devices = await emulator_service.discover_devices()
        if not devices:
            print("❌ No devices found. Please ensure an emulator is running.")
            return
        
        device = devices[0]
        print(f"✅ Found device: {device.device_name} ({device.serial})")
        print(f"   Architecture: {device.architecture}")
        print(f"   Android Version: {device.android_version}")
        
    except Exception as e:
        print(f"❌ Failed to discover devices: {e}")
        return
    
    # Test 2: Check Frida server status
    print("\n2. Checking Frida server status...")
    try:
        is_installed = await emulator_service.frida_manager.is_server_installed(device.serial)
        print(f"   Installed: {is_installed}")
        
        # Check if running
        try:
            pid_output = await emulator_service.adb.shell(device.serial, "pidof frida-server")
            is_running = bool(pid_output.strip())
            print(f"   Running: {is_running}")
        except Exception:
            print("   Running: False (could not check)")
            
    except Exception as e:
        print(f"❌ Failed to check Frida status: {e}")
    
    # Test 3: Stop server if running
    print("\n3. Stopping Frida server (if running)...")
    try:
        success = await emulator_service.frida_manager.stop_server(device.serial)
        print(f"   Stop result: {success}")
    except Exception as e:
        print(f"❌ Failed to stop Frida server: {e}")
    
    # Test 4: Remove server if installed
    print("\n4. Removing Frida server (if installed)...")
    try:
        success = await emulator_service.frida_manager.remove_server(device.serial)
        print(f"   Remove result: {success}")
    except Exception as e:
        print(f"❌ Failed to remove Frida server: {e}")
    
    # Test 5: Install server
    print("\n5. Installing Frida server...")
    try:
        # Get Frida version
        import frida
        target_version = frida.__version__
        print(f"   Target version: {target_version}")
        
        success = await emulator_service.frida_manager.install_server(
            device.serial, device.architecture, target_version
        )
        print(f"   Install result: {success}")
        
    except ImportError:
        print("❌ Frida library not available")
        return
    except Exception as e:
        print(f"❌ Failed to install Frida server: {e}")
    
    # Test 6: Start server
    print("\n6. Starting Frida server...")
    try:
        success = await emulator_service.frida_manager.start_server(device.serial)
        print(f"   Start result: {success}")
        
        if success:
            # Wait a moment and check if it's running
            await asyncio.sleep(2)
            try:
                pid_output = await emulator_service.adb.shell(device.serial, "pidof frida-server")
                is_running = bool(pid_output.strip())
                print(f"   Verified running: {is_running}")
            except Exception:
                print("   Could not verify if running")
                
    except Exception as e:
        print(f"❌ Failed to start Frida server: {e}")
    
    # Test 7: Get server version
    print("\n7. Getting server version...")
    try:
        version = await emulator_service.frida_manager.get_server_version(device.serial)
        print(f"   Server version: {version}")
    except Exception as e:
        print(f"❌ Failed to get server version: {e}")
    
    # Test 8: Stop server again
    print("\n8. Stopping Frida server...")
    try:
        success = await emulator_service.frida_manager.stop_server(device.serial)
        print(f"   Stop result: {success}")
    except Exception as e:
        print(f"❌ Failed to stop Frida server: {e}")
    
    print("\n✅ Frida server functionality test completed!")

if __name__ == "__main__":
    asyncio.run(test_frida_server_functionality())
