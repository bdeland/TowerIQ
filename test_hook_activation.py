#!/usr/bin/env python3
"""
Test script for hook activation functionality.
This script tests the hook activation and deactivation features.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from tower_iq.api_server import HookActivationRequest, HookDeactivationRequest

async def test_hook_activation_api():
    """Test the hook activation API endpoints."""
    
    print("🔍 Testing Hook Activation API")
    print("=" * 50)
    
    # Test 1: Create hook activation request
    print("\n1. Testing hook activation request creation...")
    try:
        hook_request = HookActivationRequest(
            device_id="test_device_123",
            process_info={
                "id": "com.example.app",
                "name": "Example App",
                "pid": 12345,
                "package": "com.example.app"
            },
            script_content="console.log('Hello from hook!');"
        )
        print(f"✅ Hook activation request created successfully")
        print(f"   Device ID: {hook_request.device_id}")
        print(f"   Process: {hook_request.process_info['name']} (PID: {hook_request.process_info['pid']})")
        print(f"   Script length: {len(hook_request.script_content)} characters")
        
    except Exception as e:
        print(f"❌ Failed to create hook activation request: {e}")
        return
    
    # Test 2: Create hook deactivation request
    print("\n2. Testing hook deactivation request creation...")
    try:
        deactivate_request = HookDeactivationRequest(
            device_id="test_device_123",
            process_info={
                "id": "com.example.app",
                "name": "Example App",
                "pid": 12345,
                "package": "com.example.app"
            }
        )
        print(f"✅ Hook deactivation request created successfully")
        print(f"   Device ID: {deactivate_request.device_id}")
        print(f"   Process: {deactivate_request.process_info['name']} (PID: {deactivate_request.process_info['pid']})")
        
    except Exception as e:
        print(f"❌ Failed to create hook deactivation request: {e}")
        return
    
    # Test 3: Test request serialization
    print("\n3. Testing request serialization...")
    try:
        hook_dict = hook_request.model_dump()
        deactivate_dict = deactivate_request.model_dump()
        
        print(f"✅ Hook activation request serialized: {len(hook_dict)} fields")
        print(f"✅ Hook deactivation request serialized: {len(deactivate_dict)} fields")
        
        # Verify required fields are present
        required_hook_fields = ['device_id', 'process_info', 'script_content']
        required_deactivate_fields = ['device_id', 'process_info']
        
        for field in required_hook_fields:
            if field in hook_dict:
                print(f"   ✅ Hook activation has field: {field}")
            else:
                print(f"   ❌ Hook activation missing field: {field}")
        
        for field in required_deactivate_fields:
            if field in deactivate_dict:
                print(f"   ✅ Hook deactivation has field: {field}")
            else:
                print(f"   ❌ Hook deactivation missing field: {field}")
        
    except Exception as e:
        print(f"❌ Failed to serialize requests: {e}")
        return
    
    print("\n✅ Hook activation API test completed successfully!")

if __name__ == "__main__":
    asyncio.run(test_hook_activation_api())
