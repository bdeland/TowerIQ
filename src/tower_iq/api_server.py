"""
TowerIQ API Server - FastAPI backend for Tauri frontend

This module provides a FastAPI server that bridges the React/Tauri frontend
with the existing Python backend services.
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import structlog

# Add the src directory to the path so we can import tower_iq modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.main_controller import MainController
from tower_iq.services.database_service import DatabaseService


# Pydantic models for API requests/responses
class ConnectionRequest(BaseModel):
    device_serial: str

class HookActivationRequest(BaseModel):
    device_id: str
    process_info: Dict[str, Any]
    script_content: str

class HookDeactivationRequest(BaseModel):
    device_id: str
    process_info: Dict[str, Any]

class ScriptCompatibilityRequest(BaseModel):
    package_name: str
    app_version: str

class TestModeRequest(BaseModel):
    test_mode: bool
    test_mode_replay: bool = False
    test_mode_generate: bool = False

class SessionState(BaseModel):
    is_connected: bool
    current_device: Optional[str] = None
    current_process: Optional[Dict[str, Any]] = None
    test_mode: bool = False

# Global variables for the backend services
config: Optional[ConfigurationManager] = None
logger: Optional[Any] = None
controller: Optional[MainController] = None
db_service: Optional[DatabaseService] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the lifespan of the FastAPI application and backend services."""
    global config, logger, controller, db_service
    
    # Initialize paths & environment
    app_root = Path(__file__).parent.parent.parent
    os.chdir(app_root)
    
    # Initialize configuration
    config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))
    
    # Set up logging
    setup_logging(config)
    logger = structlog.get_logger()
    logger.info("Starting TowerIQ API Server")
    
    # Initialize database service
    db_service = DatabaseService(config, logger)
    db_service.connect()
    logger.info("Database connected successfully")
    
    # Link database service to config manager
    config.link_database_service(db_service)
    
    # Initialize main controller
    controller = MainController(config, logger, db_service=db_service)
    controller.start_background_operations()
    
    logger.info("TowerIQ API Server started successfully")
    
    yield
    
    # Cleanup
    if controller:
        logger.info("Shutting down controller")
        controller.shutdown()
    logger.info("TowerIQ API Server shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="TowerIQ API",
    description="API server for TowerIQ Tauri frontend",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware for Tauri frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:1420", "http://127.0.0.1:1420"],  # Tauri dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"message": "TowerIQ API Server is running", "version": "1.0.0"}


@app.get("/api/status")
async def get_status():
    """Get the current status of the backend services."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        session_state = controller.get_session_state()
        return {
            "status": "running",
            "session": SessionState(
                is_connected=session_state.get("is_connected", False),
                current_device=session_state.get("current_device"),
                current_process=session_state.get("current_process"),
                test_mode=controller._test_mode
            )
        }
    except Exception as e:
        if logger:
            logger.error("Error getting status", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/connect")
async def connect_device(request: ConnectionRequest):
    """Connect to a specific device."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # Use the main controller to handle the connection
        controller.connect_to_device(request.device_serial)
        
        return {"message": "Device connected successfully", "device_serial": request.device_serial}
    except Exception as e:
        logger.error("Error connecting to device", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/disconnect")
async def disconnect_device():
    """Disconnect from the currently connected device."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # Use the main controller to handle the disconnection
        controller.disconnect_from_device()
        
        return {"message": "Device disconnected successfully"}
    except Exception as e:
        logger.error("Error disconnecting from device", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/activate-hook")
async def activate_hook(request: HookActivationRequest, background_tasks: BackgroundTasks):
    """Activate a hook script."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        def activate_hook_task():
            try:
                hook_data = {
                    "device_id": request.device_id,
                    "process_info": request.process_info,
                    "script_content": request.script_content
                }
                # For now, just log the hook activation
                # In a full implementation, this would trigger the hook activation flow
                logger.info("Hook activation initiated", hook_data=hook_data)
            except Exception as e:
                logger.error("Error activating hook", error=str(e))
        
        background_tasks.add_task(activate_hook_task)
        
        return {"message": "Hook activation initiated"}
    except Exception as e:
        logger.error("Error initiating hook activation", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/deactivate-hook")
async def deactivate_hook(request: HookDeactivationRequest, background_tasks: BackgroundTasks):
    """Deactivate a hook script."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        def deactivate_hook_task():
            try:
                hook_data = {
                    "device_id": request.device_id,
                    "process_info": request.process_info
                }
                # For now, just log the hook deactivation
                # In a full implementation, this would trigger the hook deactivation flow
                logger.info("Hook deactivation initiated", hook_data=hook_data)
            except Exception as e:
                logger.error("Error deactivating hook", error=str(e))
        
        background_tasks.add_task(deactivate_hook_task)
        
        return {"message": "Hook deactivation initiated"}
    except Exception as e:
        logger.error("Error initiating hook deactivation", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/compatible-scripts")
async def get_compatible_scripts(request: ScriptCompatibilityRequest):
    """Get compatible scripts for a package and version."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # This would need to be adapted to work with the async nature
        # For now, we'll return a placeholder
        return {"scripts": []}
    except Exception as e:
        logger.error("Error getting compatible scripts", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/test-mode")
async def set_test_mode(request: TestModeRequest):
    """Set test mode configuration."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        controller._test_mode = request.test_mode
        controller._test_mode_replay = request.test_mode_replay
        controller._test_mode_generate = request.test_mode_generate
        
        return {"message": "Test mode updated", "test_mode": request.test_mode}
    except Exception as e:
        logger.error("Error setting test mode", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/devices")
async def get_devices():
    """Get available devices."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # Use the simplified device discovery method
        devices = await controller.emulator_service.discover_devices()
        
        # Convert Device objects to dictionaries for JSON serialization
        device_dicts = []
        for device in devices:
            device_dicts.append({
                'id': device.serial,  # Use serial as ID for frontend compatibility
                'name': device.device_name or device.model,  # Use device_name if available, fallback to model
                'type': device.device_type,
                'status': device.status,
                'serial': device.serial,
                'model': device.model,
                'device_name': device.device_name,  # Include the new device_name field
                'brand': device.brand,  # Include brand information
                'android_version': device.android_version,
                'api_level': device.api_level,
                'architecture': device.architecture,
                'is_network_device': device.is_network_device,
                'ip_address': device.ip_address,
                'port': device.port
            })
        
        return {"devices": device_dicts}
    except Exception as e:
        logger.error("Error getting devices", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/devices/{device_id}/processes")
async def get_processes(device_id: str):
    """Get processes for a specific device."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # First get the device to pass to the process listing method
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        
        if not device:
            logger.warning("Device not found", device_id=device_id)
            return {"processes": [], "message": "Device not found"}
        
        # Use the new process listing method
        processes = await controller.emulator_service.get_processes(device)
        
        # Convert Process objects to dictionaries for JSON serialization
        process_dicts = []
        for process in processes:
            process_dicts.append({
                'id': process.package,  # Use package as ID for frontend compatibility
                'name': process.name,
                'pid': process.pid,
                'package': process.package,
                'version': process.version,
                'is_system': process.is_system
            })
        
        if not process_dicts:
            logger.info("No processes found for device", device_id=device_id)
            return {"processes": [], "message": "No user processes found on device"}
        
        logger.info("Retrieved processes for device", device_id=device_id, count=len(process_dicts))
        return {"processes": process_dicts}
        
    except Exception as e:
        logger.error("Error getting processes", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/hook-scripts")
async def get_hook_scripts():
    """Get available hook scripts."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # Get scripts from the hook script manager
        scripts = controller.hook_script_manager.get_available_scripts()
        return {"scripts": scripts}
    except Exception as e:
        logger.error("Error getting hook scripts", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/devices/{device_id}/frida-status")
async def get_frida_status(device_id: str):
    """Get Frida server status for a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Get the device to check Frida status
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Check if Frida server is running using ADB
        try:
            # Check if frida-server process is running
            pid_output = await controller.emulator_service.adb.shell(
                device_id, "pidof frida-server"
            )
            is_running = bool(pid_output.strip())
        except Exception:
            is_running = False
        
        # Get Frida version if available
        frida_version = None
        try:
            version_output = await controller.emulator_service.adb.shell(
                device_id, "frida-server --version"
            )
            frida_version = version_output.strip()
        except Exception:
            pass
        
        # Get required Frida version (from Python frida library)
        required_version = None
        try:
            import frida
            required_version = frida.__version__
        except ImportError:
            pass
        
        # Check if server is installed
        is_installed = False
        try:
            await controller.emulator_service.adb.shell(device_id, "ls /data/local/tmp/frida-server")
            is_installed = True
        except Exception:
            pass
        
        # Determine if update is needed
        needs_update = False
        if frida_version and required_version:
            current_clean = frida_version.replace('frida-server', '').replace('frida', '').strip()
            required_clean = required_version.replace('frida-server', '').replace('frida', '').strip()
            needs_update = current_clean != required_clean
        
        frida_status = {
            "is_running": is_running,
            "is_installed": is_installed,
            "version": frida_version,
            "required_version": required_version,
            "architecture": device.architecture,
            "needs_update": needs_update
        }
        
        return {"frida_status": frida_status}
        
    except Exception as e:
        logger.error("Error checking Frida status", device_id=device_id, error=str(e))
        # Return a default status instead of throwing an error
        return {
            "frida_status": {
                "is_running": False,
                "is_installed": False,
                "version": None,
                "required_version": None,
                "architecture": None,
                "needs_update": True,
                "error": str(e)
            }
        }

@app.post("/api/devices/{device_id}/frida-provision")
async def provision_frida_server(device_id: str):
    """Provision Frida server on a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Get the device to provision Frida server
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Provision Frida server
        try:
            await controller.emulator_service.provision_frida_server(device_id)
            return {"message": "Frida server provisioned successfully"}
        except Exception as e:
            logger.error("Error provisioning Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to provision Frida server: {str(e)}")
            
    except Exception as e:
        logger.error("Error in Frida server provisioning", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to provision Frida server: {str(e)}")

@app.post("/api/devices/{device_id}/frida-start")
async def start_frida_server(device_id: str):
    """Start Frida server on a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Get the device to start Frida server
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Start Frida server
        try:
            success = await controller.emulator_service.frida_manager.start_server(device_id)
            
            if success:
                return {"message": "Frida server started successfully", "device_id": device_id}
            else:
                raise HTTPException(status_code=500, detail="Failed to start Frida server")
                
        except Exception as e:
            logger.error("Error starting Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to start Frida server: {str(e)}")
            
    except Exception as e:
        logger.error("Error in Frida server start", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to start Frida server: {str(e)}")

@app.post("/api/devices/{device_id}/frida-stop")
async def stop_frida_server(device_id: str):
    """Stop Frida server on a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Get the device to stop Frida server
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Stop Frida server
        try:
            success = await controller.emulator_service.frida_manager.stop_server(device_id)
            
            if success:
                return {"message": "Frida server stopped successfully", "device_id": device_id}
            else:
                raise HTTPException(status_code=500, detail="Failed to stop Frida server")
                
        except Exception as e:
            logger.error("Error stopping Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to stop Frida server: {str(e)}")
            
    except Exception as e:
        logger.error("Error in Frida server stop", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to stop Frida server: {str(e)}")

@app.post("/api/devices/{device_id}/frida-install")
async def install_frida_server(device_id: str):
    """Install Frida server on a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Get the device to install Frida server
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Install Frida server
        try:
            # Get required Frida version
            try:
                import frida
                target_version = frida.__version__
            except ImportError:
                raise HTTPException(status_code=500, detail="Frida library not available")
            
            # Install Frida server
            success = await controller.emulator_service.frida_manager.install_server(
                device_id, device.architecture, target_version
            )
            
            if success:
                return {"message": "Frida server installed successfully", "device_id": device_id}
            else:
                raise HTTPException(status_code=500, detail="Failed to install Frida server")
                
        except Exception as e:
            logger.error("Error installing Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to install Frida server: {str(e)}")
            
    except Exception as e:
        logger.error("Error in Frida server install", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to install Frida server: {str(e)}")

@app.post("/api/devices/{device_id}/frida-remove")
async def remove_frida_server(device_id: str):
    """Remove Frida server from a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Get the device to remove Frida server
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Remove Frida server
        try:
            success = await controller.emulator_service.frida_manager.remove_server(device_id)
            
            if success:
                return {"message": "Frida server removed successfully", "device_id": device_id}
            else:
                raise HTTPException(status_code=500, detail="Failed to remove Frida server")
                
        except Exception as e:
            logger.error("Error removing Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to remove Frida server: {str(e)}")
            
    except Exception as e:
        logger.error("Error in Frida server remove", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to remove Frida server: {str(e)}")

@app.get("/api/script-status")
async def get_script_status():
    """Get the current script status including heartbeat information."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Get script status from controller
        return controller.get_script_status()
        
    except Exception as e:
        if logger:
            logger.error("Error getting script status", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get script status: {str(e)}")

@app.post("/api/heartbeat")
async def receive_heartbeat(request: dict):
    """Receive heartbeat message from hook script."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")
        
        # Handle heartbeat message
        controller.handle_heartbeat_message(request)
        
        return {"message": "Heartbeat received"}
        
    except Exception as e:
        if logger:
            logger.error("Error processing heartbeat", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to process heartbeat: {str(e)}")

def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Start the FastAPI server."""
    uvicorn.run(
        "tower_iq.api_server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    start_server()
