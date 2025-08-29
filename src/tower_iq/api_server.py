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

# Dashboard API models
class DashboardCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    config: Dict[str, Any]
    tags: Optional[List[str]] = None

class DashboardUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None

class DashboardResponse(BaseModel):
    id: str
    uid: str
    title: str
    description: Optional[str] = None
    config: Dict[str, Any]
    tags: List[str]
    created_at: str
    updated_at: str
    created_by: str
    is_default: bool
    schema_version: int

class QueryRequest(BaseModel):
    query: str

class QueryResponse(BaseModel):
    data: List[Dict[str, Any]]
    rowCount: int

class QueryPreviewRequest(BaseModel):
    query: str

class QueryPreviewResponse(BaseModel):
    status: str
    message: str
    plan: Optional[List[Dict[str, Any]]] = None

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
    if logger:
        logger.info("Starting TowerIQ API Server")
    
    # Initialize database service
    db_service = DatabaseService(config, logger)
    db_service.connect()
    if logger:
        logger.info("Database connected successfully")
    
    # Ensure dashboards table exists
    db_service.ensure_dashboards_table_exists()
    
    # Link database service to config manager
    config.link_database_service(db_service)
    
    # Initialize main controller
    controller = MainController(config, logger, db_service=db_service)
    controller.start_background_operations()
    
    # Start the message processing loop as a background task
    asyncio.create_task(controller.run())
    
    # Start the loading sequence
    controller.loading_manager.start_loading()
    controller.loading_manager.mark_step_complete('database')
    controller.loading_manager.mark_step_complete('emulator_service')
    controller.loading_manager.mark_step_complete('frida_service')
    controller.loading_manager.mark_step_complete('hook_scripts')
    
    # Simulate some startup time for services
    await asyncio.sleep(2)  # Simulate 2 seconds of startup time
    
    # Signal that the API server is ready
    controller.signal_loading_complete()
    
    if logger:
        logger.info("TowerIQ API Server started successfully")
    
    yield
    
    # Cleanup
    if controller:
        if logger:
            logger.info("Shutting down controller")
        controller.shutdown()
    if logger:
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
            ),
            "loading_complete": controller.loading_manager.is_loading_complete()
        }
    except Exception as e:
        if logger:
            logger.error("Error getting status", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/health/frida")
async def get_frida_health():
    """Get the health status of Frida-related services."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        health_status = {
            "controller_available": controller is not None,
            "emulator_service_available": controller.emulator_service is not None if controller else False,
            "frida_manager_available": controller.emulator_service.frida_manager is not None if controller and controller.emulator_service else False,
            "frida_library_available": False,
            "devices_available": False,
            "device_count": 0
        }
        
        # Check if Frida library is available
        try:
            import frida
            health_status["frida_library_available"] = True
            health_status["frida_version"] = frida.__version__
        except ImportError:
            pass
        
        # Check if devices are available
        if controller and controller.emulator_service:
            try:
                devices = await controller.emulator_service.discover_devices()
                health_status["devices_available"] = len(devices) > 0
                health_status["device_count"] = len(devices)
                if devices:
                    health_status["device_serials"] = [d.serial for d in devices]
            except Exception as e:
                health_status["device_discovery_error"] = str(e)
        
        return health_status
    except Exception as e:
        if logger:
            logger.error("Error getting Frida health status", error=str(e))
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
        if logger:
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
        if logger:
            logger.error("Error disconnecting from device", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/activate-hook")
async def activate_hook(request: HookActivationRequest, background_tasks: BackgroundTasks):
    """Activate a hook script."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # Extract process info
        process_info = request.process_info
        device_id = request.device_id
        script_content = request.script_content
        
        # Get the process ID from the process info
        pid = process_info.get('pid')
        if not pid:
            raise HTTPException(status_code=400, detail="Process ID not found in process info")
        
        if logger:
            logger.info("Starting hook activation", 
                       device_id=device_id, 
                       pid=pid, 
                       script_length=len(script_content))
        
        # Use the Frida service to inject the script
        success = await controller.frida_service.inject_and_run_script(
            device_id=device_id,
            pid=pid,
            script_content=script_content
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to inject hook script")
        
        if logger:
            logger.info("Hook script injected successfully", device_id=device_id, pid=pid)
        
        return {"message": "Hook script injected successfully"}
    except Exception as e:
        if logger:
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


@app.post("/api/devices/refresh")
async def refresh_devices():
    """Refresh device list with cache clearing."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # Use the device discovery method with cache clearing
        devices = await controller.emulator_service.discover_devices(clear_cache=True)
        
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
        logger.error("Error refreshing devices", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/devices/{device_id}/processes")
async def get_processes(device_id: str):
    """Get processes for a specific device."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # First get the device to pass to the process listing method
        if not controller.emulator_service:
            raise HTTPException(status_code=503, detail="Emulator service not initialized")
            
        devices = await controller.emulator_service.discover_devices()
        device = next((d for d in devices if d.serial == device_id), None)
        
        if not device:
            if logger:
                logger.warning("Device not found", device_id=device_id)
            return {"processes": [], "message": "Device not found"}
        
        # Use the unfiltered process listing method to show all processes
        processes = await controller.emulator_service.get_all_processes_unfiltered(device)
        
        # Convert Process objects to dictionaries for JSON serialization
        process_dicts = []
        target_found = False
        for process in processes:
            process_dicts.append({
                'id': process.package,  # Use package as ID for frontend compatibility
                'name': process.name,
                'pid': process.pid,
                'package': process.package,
                'version': process.version,
                'is_system': process.is_system
            })
            
            # Check if target process is found
            if process.package == "com.TechTreeGames.TheTower":
                target_found = True
        
        if not process_dicts:
            if logger:
                logger.info("No processes found for device", device_id=device_id)
            return {"processes": [], "message": "No user processes found on device"}
        
        if logger:
            logger.info("Retrieved processes for device", device_id=device_id, count=len(process_dicts), target_found=target_found)
        return {
            "processes": process_dicts,
            "target_found": target_found,
            "total_count": len(process_dicts)
        }
        
    except Exception as e:
        if logger:
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
        
        # Use FridaServerManager methods for better status checking
        frida_manager = controller.emulator_service.frida_manager
        
        # Check if server is installed
        is_installed = await frida_manager.is_server_installed(device_id)
        
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
        if is_installed:
            try:
                frida_version = await frida_manager.get_server_version(device_id)
            except Exception:
                pass
        
        # Get required Frida version (from Python frida library)
        required_version = None
        try:
            import frida
            required_version = frida.__version__
        except ImportError:
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
        
        if logger:
            logger.info("Frida status response", device_id=device_id, status=frida_status)
        
        return {"frida_status": frida_status}
        
    except Exception as e:
        if logger:
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
        
        if not controller.emulator_service:
            raise HTTPException(status_code=500, detail="Emulator service not available")
        
        if not controller.emulator_service.frida_manager:
            raise HTTPException(status_code=500, detail="Frida manager not available")
        
        # Get the device to provision Frida server
        try:
            devices = await controller.emulator_service.discover_devices()
            if not devices:
                raise HTTPException(status_code=404, detail="No devices found")
            
            device = next((d for d in devices if d.serial == device_id), None)
            if not device:
                raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
        except Exception as e:
            if logger:
                logger.error("Error discovering devices", error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to discover devices: {str(e)}")
        
        # Provision Frida server
        try:
            # Get required Frida version from Python frida library
            try:
                import frida
                target_version = frida.__version__
            except ImportError:
                raise HTTPException(status_code=500, detail="Frida library not available")
            except Exception as e:
                if logger:
                    logger.error("Error getting Frida version", error=str(e))
                raise HTTPException(status_code=500, detail=f"Failed to get Frida version: {str(e)}")
            
            if logger:
                logger.info("Provisioning Frida server with compatible version", 
                           device_id=device_id, 
                           architecture=device.architecture, 
                           target_version=target_version)
            
            if logger:
                logger.info("Starting frida-provision process", device_id=device_id, architecture=device.architecture, target_version=target_version)
            
            success = await controller.emulator_service.frida_manager.provision(device_id, device.architecture, target_version)
            
            if logger:
                logger.info("Frida-provision result", device_id=device_id, success=success)
            
            if success:
                return {"message": "Frida server provisioned successfully"}
            else:
                raise HTTPException(status_code=500, detail="Failed to provision Frida server - check logs for details")
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            if logger:
                logger.error("Error provisioning Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to provision Frida server: {str(e)}")
            
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        if logger:
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
            if logger:
                logger.error("Error installing Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to install Frida server: {str(e)}")
            
    except Exception as e:
        if logger:
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
            if logger:
                logger.error("Error removing Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to remove Frida server: {str(e)}")
            
    except Exception as e:
        if logger:
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

# --- ADB Server Management Endpoints ---

@app.post("/api/adb/start")
async def start_adb_server():
    """Start the ADB server."""
    try:
        if not controller:
            raise HTTPException(status_code=503, detail="Backend not initialized")
        
        await controller.emulator_service.start_adb_server()
        return {"message": "ADB server started successfully"}
        
    except Exception as e:
        if logger:
            logger.error("Error starting ADB server", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to start ADB server: {str(e)}")

@app.post("/api/adb/kill")
async def kill_adb_server():
    """Kill the ADB server."""
    try:
        if not controller:
            raise HTTPException(status_code=503, detail="Backend not initialized")
        
        await controller.emulator_service.kill_adb_server()
        return {"message": "ADB server killed successfully"}
        
    except Exception as e:
        if logger:
            logger.error("Error killing ADB server", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to kill ADB server: {str(e)}")

@app.post("/api/adb/restart")
async def restart_adb_server():
    """Restart the ADB server."""
    try:
        if not controller:
            raise HTTPException(status_code=503, detail="Backend not initialized")
        
        await controller.emulator_service.restart_adb_server()
        return {"message": "ADB server restarted successfully"}
        
    except Exception as e:
        if logger:
            logger.error("Error restarting ADB server", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to restart ADB server: {str(e)}")

# --- Dashboard Management Endpoints ---

@app.get("/api/dashboards", response_model=List[DashboardResponse])
async def get_dashboards():
    """Get all dashboards."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        dashboards = db_service.get_all_dashboards()
        return dashboards
        
    except Exception as e:
        if logger:
            logger.error("Error getting dashboards", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get dashboards: {str(e)}")

@app.get("/api/dashboards/{dashboard_id}", response_model=DashboardResponse)
async def get_dashboard(dashboard_id: str):
    """Get a specific dashboard by ID."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        dashboard = db_service.get_dashboard_by_id(dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        return dashboard
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error getting dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")

@app.post("/api/dashboards", response_model=DashboardResponse)
async def create_dashboard(request: DashboardCreateRequest):
    """Create a new dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        import uuid
        dashboard_id = str(uuid.uuid4())
        dashboard_uid = str(uuid.uuid4())
        
        dashboard_data = {
            'id': dashboard_id,
            'uid': dashboard_uid,
            'title': request.title,
            'description': request.description or '',
            'config': request.config,
            'tags': request.tags or [],
            'created_by': 'system'
        }
        
        success = db_service.create_dashboard(dashboard_data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to create dashboard")
        
        # Get the created dashboard
        dashboard = db_service.get_dashboard_by_id(dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=500, detail="Dashboard created but not found")
        
        return dashboard
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error creating dashboard", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to create dashboard: {str(e)}")

@app.put("/api/dashboards/{dashboard_id}", response_model=DashboardResponse)
async def update_dashboard(dashboard_id: str, request: DashboardUpdateRequest):
    """Update an existing dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        # Check if dashboard exists
        existing = db_service.get_dashboard_by_id(dashboard_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        # Prepare update data
        update_data = {}
        if request.title is not None:
            update_data['title'] = request.title
        if request.description is not None:
            update_data['description'] = request.description
        if request.config is not None:
            update_data['config'] = request.config
        if request.tags is not None:
            update_data['tags'] = request.tags
        
        success = db_service.update_dashboard(dashboard_id, update_data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update dashboard")
        
        # Get the updated dashboard
        dashboard = db_service.get_dashboard_by_id(dashboard_id)
        if not dashboard:
            raise HTTPException(status_code=500, detail="Dashboard updated but not found")
        
        return dashboard
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error updating dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to update dashboard: {str(e)}")

@app.delete("/api/dashboards/{dashboard_id}")
async def delete_dashboard(dashboard_id: str):
    """Delete a dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        # Check if dashboard exists
        existing = db_service.get_dashboard_by_id(dashboard_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        success = db_service.delete_dashboard(dashboard_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete dashboard")
        
        return {"message": "Dashboard deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error deleting dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to delete dashboard: {str(e)}")

@app.post("/api/dashboards/{dashboard_id}/set-default")
async def set_default_dashboard(dashboard_id: str):
    """Set a dashboard as the default dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        # Check if dashboard exists
        existing = db_service.get_dashboard_by_id(dashboard_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        
        success = db_service.set_default_dashboard(dashboard_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to set default dashboard")
        
        return {"message": "Default dashboard set successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error setting default dashboard", error=str(e), dashboard_id=dashboard_id)
        raise HTTPException(status_code=500, detail=f"Failed to set default dashboard: {str(e)}")

@app.get("/api/dashboards/default", response_model=DashboardResponse)
async def get_default_dashboard():
    """Get the default dashboard."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        dashboard = db_service.get_default_dashboard()
        if not dashboard:
            raise HTTPException(status_code=404, detail="No default dashboard found")
        
        return dashboard
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error getting default dashboard", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get default dashboard: {str(e)}")

@app.post("/api/dashboards/ensure-table")
async def ensure_dashboards_table():
    """Ensure the dashboards table exists in the database."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        success = db_service.ensure_dashboards_table_exists()
        if success:
            return {"message": "Dashboards table ensured successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to ensure dashboards table")
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error ensuring dashboards table", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to ensure dashboards table: {str(e)}")

@app.post("/api/query/preview", response_model=QueryPreviewResponse)
async def preview_query(request: QueryPreviewRequest):
    """Preview a SQL query to validate syntax and get execution plan without executing it."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        if not db_service.sqlite_conn:
            raise HTTPException(status_code=503, detail="Database connection not available")
        
        # Basic SQL injection protection - only allow SELECT statements
        query_stripped = request.query.strip().upper()
        if not query_stripped.startswith('SELECT'):
            raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")
        
        # Additional protection against dangerous SQL operations
        dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER', 'TRUNCATE', '--', ';']
        for keyword in dangerous_keywords:
            if keyword in query_stripped:
                raise HTTPException(status_code=400, detail=f"Query contains forbidden keyword: {keyword}")
        
        # Use EXPLAIN QUERY PLAN to validate syntax and get execution plan
        explain_query = f"EXPLAIN QUERY PLAN {request.query}"
        cursor = db_service.sqlite_conn.cursor()
        cursor.execute(explain_query)
        
        # Fetch the execution plan
        plan_rows = cursor.fetchall()
        
        # Convert plan to list of dictionaries
        plan = []
        for row in plan_rows:
            plan.append({
                "selectid": row[0],
                "order": row[1],
                "from": row[2],
                "detail": row[3]
            })
        
        if logger:
            logger.info("Query preview successful", 
                       query=request.query, 
                       plan_rows=len(plan))
        
        return QueryPreviewResponse(
            status="success",
            message="Query syntax is valid.",
            plan=plan
        )
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error previewing query", query=request.query, error=str(e))
        return QueryPreviewResponse(
            status="error",
            message=f"Syntax error: {str(e)}"
        )

@app.post("/api/query", response_model=QueryResponse)
async def execute_query(request: QueryRequest):
    """Execute a SQL query against the database and return the results."""
    try:
        if not db_service:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        if not db_service.sqlite_conn:
            raise HTTPException(status_code=503, detail="Database connection not available")
        
        # Basic SQL injection protection - only allow SELECT statements
        query_stripped = request.query.strip().upper()
        if not query_stripped.startswith('SELECT'):
            raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")
        
        # Additional protection against dangerous SQL operations
        dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER', 'TRUNCATE', '--', ';']
        for keyword in dangerous_keywords:
            if keyword in query_stripped:
                raise HTTPException(status_code=400, detail=f"Query contains forbidden keyword: {keyword}")
        
        # Enforce LIMIT clause for safety
        query = request.query.strip()
        if not query.upper().endswith('LIMIT') and 'LIMIT' not in query.upper():
            # Check if query already ends with a semicolon
            if query.endswith(';'):
                query = query[:-1] + ' LIMIT 500;'
            else:
                query = query + ' LIMIT 500'
        
        # Execute the query
        cursor = db_service.sqlite_conn.cursor()
        cursor.execute(query)
        
        # Fetch all results
        rows = cursor.fetchall()
        
        # Get column names
        column_names = [description[0] for description in cursor.description] if cursor.description else []
        
        # Convert rows to list of dictionaries
        data = []
        for row in rows:
            row_dict = {}
            for i, value in enumerate(row):
                column_name = column_names[i] if i < len(column_names) else f"column_{i}"
                row_dict[column_name] = value
            data.append(row_dict)
        
        if logger:
            logger.info("Query executed successfully", 
                       query=query, 
                       row_count=len(data))
        
        return QueryResponse(data=data, rowCount=len(data))
        
    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error executing query", query=request.query, error=str(e))
        raise HTTPException(status_code=500, detail=f"Query execution failed: {str(e)}")

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
