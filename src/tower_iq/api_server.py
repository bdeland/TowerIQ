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
        logger.error("Error getting status", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/connect-device")
async def connect_device(request: ConnectionRequest, background_tasks: BackgroundTasks):
    """Connect to a device."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # For now, we'll just update the session state directly
        # In a full implementation, this would trigger the device connection flow
        def connect_device_task():
            try:
                # Update session state to indicate connection attempt
                if hasattr(controller.session, 'current_device'):
                    controller.session.current_device = request.device_serial
                logger.info("Device connection initiated", device_serial=request.device_serial)
            except Exception as e:
                logger.error("Error connecting device", error=str(e))
        
        background_tasks.add_task(connect_device_task)
        
        return {"message": "Device connection initiated", "device_serial": request.device_serial}
    except Exception as e:
        logger.error("Error initiating device connection", error=str(e))
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
        # Use the emulator service to get devices
        devices = await controller.emulator_service.list_devices_with_details()
        return {"devices": devices}
    except Exception as e:
        logger.error("Error getting devices", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/devices/{device_id}/processes")
async def get_processes(device_id: str):
    """Get processes for a specific device."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")
    
    try:
        # Use the emulator service to get processes for the device
        processes = await controller.emulator_service.get_processes(device_id)
        return {"processes": processes}
    except Exception as e:
        logger.error("Error getting processes", error=str(e))
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
