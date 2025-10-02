"""
Health and System Management Router

Handles:
- Health checks
- System status
- Heartbeat messages
- Shutdown operations
- Settings management
"""

from fastapi import APIRouter, HTTPException
from typing import Dict

from ..models import SessionState, SettingValue, SettingUpdate
from ..dependencies import get_logger, get_controller

router = APIRouter()

# Get dependencies at module level
logger = None
controller = None
config = None


def initialize(log, ctrl, cfg):
    """Initialize module-level dependencies."""
    global logger, controller, config
    logger = log
    controller = ctrl
    config = cfg


@router.get("/")
async def root():
    """Health check endpoint."""
    return {"message": "TowerIQ API Server is running", "version": "1.0.0"}


@router.options("/api/{path:path}")
async def options_handler(path: str):
    """Handle preflight OPTIONS requests for all API endpoints."""
    return {"message": "OK"}


@router.get("/api/status")
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
                test_mode=controller._test_mode,
                connection_state=session_state.get("connection_state"),
                connection_sub_state=session_state.get("connection_sub_state"),
                device_monitoring_active=session_state.get("device_monitoring_active", False),
                last_error=session_state.get("last_error")
            ),
            "loading_complete": controller.loading_manager.is_loading_complete()
        }
    except Exception as e:
        if logger:
            logger.error("Error getting status", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/heartbeat")
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


@router.post("/api/shutdown")
async def shutdown_services():
    """Close services and database to ensure journal cleanup. Does not exit the process."""
    try:
        # Stop controller background operations and detach frida if possible
        try:
            if controller:
                controller.stop_background_operations()
                # Best-effort: detach frida without raising
                try:
                    await controller.frida_service.detach()
                except Exception:
                    pass
                controller.shutdown()
        except Exception as e:
            if logger:
                logger.warning("Error during controller shutdown", error=str(e))

        # Import db_service here to avoid circular import
        from ..dependencies import get_db_service
        try:
            db_service = get_db_service()
            db_service.close()
        except Exception as e:
            if logger:
                logger.warning("Error during database close", error=str(e))

        return {"message": "Shutdown sequence completed"}
    except Exception as e:
        if logger:
            logger.error("Error in shutdown endpoint", error=str(e))
        raise HTTPException(status_code=500, detail=f"Shutdown failed: {str(e)}")


@router.get("/api/settings/get/{setting_key:path}", response_model=SettingValue)
async def get_setting(setting_key: str):
    """Get a specific setting value by key."""
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")

        # Get the setting value, defaulting to False for boolean settings
        value = config.get(setting_key, False if 'enabled' in setting_key else None)

        if logger:
            logger.debug("Retrieved setting", key=setting_key, value=value)

        return SettingValue(value=value)
    except Exception as e:
        if logger:
            logger.error("Error getting setting", key=setting_key, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get setting: {str(e)}")


@router.post("/api/settings/set", response_model=SettingValue)
async def set_setting(update: SettingUpdate):
    """Set a specific setting value."""
    try:
        if not config:
            raise HTTPException(status_code=503, detail="Configuration not available")

        # Set the setting with appropriate description
        description = f"User setting for {update.key}"
        if update.key == 'developer.mode.enabled':
            description = "Enable developer mode features and debugging tools"

        config.set(update.key, update.value, description=description)

        if logger:
            logger.info("Updated setting", key=update.key, value=update.value)

        return SettingValue(value=update.value)
    except Exception as e:
        if logger:
            logger.error("Error setting value", key=update.key, value=update.value, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to set setting: {str(e)}")

