"""
Hook Scripts Management Router

Handles:
- Compatible script discovery
- Available scripts listing
- Script status monitoring
"""

from fastapi import APIRouter, HTTPException

from ..models import ScriptCompatibilityRequest

router = APIRouter()

# Module-level dependencies
logger = None
controller = None


def initialize(log, ctrl):
    """Initialize module-level dependencies."""
    global logger, controller
    logger = log
    controller = ctrl


@router.post("/api/compatible-scripts")
async def get_compatible_scripts(request: ScriptCompatibilityRequest):
    """Get compatible scripts for a package and version."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")

    try:
        package_name = request.package_name
        app_version = request.app_version

        if logger:
            logger.info("Getting compatible scripts", package_name=package_name, app_version=app_version)

        if not controller.hook_script_manager:
            return {"scripts": []}

        # Get compatible scripts
        compatible_scripts = controller.hook_script_manager.get_compatible_scripts(package_name, app_version)

        # Convert to frontend-friendly format
        scripts_for_frontend = []
        for script in compatible_scripts:
            scripts_for_frontend.append({
                "id": script.get("id", ""),
                "name": script.get("scriptName", script.get("fileName", "Unknown")),
                "description": script.get("scriptDescription", script.get("description", "No description")),
                "fileName": script.get("fileName", ""),
                "targetPackage": script.get("targetPackage", ""),
                "supportedVersions": script.get("supportedVersions", [])
            })

        if logger:
            logger.info("Returning compatible scripts", count=len(scripts_for_frontend))

        return {"scripts": scripts_for_frontend}
    except Exception as e:
        if logger:
            logger.error("Error getting compatible scripts", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/available-scripts")
async def get_available_scripts():
    """Get all available scripts."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")

    try:
        if logger:
            logger.info("Getting all available scripts")

        if not controller.hook_script_manager:
            return {"scripts": []}

        # Get all available scripts
        available_scripts = controller.hook_script_manager.get_available_scripts()

        # Convert to frontend-friendly format
        scripts_for_frontend = []
        for script in available_scripts:
            scripts_for_frontend.append({
                "id": script.get("id", ""),
                "name": script.get("name", script.get("fileName", "Unknown")),
                "description": script.get("description", "No description"),
                "fileName": script.get("fileName", ""),
                "targetPackage": script.get("targetPackage", ""),
                "supportedVersions": script.get("supportedVersions", [])
            })

        if logger:
            logger.info("Returning available scripts", count=len(scripts_for_frontend))

        return {"scripts": scripts_for_frontend}
    except Exception as e:
        if logger:
            logger.error("Error getting available scripts", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/hook-scripts")
async def get_hook_scripts():
    """Get available hook scripts."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")

    try:
        # Get scripts from the hook script manager
        scripts = controller.hook_script_manager.get_available_scripts()
        return {"scripts": scripts}
    except Exception as e:
        if logger:
            logger.error("Error getting hook scripts", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/script-status")
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

