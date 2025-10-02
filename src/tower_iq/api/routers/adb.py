"""
ADB Server Management Router

Handles Android Debug Bridge (ADB) server lifecycle operations:
- Start ADB server
- Stop ADB server
- Restart ADB server
- Get ADB server status
"""

from fastapi import APIRouter, HTTPException

router = APIRouter()

# Module-level dependencies
logger = None
controller = None


def initialize(log, ctrl):
    """Initialize module-level dependencies."""
    global logger, controller
    logger = log
    controller = ctrl


@router.post("/api/adb/start")
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


@router.post("/api/adb/kill")
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


@router.post("/api/adb/restart")
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


@router.get("/api/adb/status")
async def get_adb_status():
    """Return whether the local ADB server is running and its version."""
    try:
        if not controller:
            raise HTTPException(status_code=503, detail="Backend not initialized")

        running = await controller.emulator_service.is_adb_server_running()
        version = await controller.emulator_service.get_adb_version()
        return {"running": running, "version": version}
    except Exception as e:
        if logger:
            logger.error("Error getting ADB status", error=str(e))
        # Return a safe default rather than 500 so UI can still render
        return {"running": False, "version": None, "error": str(e)}

