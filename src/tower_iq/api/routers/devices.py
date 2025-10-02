"""
Device Management Router

Handles:
- Device discovery
- Device listing with caching
- Process enumeration per device
- Device disconnection simulation (testing)
"""

from fastapi import APIRouter, HTTPException
from ..cache_utils import get_cached_devices, get_device_by_id, device_dict_to_device_object

router = APIRouter()

# Module-level dependencies
logger = None
controller = None


def initialize(log, ctrl):
    """Initialize module-level dependencies."""
    global logger, controller
    logger = log
    controller = ctrl


@router.get("/api/devices")
async def get_devices():
    """Get available devices using cached results when possible."""
    try:
        device_dicts = await get_cached_devices(controller, logger, force_refresh=False)
        return {"devices": device_dicts}
    except Exception as e:
        if logger:
            logger.error("Error getting devices", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/devices/refresh")
async def refresh_devices():
    """Refresh device list with cache clearing."""
    try:
        device_dicts = await get_cached_devices(controller, logger, force_refresh=True)
        return {"devices": device_dicts}
    except Exception as e:
        if logger:
            logger.error("Error refreshing devices", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/{device_id}/processes")
async def get_processes(device_id: str):
    """Get processes for a specific device."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")

    try:
        # First get the device to pass to the process listing method
        if not controller.emulator_service:
            raise HTTPException(status_code=503, detail="Emulator service not initialized")

        # Get device from cache to avoid redundant discovery
        device_dict = await get_device_by_id(controller, logger, device_id)
        if not device_dict:
            if logger:
                logger.warning("Device not found", device_id=device_id)
            return {"processes": [], "message": "Device not found"}

        # Convert device dict back to Device object for compatibility
        device = device_dict_to_device_object(device_dict)

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
            logger.info("Retrieved processes for device", device_id=device_id,
                       count=len(process_dicts), target_found=target_found)
        return {
            "processes": process_dicts,
            "target_found": target_found,
            "total_count": len(process_dicts)
        }

    except Exception as e:
        if logger:
            logger.error("Error getting processes", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/test/simulate-device-disconnection")
async def simulate_device_disconnection():
    """Simulate device disconnection for testing purposes."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")

        if not controller.session:
            raise HTTPException(status_code=500, detail="Session manager not available")

        # Import here to avoid circular import
        from tower_iq.core.session import ConnectionState

        # Check if we're connected to a device
        if controller.session.connection_main_state not in [ConnectionState.CONNECTED, ConnectionState.ACTIVE]:
            raise HTTPException(status_code=400, detail="No device connected to simulate disconnection")

        # Trigger the simulation
        controller.session.simulate_device_disconnection()

        if logger:
            logger.info("Device disconnection simulation triggered via API")

        return {"message": "Device disconnection simulation triggered"}

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error simulating device disconnection", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to simulate device disconnection: {str(e)}")

