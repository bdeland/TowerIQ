"""
Frida Server Management Router

Handles Frida server lifecycle operations on Android devices:
- Health checks
- Status monitoring
- Provisioning
- Start/Stop operations
- Installation/Removal
"""

from typing import Dict, Any
from fastapi import APIRouter, HTTPException
from ..cache_utils import get_device_by_id

router = APIRouter()

# Module-level dependencies
logger = None
controller = None


def initialize(log, ctrl):
    """Initialize module-level dependencies."""
    global logger, controller
    logger = log
    controller = ctrl


@router.get("/api/health/frida")
async def get_frida_health():
    """Get the health status of Frida-related services."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")

    try:
        health_status: Dict[str, Any] = {
            "controller_available": controller is not None,
            "emulator_service_available": controller.emulator_service is not None if controller else False,
            "frida_service_available": controller.frida_service is not None if controller else False
        }

        # Try to import frida to check if it's available
        try:
            import frida
            health_status["frida_library_available"] = True
            health_status["frida_version"] = frida.__version__
        except ImportError:
            health_status["frida_library_available"] = False
            health_status["frida_version"] = None

        # Check if we can connect to Frida
        if controller and controller.frida_service:
            try:
                # This is a lightweight check - just verify service exists
                health_status["frida_service_status"] = "available"
            except Exception as e:
                health_status["frida_service_status"] = f"error: {str(e)}"
        else:
            health_status["frida_service_status"] = "not available"

        return health_status
    except Exception as e:
        if logger:
            logger.error("Error getting Frida health", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/{device_id}/frida-status")
async def get_frida_status(device_id: str):
    """Get Frida server status for a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")

        # Get the device to check Frida status using cached results
        device_dict = await get_device_by_id(controller, logger, device_id)
        if not device_dict:
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

        # Get local Frida library version
        try:
            import frida
            local_version = frida.__version__
        except ImportError:
            local_version = None

        return {
            "device_id": device_id,
            "is_installed": is_installed,
            "is_running": is_running,
            "server_version": frida_version,
            "local_version": local_version,
            "versions_match": frida_version == local_version if frida_version and local_version else None
        }

    except Exception as e:
        if logger:
            logger.error("Error getting Frida status", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get Frida status: {str(e)}")


@router.post("/api/devices/{device_id}/frida-provision")
async def provision_frida_server(device_id: str):
    """Provision Frida server on a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")

        if not controller.emulator_service:
            raise HTTPException(status_code=500, detail="Emulator service not available")

        if not controller.emulator_service.frida_manager:
            raise HTTPException(status_code=500, detail="Frida manager not available")

        # Get the device to provision Frida server using cached results
        try:
            device_dict = await get_device_by_id(controller, logger, device_id)
            if not device_dict:
                raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
        except Exception as e:
            if logger:
                logger.error("Error getting device info for provisioning", device_id=device_id, error=str(e))
            raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

        # Get architecture from device
        architecture = device_dict.get('architecture', 'x86_64')

        # Get the target Frida version
        try:
            import frida
            target_version = frida.__version__
        except ImportError:
            if logger:
                logger.error("Frida library not available for provisioning")
            raise HTTPException(status_code=500, detail="Frida library not available")

        # Provision the Frida server (install + start)
        try:
            result = await controller.emulator_service.frida_manager.provision_server(
                device_id, architecture, target_version
            )
            if result:
                return {"message": "Frida server provisioned successfully", "device_id": device_id}
            else:
                raise HTTPException(status_code=500, detail="Failed to provision Frida server")
        except Exception as e:
            if logger:
                logger.error("Error provisioning Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to provision Frida server: {str(e)}")

    except HTTPException:
        raise
    except Exception as e:
        if logger:
            logger.error("Error in Frida provision", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to provision Frida server: {str(e)}")


@router.post("/api/devices/{device_id}/frida-start")
async def start_frida_server(device_id: str):
    """Start Frida server on a specific device."""
    try:
        if not controller:
            raise HTTPException(status_code=500, detail="Controller not available")

        # Get the device to start Frida server using cached results
        device_dict = await get_device_by_id(controller, logger, device_id)
        if not device_dict:
            raise HTTPException(status_code=404, detail="Device not found")

        # Start Frida server
        try:
            success = await controller.emulator_service.frida_manager.start_server(device_id)

            if success:
                return {"message": "Frida server started successfully", "device_id": device_id}
            else:
                raise HTTPException(status_code=500, detail="Failed to start Frida server")

        except Exception as e:
            if logger:
                logger.error("Error starting Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to start Frida server: {str(e)}")

    except Exception as e:
        if logger:
            logger.error("Error in Frida server start", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to start Frida server: {str(e)}")


@router.post("/api/devices/{device_id}/frida-stop")
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
            if logger:
                logger.error("Error stopping Frida server", device_id=device_id, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to stop Frida server: {str(e)}")

    except Exception as e:
        if logger:
            logger.error("Error in Frida server stop", device_id=device_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to stop Frida server: {str(e)}")


@router.post("/api/devices/{device_id}/frida-install")
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


@router.post("/api/devices/{device_id}/frida-remove")
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

