"""
Connection and Hook Management Router

Handles:
- Device connection/disconnection
- Hook activation/deactivation
- Test mode configuration
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks

from ..models import ConnectionRequest, HookActivationRequest, HookDeactivationRequest, TestModeRequest

router = APIRouter()

# Module-level dependencies
logger = None
controller = None


def initialize(log, ctrl):
    """Initialize module-level dependencies."""
    global logger, controller
    logger = log
    controller = ctrl


@router.post("/api/connect")
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


@router.post("/api/disconnect")
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


@router.post("/api/activate-hook")
async def activate_hook(request: HookActivationRequest, background_tasks: BackgroundTasks):
    """Activate a hook script."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")

    try:
        # Extract process info
        process_info = request.process_info
        device_id = request.device_id
        script_id = request.script_id
        script_name = request.script_name

        # Get the process ID from the process info
        pid = process_info.get('pid')
        if not pid:
            raise HTTPException(status_code=400, detail="Process ID not found in process info")

        # Always load script content on backend using id/name; UI does not send content
        script_content = None
        if controller.hook_script_manager:
            package_name = process_info.get('package', '')
            version = process_info.get('version', 'Unknown')

            if logger:
                logger.info(
                    "Loading script based on selection",
                    script_id=script_id,
                    script_name=script_name,
                    package_name=package_name,
                    version=version,
                )

            # Load script by ID first, then by name, then fallback to compatible scripts
            if script_id:
                script_content = await controller._load_script_by_id(script_id)
            elif script_name:
                script_content = await controller._load_script_by_name(script_name, package_name, version)
            else:
                script_content = await controller._load_compatible_script(package_name, version)

            if script_content and logger:
                logger.info(
                    "Script content loaded successfully",
                    script_id=script_id,
                    script_name=script_name,
                    content_length=len(script_content),
                )

        if not script_content:
            # Provide actionable error with discovered scripts
            available = []
            try:
                if controller and controller.hook_script_manager:
                    scripts = controller.hook_script_manager.get_available_scripts()
                    available = [s.get("fileName") or s.get("name") for s in scripts]
            except Exception:
                pass
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "No script content available",
                    "hint": "Ensure the script metadata fileName matches the actual filename or pass raw script_content.",
                    "available_scripts": available,
                },
            )

        if logger:
            logger.info("Starting hook activation",
                       device_id=device_id,
                       pid=pid,
                       script_id=script_id,
                       script_name=script_name,
                       content_length=len(script_content))

        frida_service = controller.frida_service
        session_manager = getattr(controller, "session", None)
        activation_successful = False
        attach_attempted = False

        try:
            # Use the Frida service to attach and inject the script (no fallbacks)
            attach_attempted = True
            attached = await frida_service.attach(pid, device_id)
            if not attached:
                raise HTTPException(status_code=500, detail="Failed to attach to process")

            success = await frida_service.inject_script(script_content)

            if not success:
                raise HTTPException(status_code=500, detail="Failed to inject hook script")

            activation_successful = True
        except HTTPException:
            raise
        except Exception as frida_error:
            raise HTTPException(status_code=500, detail=str(frida_error))
        finally:
            if attach_attempted and not activation_successful:
                try:
                    await frida_service.detach()
                except Exception as detach_error:
                    if logger:
                        logger.warning("Failed to detach after unsuccessful activation",
                                     error=str(detach_error))

                if session_manager:
                    try:
                        session_manager.set_script_inactive()
                    except Exception as session_error:
                        if logger:
                            logger.warning("Failed to mark script inactive after activation failure",
                                         error=str(session_error))

                    try:
                        session_manager.frida_script = None
                        session_manager.frida_session = None
                        session_manager.frida_device = None
                        session_manager.frida_attached_pid = None
                    except Exception as session_error:
                        if logger:
                            logger.warning("Failed to reset session manager Frida state",
                                         error=str(session_error))

        # Start background message processing only after successful injection
        controller.start_background_operations()
        if logger:
            logger.info("Hook script injected successfully", device_id=device_id, pid=pid)

        return {"message": "Hook script injected successfully"}
    except HTTPException as e:
        if logger:
            logger.error("Error initiating hook activation", error=str(e))
        raise
    except Exception as e:
        if logger:
            logger.error("Error initiating hook activation", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/deactivate-hook")
async def deactivate_hook(request: HookDeactivationRequest, background_tasks: BackgroundTasks):
    """Deactivate a hook script."""
    if not controller:
        raise HTTPException(status_code=503, detail="Backend not initialized")

    try:
        if logger:
            logger.info("Deactivating hook and detaching Frida")

        # Stop background message processing first so no further get_message calls occur
        controller.stop_background_operations()

        # Detach from Frida (graceful with fallback to force cleanup inside)
        await controller.frida_service.detach()

        # Mark script inactive at session level for good measure
        try:
            controller.session.set_script_inactive()
        except Exception:
            pass

        if logger:
            logger.info("Hook deactivated and Frida detached successfully")

        return {"message": "Hook deactivated successfully"}
    except Exception as e:
        if logger:
            logger.error("Error initiating hook deactivation", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/test-mode")
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
        if logger:
            logger.error("Error setting test mode", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

