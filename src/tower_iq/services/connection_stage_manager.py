"""
TowerIQ Connection Stage Manager

This module provides the ConnectionStageManager class for orchestrating
the multi-stage connection process with transparent progress tracking.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum

from ..core.session import SessionManager
from .emulator_service import EmulatorService
from .frida_service import FridaService


class StageStatus(Enum):
    """Connection stage status enumeration."""
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ConnectionStageInfo:
    """Information about a connection stage."""
    stage_name: str
    display_name: str
    description: str
    status: StageStatus = StageStatus.PENDING
    message: str = ""
    progress_percent: Optional[int] = None
    error_details: Optional[str] = None
    retry_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class ConnectionStageManager:
    """
    Manages the multi-stage connection process with transparent progress tracking.

    This class orchestrates the connection flow through defined stages:
    1. Device selection (handled externally)
    2. Process selection (handled externally)
    3. Frida server check
    4. Frida server install
    5. Frida server start
    6. Frida server verify
    7. Hook compatibility check
    8. Process attachment
    9. Script injection
    10. Connection active
    """

    def __init__(self, session_manager: SessionManager, emulator_service: EmulatorService,
                 frida_service: FridaService, logger: Any):
        """
        Initialize the connection stage manager.

        Args:
            session_manager: Session manager for state updates
            emulator_service: Emulator service for device operations
            frida_service: Frida service for script operations
            logger: Logger instance
        """
        self.logger = logger.bind(source="ConnectionStageManager")
        self.session_manager = session_manager
        self.emulator_service = emulator_service
        self.frida_service = frida_service
        self.current_hook_script: Optional[str] = None

        # Define connection stages
        self.stages = [
            ConnectionStageInfo(
                stage_name="frida_server_check",
                display_name="Checking Frida Server",
                description="Verifying if Frida server is already running on device"
            ),
            ConnectionStageInfo(
                stage_name="frida_server_install",
                display_name="Installing Frida Server",
                description="Downloading and installing Frida server binary"
            ),
            ConnectionStageInfo(
                stage_name="frida_server_start",
                display_name="Starting Frida Server",
                description="Starting Frida server process on device"
            ),
            ConnectionStageInfo(
                stage_name="frida_server_verify",
                display_name="Verifying Frida Server",
                description="Testing Frida server connection and functionality"
            ),
            ConnectionStageInfo(
                stage_name="hook_compatibility_check",
                display_name="Validating Hook Script",
                description="Checking hook script compatibility with target app"
            ),
            ConnectionStageInfo(
                stage_name="process_attachment",
                display_name="Attaching to Process",
                description="Attaching Frida to the target application process"
            ),
            ConnectionStageInfo(
                stage_name="script_injection",
                display_name="Injecting Hook Script",
                description="Loading and executing the hook script in target process"
            )
        ]

        # Create stage lookup
        self.stage_map = {stage.stage_name: stage for stage in self.stages}

        # Current execution state
        self.current_device_id: Optional[str] = None
        self.current_process_info: Optional[Dict] = None
        self.is_executing = False

        # Retry configuration
        self.max_retries = {
            "frida_server_check": 2,
            "frida_server_install": 1,
            "frida_server_start": 2,
            "frida_server_verify": 3,
            "hook_compatibility_check": 1,
            "process_attachment": 2,
            "script_injection": 1
        }

    async def execute_connection_flow(self, device_id: str, process_info: Dict, hook_script_content: Optional[str] = None) -> bool:
        """
        Execute the complete connection flow with stage tracking.

        Args:
            device_id: Device serial ID
            process_info: Process information dictionary
            hook_script_content: Optional hook script content to inject

        Returns:
            True if connection flow completed successfully, False otherwise
        """
        if self.is_executing:
            self.logger.warning("Connection flow already in progress")
            return False

        self.logger.info("Starting connection flow", device=device_id,
                         package=process_info.get('package'))

        self.is_executing = True
        self.current_device_id = device_id
        self.current_process_info = process_info
        self.current_hook_script = hook_script_content

        try:
            # Reset all stages to pending
            self._reset_stages()

            # Update session manager with initial state
            self._update_session_stage(
                "checking_frida", "Starting connection process...")

            # Execute each stage in sequence
            for stage in self.stages:
                success = await self._execute_stage(stage)
                # Emit live updates for UI after every stage execution
                try:
                    self.session_manager.update_connection_stages(self.get_all_stages_status())
                except Exception:
                    pass
                if not success:
                    self.logger.error("Connection flow failed",
                                      stage=stage.stage_name)
                    self._update_session_stage(
                        "failed", f"Failed at {stage.display_name}")
                    return False

            # All stages completed successfully
            self.logger.info("Connection flow completed successfully")
            self._update_session_stage(
                "success", "Connection established successfully")
            return True

        except Exception as e:
            self.logger.error(
                "Unexpected error in connection flow", error=str(e))
            self._update_session_stage("failed", f"Unexpected error: {str(e)}")
            return False
        finally:
            self.is_executing = False

    async def _execute_stage(self, stage: ConnectionStageInfo) -> bool:
        """
        Execute an individual stage with error handling and retry logic.

        Args:
            stage: Stage information

        Returns:
            True if stage completed successfully, False otherwise
        """
        self.logger.info("Executing stage", stage=stage.stage_name)

        stage.status = StageStatus.ACTIVE
        stage.start_time = datetime.now()
        stage.retry_count = 0

        # Update session manager
        self._update_session_stage(stage.stage_name, stage.description)

        max_retries = self.max_retries.get(stage.stage_name, 1)

        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    stage.retry_count = attempt
                    self.logger.info("Retrying stage",
                                     stage=stage.stage_name, attempt=attempt)
                    # Add delay between retries
                    await asyncio.sleep(min(attempt * 2, 5))

                # Execute the stage-specific logic
                success = await self._execute_stage_logic(stage)

                if success:
                    stage.status = StageStatus.COMPLETED
                    stage.end_time = datetime.now()
                    stage.message = "Completed successfully"
                    self.logger.info("Stage completed", stage=stage.stage_name)
                    return True
                else:
                    if attempt < max_retries:
                        self.logger.warning("Stage failed, will retry",
                                            stage=stage.stage_name, attempt=attempt)
                        continue
                    else:
                        stage.status = StageStatus.FAILED
                        stage.end_time = datetime.now()
                        stage.error_details = "Stage execution failed after all retries"
                        self.logger.error(
                            "Stage failed after all retries", stage=stage.stage_name)
                        return False

            except Exception as e:
                error_msg = str(e)
                self.logger.error("Error executing stage", stage=stage.stage_name,
                                  error=error_msg, attempt=attempt)

                if attempt < max_retries:
                    continue
                else:
                    stage.status = StageStatus.FAILED
                    stage.end_time = datetime.now()
                    stage.error_details = error_msg
                    return False

        return False

    async def _execute_stage_logic(self, stage: ConnectionStageInfo) -> bool:
        """
        Execute the logic for a specific stage.

        Args:
            stage: Stage information

        Returns:
            True if stage logic completed successfully, False otherwise
        """
        stage_name = stage.stage_name
        device_id = self.current_device_id
        process_info = self.current_process_info

        if not device_id or not process_info:
            raise ValueError("Device ID or process info not set")

        if stage_name == "frida_server_check":
            return await self._check_frida_server(device_id)
        elif stage_name == "frida_server_install":
            return await self._install_frida_server(device_id)
        elif stage_name == "frida_server_start":
            return await self._start_frida_server(device_id)
        elif stage_name == "frida_server_verify":
            return await self._verify_frida_server(device_id)
        elif stage_name == "hook_compatibility_check":
            return await self._check_hook_compatibility(process_info)
        elif stage_name == "process_attachment":
            return await self._attach_to_process(device_id, process_info)
        elif stage_name == "script_injection":
            return await self._inject_script()
        else:
            raise ValueError(f"Unknown stage: {stage_name}")

    async def _check_frida_server(self, device_id: str) -> bool:
        """Check if Frida server is already running."""
        try:
            # Frida server management is now handled by FridaServerManager
            # The ensure_frida_server_is_running method handles all server management
            # For now, we'll assume we need to run the full setup process
            self.logger.info("Proceeding with Frida server setup")
            return True  # Continue to installation
        except Exception as e:
            self.logger.warning("Error checking Frida server", error=str(e))
            return True  # Continue to installation anyway

    async def _install_frida_server(self, device_id: str) -> bool:
        """Install Frida server on the device."""
        try:
            # This will download and push the server if needed
            await self.emulator_service.ensure_frida_server_is_running(device_identifier=device_id)
            return True
        except Exception as e:
            self.logger.error("Error installing Frida server", error=str(e))
            return False

    async def _start_frida_server(self, device_id: str) -> bool:
        """Start Frida server process."""
        try:
            # Frida server management is now handled by FridaServerManager
            # The ensure_frida_server_is_running method handles starting the server
            await self.emulator_service.ensure_frida_server_is_running(device_identifier=device_id)
            return True
        except Exception as e:
            self.logger.error("Error starting Frida server", error=str(e))
            return False

    async def _verify_frida_server(self, device_id: str) -> bool:
        """Verify Frida server is responsive."""
        try:
            # Frida server verification is now handled by FridaServerManager
            # The ensure_frida_server_is_running method includes verification
            await self.emulator_service.ensure_frida_server_is_running(device_identifier=device_id)
            return True
        except Exception as e:
            self.logger.error("Error verifying Frida server", error=str(e))
            return False

    async def _check_hook_compatibility(self, process_info: Dict) -> bool:
        """Check hook script compatibility."""
        try:
            package_name = process_info.get('package')
            version = process_info.get('version', 'Unknown')

            if not package_name:
                self.logger.error("No package name in process info")
                return False

            is_compatible = self.frida_service.check_local_hook_compatibility(
                package_name, version)

            if not is_compatible:
                self.logger.error("Hook script not compatible",
                                  package=package_name, version=version)
                return False

            return True
        except Exception as e:
            self.logger.error(
                "Error checking hook compatibility", error=str(e))
            return False

    async def _attach_to_process(self, device_id: str, process_info: Dict) -> bool:
        """Attach Frida to the target process."""
        try:
            pid = process_info.get('pid')
            if not pid:
                self.logger.error("No PID in process info")
                return False

            success = await self.frida_service.attach(pid, device_id)
            if not success:
                self.logger.error("Failed to attach to process", pid=pid)
                return False

            return True
        except Exception as e:
            self.logger.error("Error attaching to process", error=str(e))
            return False

    async def _inject_script(self) -> bool:
        """Inject the hook script using the provided script content."""
        try:
            if not self.current_hook_script:
                self.logger.error("No hook script content provided for injection")
                return False
            success = await self.frida_service.inject_script(self.current_hook_script)

            if not success:
                self.logger.error("Failed to inject script")
                return False

            return True
        except Exception as e:
            self.logger.error("Error injecting script", error=str(e))
            return False

    def _skip_stage(self, stage_name: str):
        """Mark a stage as skipped."""
        if stage_name in self.stage_map:
            stage = self.stage_map[stage_name]
            stage.status = StageStatus.SKIPPED
            stage.message = "Skipped (not needed)"
            self.logger.info("Stage skipped", stage=stage_name)

    def _reset_stages(self):
        """Reset all stages to pending status."""
        for stage in self.stages:
            stage.status = StageStatus.PENDING
            stage.message = ""
            stage.progress_percent = None
            stage.error_details = None
            stage.retry_count = 0
            stage.start_time = None
            stage.end_time = None

    def _update_session_stage(self, stage: str, message: str):
        """Update session manager with current stage information."""
        # Legacy no-op in favor of live stage list updates via update_connection_stages()
        try:
            pass
        except Exception:
            pass

    def get_stage_status(self, stage_name: str) -> Optional[ConnectionStageInfo]:
        """Get the status of a specific stage."""
        return self.stage_map.get(stage_name)

    def get_all_stages_status(self) -> List[ConnectionStageInfo]:
        """Get the status of all stages."""
        return self.stages.copy()

    async def cancel_connection_flow(self):
        """Cancel the current connection flow."""
        if self.is_executing:
            self.logger.info("Cancelling connection flow")
            self.is_executing = False

            # Clean up any active connections
            try:
                if self.frida_service.session:
                    await self.frida_service.detach()
            except Exception as e:
                self.logger.warning("Error during cleanup", error=str(e))

            self._update_session_stage(
                "cancelled", "Connection flow cancelled")

    def is_connection_active(self) -> bool:
        """Check if connection flow is currently active."""
        return self.is_executing

    async def retry_failed_stage(self, stage_name: str) -> bool:
        """
        Retry a specific failed stage.

        Args:
            stage_name: Name of the stage to retry

        Returns:
            True if retry was successful, False otherwise
        """
        if not self.current_device_id or not self.current_process_info:
            self.logger.error("Cannot retry: no active connection context")
            return False

        if stage_name not in self.stage_map:
            self.logger.error("Cannot retry: unknown stage", stage=stage_name)
            return False

        stage = self.stage_map[stage_name]
        if stage.status != StageStatus.FAILED:
            self.logger.warning("Cannot retry: stage is not in failed state",
                                stage=stage_name, status=stage.status)
            return False

        self.logger.info("Retrying failed stage", stage=stage_name)

        # Reset the stage
        stage.status = StageStatus.PENDING
        stage.error_details = None
        stage.retry_count = 0

        # Execute the stage
        success = await self._execute_stage(stage)

        if success:
            # Continue with remaining stages
            remaining_stages = []
            found_current = False
            for s in self.stages:
                if s.stage_name == stage_name:
                    found_current = True
                    continue
                if found_current and s.status == StageStatus.PENDING:
                    remaining_stages.append(s)

            # Execute remaining stages
            for remaining_stage in remaining_stages:
                success = await self._execute_stage(remaining_stage)
                if not success:
                    self._update_session_stage(
                        "failed", f"Failed at {remaining_stage.display_name}")
                    return False

            # All stages completed
            self._update_session_stage(
                "success", "Connection established successfully")
            return True
        else:
            self._update_session_stage(
                "failed", f"Retry failed at {stage.display_name}")
            return False

    def get_user_friendly_error_message(self, stage_name: str, error: Exception) -> str:
        """
        Convert technical errors to user-friendly messages with suggested actions.

        Args:
            stage_name: Name of the stage that failed
            error: The exception that occurred

        Returns:
            User-friendly error message with suggestions
        """
        error_str = str(error).lower()

        # Stage-specific error messages
        if stage_name == "frida_server_check":
            return "Unable to check Frida server status. Please ensure the device is connected and accessible."

        elif stage_name == "frida_server_install":
            if "network" in error_str or "download" in error_str or "connection" in error_str:
                return "Failed to download Frida server. Please check your internet connection and try again."
            elif "permission" in error_str or "denied" in error_str:
                return "Permission denied while installing Frida server. Please ensure the device has root access."
            elif "space" in error_str or "storage" in error_str:
                return "Insufficient storage space on device. Please free up some space and try again."
            else:
                return "Failed to install Frida server. Please check device connectivity and try again."

        elif stage_name == "frida_server_start":
            if "permission" in error_str or "denied" in error_str:
                return "Permission denied while starting Frida server. Please ensure the device has root access."
            elif "port" in error_str or "address" in error_str:
                return "Port conflict detected. Please restart the device and try again."
            else:
                return "Failed to start Frida server. Please check device permissions and try again."

        elif stage_name == "frida_server_verify":
            if "timeout" in error_str or "connection" in error_str:
                return "Frida server is not responding. Please check device connectivity and try again."
            elif "version" in error_str or "compatibility" in error_str:
                return "Frida server version mismatch. Please update your Frida installation."
            else:
                return "Frida server verification failed. Please restart the connection process."

        elif stage_name == "hook_compatibility_check":
            if "version" in error_str or "compatibility" in error_str:
                return "Hook script is not compatible with this app version. Please check for script updates."
            elif "package" in error_str or "not found" in error_str:
                return "Target application not found or not supported. Please select a different app."
            else:
                return "Hook compatibility check failed. Please verify the target application."

        elif stage_name == "process_attachment":
            if "permission" in error_str or "denied" in error_str:
                return "Permission denied while attaching to process. Please ensure proper device permissions."
            elif "process" in error_str or "not found" in error_str:
                return "Target process not found. Please ensure the application is running and try again."
            elif "timeout" in error_str:
                return "Process attachment timed out. Please try again or restart the target application."
            else:
                return "Failed to attach to target process. Please restart the application and try again."

        elif stage_name == "script_injection":
            if "permission" in error_str or "denied" in error_str:
                return "Permission denied during script injection. Please check device security settings."
            elif "script" in error_str or "syntax" in error_str:
                return "Hook script error detected. Please check for script updates."
            elif "memory" in error_str or "allocation" in error_str:
                return "Insufficient memory for script injection. Please close other applications and try again."
            else:
                return "Script injection failed. Please restart the target application and try again."

        # Generic fallback message
        return f"An error occurred during {stage_name.replace('_', ' ')}. Please try again or restart the connection process."

    def get_retry_suggestion(self, stage_name: str) -> str:
        """
        Get specific retry suggestions for a failed stage.

        Args:
            stage_name: Name of the failed stage

        Returns:
            Specific suggestion for resolving the issue
        """
        suggestions = {
            "frida_server_check": "Try refreshing the device connection or restarting the device.",
            "frida_server_install": "Check internet connection and device storage space.",
            "frida_server_start": "Ensure device has root access and restart if needed.",
            "frida_server_verify": "Check device connectivity and Frida installation.",
            "hook_compatibility_check": "Verify the target application version is supported.",
            "process_attachment": "Ensure the target application is running and accessible.",
            "script_injection": "Close other applications to free up memory and try again."
        }

        return suggestions.get(stage_name, "Try restarting the connection process from the beginning.")

    def get_connection_health_status(self) -> Dict[str, Any]:
        """
        Get overall connection health status and diagnostics.

        Returns:
            Dictionary containing health status information
        """
        completed_stages = [
            s for s in self.stages if s.status == StageStatus.COMPLETED]
        failed_stages = [
            s for s in self.stages if s.status == StageStatus.FAILED]
        active_stages = [
            s for s in self.stages if s.status == StageStatus.ACTIVE]

        total_retry_count = sum(s.retry_count for s in self.stages)

        return {
            "total_stages": len(self.stages),
            "completed_stages": len(completed_stages),
            "failed_stages": len(failed_stages),
            "active_stages": len(active_stages),
            "total_retries": total_retry_count,
            "is_healthy": len(failed_stages) == 0 and not self.is_executing,
            "current_stage": active_stages[0].stage_name if active_stages else None,
            "last_error": failed_stages[-1].error_details if failed_stages else None
        }
