"""
TowerIQ Connection Flow Controller

This module provides the ConnectionFlowController class for centralized
connection flow orchestration with proper error handling and state management.
"""

import asyncio
import random
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable, Union
from enum import Enum

from PyQt6.QtCore import QObject, pyqtSignal

from ..core.session import (
    SessionManager, ConnectionState, ConnectionSubState, ErrorInfo, ErrorType,
    StageProgress, StageStatus, StateInconsistency
)
from ..core.cleanup_manager import ResourceCleanupManager, ServiceLifecycle
from .connection_stage_manager import ConnectionStageManager
from .emulator_service import EmulatorService
from .frida_service import FridaService
import structlog

logger = structlog.get_logger(__name__)


class ConnectionFlowError(Exception):
    """Base exception for connection flow errors."""
    pass


class ConnectionReadinessError(ConnectionFlowError):
    """Raised when system is not ready for connection."""
    pass


class StateTransitionError(ConnectionFlowError):
    """Raised when an invalid state transition is attempted."""
    pass


class CleanupLevel(Enum):
    """Levels of cleanup to perform during disconnection."""
    MINIMAL = "minimal"  # Just disconnect current session
    STANDARD = "standard"  # Standard cleanup with resource release
    FULL = "full"  # Complete cleanup including service reset


class RetryStrategy(Enum):
    """Retry strategies for different types of errors."""
    IMMEDIATE = "immediate"  # Retry immediately
    LINEAR_BACKOFF = "linear_backoff"  # Linear delay increase
    EXPONENTIAL_BACKOFF = "exponential_backoff"  # Exponential delay increase
    NO_RETRY = "no_retry"  # Don't retry


class ConnectionStage(Enum):
    """Connection stages for orchestration."""
    DEVICE_VALIDATION = "device_validation"
    PROCESS_VALIDATION = "process_validation"
    FRIDA_SERVER_SETUP = "frida_server_setup"
    HOOK_COMPATIBILITY = "hook_compatibility"
    PROCESS_ATTACHMENT = "process_attachment"
    SCRIPT_INJECTION = "script_injection"
    CONNECTION_VERIFICATION = "connection_verification"


class ConnectionFlowController(QObject):
    """
    Centralized controller for managing the entire connection flow lifecycle.
    
    This controller orchestrates connection establishment, state management,
    error handling, and resource cleanup across all services.
    """
    
    # Signals for flow events
    flow_started = pyqtSignal(str)  # flow_type
    flow_completed = pyqtSignal(str, bool)  # flow_type, success
    flow_error = pyqtSignal(str, object)  # flow_type, error_info
    state_validation_failed = pyqtSignal(list)  # inconsistencies
    cleanup_completed = pyqtSignal(bool)  # success
    
    def __init__(self, session_manager: SessionManager, 
                 cleanup_manager: ResourceCleanupManager,
                 stage_manager: Optional[ConnectionStageManager] = None,
                 emulator_service: Optional[EmulatorService] = None,
                 frida_service: Optional[FridaService] = None,
                 config_manager: Optional[Any] = None,
                 logger_instance: Any = None):
        """
        Initialize the connection flow controller.
        
        Args:
            session_manager: Session manager for state tracking
            cleanup_manager: Resource cleanup manager
            stage_manager: Connection stage manager (optional)
            emulator_service: Emulator service (optional)
            frida_service: Frida service (optional)
            config_manager: Configuration manager (optional)
            logger_instance: Logger instance (optional)
        """
        super().__init__()
        
        self.session_manager = session_manager
        self.cleanup_manager = cleanup_manager
        self.stage_manager = stage_manager
        self.emulator_service = emulator_service
        self.frida_service = frida_service
        self.config_manager = config_manager
        self._logger = logger_instance or logger.bind(component="ConnectionFlowController")
        
        # Flow state tracking
        self._current_flow: Optional[str] = None
        self._flow_start_time: Optional[datetime] = None
        self._flow_callbacks: Dict[str, List[Callable]] = {}
        
        # Connection readiness validators
        self._readiness_validators: List[Callable[[], bool]] = []
        
        # Error recovery strategies and retry configuration
        self._recovery_strategies: Dict[ErrorType, Callable] = {}
        self._retry_config = self._initialize_retry_config()
        self._error_categorization = self._initialize_error_categorization()
        
        # Connection orchestration state
        self._current_stage: Optional[ConnectionStage] = None
        self._stage_retry_counts: Dict[ConnectionStage, int] = {}
        self._connection_context: Dict[str, Any] = {}
        
        self._logger.info("ConnectionFlowController initialized")
    
    def _initialize_retry_config(self) -> Dict[ErrorType, Dict[str, Any]]:
        """Initialize retry configuration for different error types."""
        # Get retry config from configuration manager if available
        config = getattr(self, 'config_manager', None)
        
        if config:
            retry_config = config.get('connection.retry_config', {})
            return {
                ErrorType.NETWORK: {
                    "max_retries": retry_config.get('network', {}).get('max_retries', 3),
                    "strategy": RetryStrategy.EXPONENTIAL_BACKOFF,
                    "base_delay": retry_config.get('network', {}).get('base_delay', 2.0),
                    "max_delay": retry_config.get('network', {}).get('max_delay', 30.0),
                    "jitter": retry_config.get('network', {}).get('jitter', True)
                },
                ErrorType.TIMEOUT: {
                    "max_retries": retry_config.get('timeout', {}).get('max_retries', 2),
                    "strategy": RetryStrategy.LINEAR_BACKOFF,
                    "base_delay": retry_config.get('timeout', {}).get('base_delay', 5.0),
                    "max_delay": retry_config.get('timeout', {}).get('max_delay', 15.0),
                    "jitter": retry_config.get('timeout', {}).get('jitter', False)
                },
                ErrorType.RESOURCE: {
                    "max_retries": retry_config.get('resource', {}).get('max_retries', 1),
                    "strategy": RetryStrategy.IMMEDIATE,
                    "base_delay": retry_config.get('resource', {}).get('base_delay', 0.0),
                    "max_delay": retry_config.get('resource', {}).get('max_delay', 0.0),
                    "jitter": retry_config.get('resource', {}).get('jitter', False)
                },
                ErrorType.PERMISSION: {
                    "max_retries": retry_config.get('permission', {}).get('max_retries', 0),
                    "strategy": RetryStrategy.NO_RETRY,
                    "base_delay": retry_config.get('permission', {}).get('base_delay', 0.0),
                    "max_delay": retry_config.get('permission', {}).get('max_delay', 0.0),
                    "jitter": retry_config.get('permission', {}).get('jitter', False)
                },
                ErrorType.COMPATIBILITY: {
                    "max_retries": retry_config.get('compatibility', {}).get('max_retries', 0),
                    "strategy": RetryStrategy.NO_RETRY,
                    "base_delay": retry_config.get('compatibility', {}).get('base_delay', 0.0),
                    "max_delay": retry_config.get('compatibility', {}).get('max_delay', 0.0),
                    "jitter": retry_config.get('compatibility', {}).get('jitter', False)
                },
                ErrorType.UNKNOWN: {
                    "max_retries": retry_config.get('unknown', {}).get('max_retries', 1),
                    "strategy": RetryStrategy.LINEAR_BACKOFF,
                    "base_delay": retry_config.get('unknown', {}).get('base_delay', 3.0),
                    "max_delay": retry_config.get('unknown', {}).get('max_delay', 10.0),
                    "jitter": retry_config.get('unknown', {}).get('jitter', True)
                }
            }
        else:
            # Fallback to hardcoded defaults
            return {
                ErrorType.NETWORK: {
                    "max_retries": 3,
                    "strategy": RetryStrategy.EXPONENTIAL_BACKOFF,
                    "base_delay": 2.0,
                    "max_delay": 30.0,
                    "jitter": True
                },
                ErrorType.TIMEOUT: {
                    "max_retries": 2,
                    "strategy": RetryStrategy.LINEAR_BACKOFF,
                    "base_delay": 5.0,
                    "max_delay": 15.0,
                    "jitter": False
                },
                ErrorType.RESOURCE: {
                    "max_retries": 1,
                    "strategy": RetryStrategy.IMMEDIATE,
                    "base_delay": 0.0,
                    "max_delay": 0.0,
                    "jitter": False
                },
                ErrorType.PERMISSION: {
                    "max_retries": 0,
                    "strategy": RetryStrategy.NO_RETRY,
                    "base_delay": 0.0,
                    "max_delay": 0.0,
                    "jitter": False
                },
                ErrorType.COMPATIBILITY: {
                    "max_retries": 0,
                    "strategy": RetryStrategy.NO_RETRY,
                    "base_delay": 0.0,
                    "max_delay": 0.0,
                    "jitter": False
                },
                ErrorType.UNKNOWN: {
                    "max_retries": 1,
                    "strategy": RetryStrategy.LINEAR_BACKOFF,
                    "base_delay": 3.0,
                    "max_delay": 10.0,
                    "jitter": True
                }
            }
    
    def _initialize_error_categorization(self) -> Dict[str, ErrorType]:
        """Initialize error categorization patterns."""
        return {
            # Network-related errors
            "connection": ErrorType.NETWORK,
            "network": ErrorType.NETWORK,
            "timeout": ErrorType.TIMEOUT,
            "unreachable": ErrorType.NETWORK,
            "dns": ErrorType.NETWORK,
            "socket": ErrorType.NETWORK,
            
            # Permission-related errors
            "permission": ErrorType.PERMISSION,
            "denied": ErrorType.PERMISSION,
            "unauthorized": ErrorType.PERMISSION,
            "access": ErrorType.PERMISSION,
            "root": ErrorType.PERMISSION,
            
            # Resource-related errors
            "memory": ErrorType.RESOURCE,
            "storage": ErrorType.RESOURCE,
            "space": ErrorType.RESOURCE,
            "resource": ErrorType.RESOURCE,
            "busy": ErrorType.RESOURCE,
            
            # Compatibility-related errors
            "version": ErrorType.COMPATIBILITY,
            "compatibility": ErrorType.COMPATIBILITY,
            "unsupported": ErrorType.COMPATIBILITY,
            "architecture": ErrorType.COMPATIBILITY,
            "abi": ErrorType.COMPATIBILITY
        }
    
    # --- Main Flow Control Methods ---
    
    async def start_connection_flow(self, device_id: str, process_info: Optional[Dict[str, Any]] = None, 
                                  hook_script_content: Optional[str] = None) -> bool:
        """
        Start the complete connection flow from device selection to hook activation.
        
        Args:
            device_id: Target device identifier
            process_info: Optional process information if already selected
            hook_script_content: Optional hook script content to inject
            
        Returns:
            True if connection flow completed successfully, False otherwise
        """
        flow_type = "connection"
        self._logger.info("Starting connection flow", device_id=device_id, process_info=process_info)
        
        # Check if we're already in a flow
        if self._current_flow:
            self._logger.warning("Connection flow already in progress", current_flow=self._current_flow)
            return False
        
        # Validate readiness before starting
        if not await self._validate_connection_readiness():
            self._logger.error("System not ready for connection")
            return False
        
        try:
            self._current_flow = flow_type
            self._flow_start_time = datetime.now()
            self.flow_started.emit(flow_type)
            
            # Initialize connection context
            self._connection_context = {
                "device_id": device_id,
                "process_info": process_info or {},
                "start_time": datetime.now(),
                "retry_counts": {},
                "stage_history": []
            }
            
            # Reset stage retry counts
            self._stage_retry_counts.clear()
            
            # Execute the complete connection orchestration
            success = await self._orchestrate_connection_flow(device_id, process_info)
            
            if success:
                self._logger.info("Connection flow completed successfully")
                self.flow_completed.emit(flow_type, True)
                return True
            else:
                self._logger.error("Connection flow failed")
                self.flow_completed.emit(flow_type, False)
                return False
            
        except Exception as e:
            self._logger.error("Connection flow start failed", error=str(e))
            error_info = self._create_error_info(
                ErrorType.UNKNOWN, "FLOW_START_001",
                "Failed to start connection process", str(e),
                ["Check system state and try again"]
            )
            self.session_manager.set_error_info(error_info)
            self.flow_error.emit(flow_type, error_info)
            return False
        finally:
            self._current_flow = None
            self._flow_start_time = None
            self._current_stage = None

    async def disconnect_flow(self, cleanup_level: CleanupLevel = CleanupLevel.STANDARD) -> bool:
        """
        Orchestrate the disconnection and cleanup process.
        Args:
            cleanup_level: Level of cleanup to perform
        Returns:
            True if cleanup completed successfully, False otherwise
        """
        flow_type = "disconnect"
        self._logger.info("Starting disconnect flow", cleanup_level=cleanup_level.value)
        
        # Check if we're already in a flow
        if self._current_flow:
            self._logger.warning("Another flow already in progress", current_flow=self._current_flow)
            return False
        
        try:
            self._current_flow = flow_type
            self._flow_start_time = datetime.now()
            self.flow_started.emit(flow_type)
            
            # Transition to disconnecting state
            if not self.session_manager.transition_to_state(ConnectionState.DISCONNECTING):
                self._logger.warning("Failed to transition to disconnecting state, continuing anyway")
            
            # Perform cleanup based on level
            cleanup_success = False
            if cleanup_level == CleanupLevel.MINIMAL:
                cleanup_success = await self._minimal_cleanup()
            elif cleanup_level == CleanupLevel.STANDARD:
                cleanup_success = await self._standard_cleanup()
            elif cleanup_level == CleanupLevel.FULL:
                cleanup_success = await self._full_cleanup()
            
            # Transition to disconnected state
            if cleanup_success:
                self.session_manager.transition_to_state(ConnectionState.DISCONNECTED)
                self.session_manager.reset_to_disconnected()
                self._logger.info("Disconnect flow completed successfully")
            else:
                self._logger.warning("Disconnect flow completed with issues")
            
            self.flow_completed.emit(flow_type, cleanup_success)
            self.cleanup_completed.emit(cleanup_success)
            return cleanup_success
            
        except Exception as e:
            self._logger.error("Disconnect flow failed", error=str(e))
            error_info = ErrorInfo(
                error_type=ErrorType.RESOURCE,
                error_code="FLOW_DISCONNECT_001",
                user_message="Failed to disconnect properly",
                technical_details=str(e),
                recovery_suggestions=["Try force disconnect or restart application"],
                is_recoverable=True,
                retry_count=0,
                timestamp=datetime.now()
            )
            self.flow_error.emit(flow_type, error_info)
            return False
        finally:
            self._current_flow = None
            self._flow_start_time = None

    async def reconnect_flow(self) -> bool:
        """
        Attempt to reconnect using the last known device and process info.
        Returns:
            True if reconnection succeeded, False otherwise
        """
        flow_type = "reconnect"
        self._logger.info("Starting reconnect flow")
        
        # Get last known connection info
        device_id = self.session_manager.connected_emulator_serial
        process_info = None
        
        if self.session_manager.selected_target_pid:
            process_info = {
                "pid": self.session_manager.selected_target_pid,
                "package": self.session_manager.selected_target_package,
                "version": self.session_manager.selected_target_version
            }
        
        if not device_id:
            self._logger.error("No previous device information available for reconnection")
            error_info = ErrorInfo(
                error_type=ErrorType.UNKNOWN,
                error_code="RECONNECT_001",
                user_message="No previous connection information available",
                technical_details="Cannot reconnect without previous device information",
                recovery_suggestions=["Start a new connection instead"],
                is_recoverable=False,
                retry_count=0,
                timestamp=datetime.now()
            )
            self.flow_error.emit(flow_type, error_info)
            return False
        
        # First disconnect if currently connected
        current_state = self.session_manager.connection_main_state
        if current_state not in [ConnectionState.DISCONNECTED, ConnectionState.ERROR]:
            self._logger.info("Disconnecting before reconnection")
            if not await self.disconnect_flow(CleanupLevel.STANDARD):
                self._logger.warning("Disconnect before reconnect failed, continuing anyway")
        
        # Start new connection with previous parameters
        return await self.start_connection_flow(device_id, process_info)

    def get_connection_state(self) -> ConnectionState:
        """
        Get the current high-level connection state.
        Returns:
            Current ConnectionState
        """
        return self.session_manager.connection_main_state

    def validate_state_consistency(self) -> List[StateInconsistency]:
        """
        Validate state consistency across all components.
        Returns:
            List of detected inconsistencies (empty if consistent)
        """
        self._logger.debug("Validating state consistency")
        
        # Use session manager's built-in validation
        inconsistencies = self.session_manager.validate_state_consistency()
        
        if inconsistencies:
            self._logger.warning("State inconsistencies detected", 
                               inconsistency_count=len(inconsistencies))
            self.state_validation_failed.emit(inconsistencies)
        else:
            self._logger.debug("State consistency validation passed")
        
        return inconsistencies

    async def recover_from_inconsistent_state(self) -> bool:
        """
        Attempt to recover from an inconsistent state.
        Returns:
            True if recovery succeeded, False otherwise
        """
        self._logger.info("Attempting to recover from inconsistent state")
        
        # Use session manager's built-in recovery
        recovery_success = self.session_manager.attempt_state_recovery()
        
        if recovery_success:
            self._logger.info("State recovery successful")
            # Validate that we're now ready for new connections if needed
            if self.get_connection_state() == ConnectionState.DISCONNECTED:
                await self.prepare_for_new_connection()
        else:
            self._logger.warning("State recovery failed")
        
        return recovery_success

    async def cleanup_all_resources(self, timeout: float = 5.0) -> bool:
        """
        Cleanup all resources across services.
        Args:
            timeout: Maximum time to wait for cleanup
        Returns:
            True if cleanup succeeded, False otherwise
        """
        self._logger.info("Cleaning up all resources", timeout=timeout)
        
        try:
            # Use the cleanup manager to clean up all services
            cleanup_results = await self.cleanup_manager.cleanup_all_services(timeout)
            
            # Check if all cleanups were successful
            all_successful = all(
                result.result.value in ["success", "partial_success"] 
                for result in cleanup_results.values()
            )
            
            if all_successful:
                self._logger.info("All resources cleaned up successfully")
            else:
                failed_services = [
                    name for name, result in cleanup_results.items()
                    if result.result.value not in ["success", "partial_success"]
                ]
                self._logger.warning("Some services failed to clean up", 
                                   failed_services=failed_services)
            
            return all_successful
            
        except Exception as e:
            self._logger.error("Resource cleanup failed", error=str(e))
            return False

    async def prepare_for_new_connection(self) -> bool:
        """
        Prepare system for a new connection (reset state, validate readiness).
        Returns:
            True if preparation succeeded, False otherwise
        """
        self._logger.info("Preparing system for new connection")
        
        try:
            # Clear any error state
            self.session_manager.clear_error_info()
            self.session_manager.clear_stage_progress()
            
            # Validate that all services are ready
            if not await self.cleanup_manager.verify_services_ready():
                self._logger.warning("Some services not ready for connection")
                return False
            
            # Validate state consistency
            inconsistencies = self.validate_state_consistency()
            if inconsistencies:
                self._logger.info("State inconsistencies found, attempting recovery")
                if not await self.recover_from_inconsistent_state():
                    self._logger.error("Failed to recover from inconsistent state")
                    return False
            
            # Run readiness validators
            if not await self._validate_connection_readiness():
                self._logger.error("Connection readiness validation failed")
                return False
            
            self._logger.info("System prepared for new connection")
            return True
            
        except Exception as e:
            self._logger.error("Failed to prepare for new connection", error=str(e))
            return False
    
    # --- Helper Methods ---
    
    async def _validate_connection_readiness(self) -> bool:
        """
        Validate that the system is ready for a new connection.
        Returns:
            True if ready, False otherwise
        """
        try:
            # Check current state allows new connections
            current_state = self.get_connection_state()
            if current_state not in [ConnectionState.DISCONNECTED, ConnectionState.ERROR]:
                self._logger.warning("Cannot start connection in current state", 
                                   current_state=current_state.value)
                return False
            
            # Run custom readiness validators
            for validator in self._readiness_validators:
                try:
                    if not validator():
                        self._logger.warning("Custom readiness validator failed")
                        return False
                except Exception as e:
                    self._logger.error("Readiness validator exception", error=str(e))
                    return False
            
            # Verify services are ready
            if not await self.cleanup_manager.verify_services_ready():
                self._logger.warning("Services not ready for connection")
                return False
            
            return True
            
        except Exception as e:
            self._logger.error("Connection readiness validation failed", error=str(e))
            return False
    
    async def _execute_flow_callbacks(self, flow_type: str, phase: str):
        """Execute registered callbacks for a flow phase."""
        callbacks = self._flow_callbacks.get(f"{flow_type}_{phase}", [])
        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                self._logger.warning("Flow callback failed", 
                                   flow_type=flow_type, 
                                   phase=phase, 
                                   error=str(e))
    
    async def _minimal_cleanup(self) -> bool:
        """Perform minimal cleanup - just disconnect current session."""
        self._logger.info("Performing minimal cleanup")
        try:
            # Just clear session state without full service cleanup
            self.session_manager.reset_to_disconnected()
            return True
        except Exception as e:
            self._logger.error("Minimal cleanup failed", error=str(e))
            return False
    
    async def _standard_cleanup(self) -> bool:
        """Perform standard cleanup with resource release."""
        self._logger.info("Performing standard cleanup")
        try:
            # Use cleanup manager for standard cleanup
            cleanup_results = await self.cleanup_manager.cleanup_all_services()
            
            # Check results
            success_count = sum(
                1 for result in cleanup_results.values()
                if result.result.value in ["success", "partial_success"]
            )
            
            # Consider it successful if most services cleaned up
            return success_count >= len(cleanup_results) * 0.8
            
        except Exception as e:
            self._logger.error("Standard cleanup failed", error=str(e))
            return False
    
    async def _full_cleanup(self) -> bool:
        """Perform complete cleanup including service reset."""
        self._logger.info("Performing full cleanup")
        try:
            # First try standard cleanup
            standard_success = await self._standard_cleanup()
            
            # Then force cleanup for any remaining issues
            await self.cleanup_manager.force_cleanup_all()
            
            # Reset session state completely
            self.session_manager.reset_to_disconnected()
            
            return standard_success
            
        except Exception as e:
            self._logger.error("Full cleanup failed", error=str(e))
            return False
    
    # --- Registration Methods ---
    
    def add_readiness_validator(self, validator: Callable[[], bool]):
        """Add a custom readiness validator function."""
        if validator not in self._readiness_validators:
            self._readiness_validators.append(validator)
            self._logger.debug("Readiness validator added")
    
    def remove_readiness_validator(self, validator: Callable[[], bool]):
        """Remove a custom readiness validator function."""
        if validator in self._readiness_validators:
            self._readiness_validators.remove(validator)
            self._logger.debug("Readiness validator removed")
    
    def register_flow_callback(self, flow_type: str, phase: str, callback: Callable):
        """Register a callback for a specific flow phase."""
        key = f"{flow_type}_{phase}"
        if key not in self._flow_callbacks:
            self._flow_callbacks[key] = []
        self._flow_callbacks[key].append(callback)
        self._logger.debug("Flow callback registered", flow_type=flow_type, phase=phase)
    
    def unregister_flow_callback(self, flow_type: str, phase: str, callback: Callable):
        """Unregister a flow callback."""
        key = f"{flow_type}_{phase}"
        if key in self._flow_callbacks and callback in self._flow_callbacks[key]:
            self._flow_callbacks[key].remove(callback)
            self._logger.debug("Flow callback unregistered", flow_type=flow_type, phase=phase)
    
    # --- Status Methods ---
    
    def is_flow_in_progress(self) -> bool:
        """Check if any flow is currently in progress."""
        return self._current_flow is not None
    
    def get_current_flow_type(self) -> Optional[str]:
        """Get the type of flow currently in progress."""
        return self._current_flow
    
    def get_flow_duration(self) -> Optional[float]:
        """Get the duration of the current flow in seconds."""
        if self._flow_start_time:
            return (datetime.now() - self._flow_start_time).total_seconds()
        return None
    
    # --- Connection Flow Orchestration Methods ---
    
    async def _orchestrate_connection_flow(self, device_id: str, process_info: Optional[Dict[str, Any]]) -> bool:
        """
        Orchestrate the complete connection flow with comprehensive error handling and retry logic.
        
        Args:
            device_id: Target device identifier
            process_info: Optional process information
            
        Returns:
            True if connection flow completed successfully, False otherwise
        """
        self._logger.info("Starting connection flow orchestration", device_id=device_id)
        
        # Define the connection stages to execute
        stages = [
            ConnectionStage.DEVICE_VALIDATION,
            ConnectionStage.PROCESS_VALIDATION,
            ConnectionStage.FRIDA_SERVER_SETUP,
            ConnectionStage.HOOK_COMPATIBILITY,
            ConnectionStage.PROCESS_ATTACHMENT,
            ConnectionStage.SCRIPT_INJECTION,
            ConnectionStage.CONNECTION_VERIFICATION
        ]
        
        try:
            # Transition to connecting state
            if not self.session_manager.transition_to_state(
                ConnectionState.CONNECTING, 
                ConnectionSubState.DEVICE_SELECTION
            ):
                raise StateTransitionError("Failed to transition to connecting state")
            
            # Execute each stage with retry logic
            for stage in stages:
                self._current_stage = stage
                self._connection_context["stage_history"].append({
                    "stage": stage.value,
                    "start_time": datetime.now()
                })
                
                success = await self._execute_stage_with_retry(stage, device_id, process_info)
                
                # Update stage history
                self._connection_context["stage_history"][-1]["end_time"] = datetime.now()
                self._connection_context["stage_history"][-1]["success"] = success
                
                if not success:
                    self._logger.error("Connection stage failed", stage=stage.value)
                    return False
                
                # Update state transitions based on stage completion
                await self._update_state_for_stage_completion(stage)
            
            # All stages completed successfully
            if not self.session_manager.transition_to_state(
                ConnectionState.ACTIVE, 
                ConnectionSubState.HOOK_ACTIVE
            ):
                self._logger.warning("Failed to transition to active state")
            
            self._logger.info("Connection flow orchestration completed successfully")
            return True
            
        except Exception as e:
            self._logger.error("Connection flow orchestration failed", error=str(e))
            error_info = self._create_error_info(
                self._categorize_error(str(e)), "ORCHESTRATION_001",
                "Connection process failed", str(e),
                self._get_recovery_suggestions_for_error(str(e))
            )
            self.session_manager.set_error_info(error_info)
            return False
    
    async def _execute_stage_with_retry(self, stage: ConnectionStage, device_id: str, 
                                      process_info: Optional[Dict[str, Any]]) -> bool:
        """
        Execute a connection stage with comprehensive retry logic.
        
        Args:
            stage: The connection stage to execute
            device_id: Target device identifier
            process_info: Process information
            
        Returns:
            True if stage completed successfully, False otherwise
        """
        stage_name = stage.value
        self._logger.info("Executing connection stage", stage=stage_name)
        
        # Initialize retry count for this stage
        if stage not in self._stage_retry_counts:
            self._stage_retry_counts[stage] = 0
        
        # Update session manager with current stage
        self._update_session_stage_info(stage, "in_progress", "Executing stage...")
        
        max_attempts = 1  # Default to 1 attempt (no retries)
        last_error = None
        
        # We'll determine max_attempts after the first error occurs
        for attempt in range(10):  # Use a high number, we'll break when appropriate
            try:
                self._logger.debug("Stage execution attempt", stage=stage_name, attempt=attempt + 1)
                
                # Execute the stage-specific logic
                success = await self._execute_stage_logic(stage, device_id, process_info)
                
                if success:
                    self._logger.info("Stage completed successfully", stage=stage_name)
                    self._update_session_stage_info(stage, "completed", "Stage completed successfully")
                    return True
                else:
                    # Stage failed, determine if we should retry
                    error_msg = f"Stage {stage_name} execution returned False"
                    last_error = Exception(error_msg)
                    
                    if attempt < max_attempts - 1:
                        self._logger.warning("Stage failed, will retry", 
                                           stage=stage_name, attempt=attempt + 1)
                        
                        # Calculate retry delay
                        delay = await self._calculate_retry_delay(ErrorType.UNKNOWN, attempt)
                        if delay > 0:
                            await asyncio.sleep(delay)
                        continue
                    else:
                        self._logger.error("Stage failed after all attempts", stage=stage_name)
                        break
                        
            except Exception as e:
                last_error = e
                error_type = self._categorize_error(str(e))
                self._logger.error("Stage execution exception", 
                                 stage=stage_name, attempt=attempt + 1, error=str(e))
                
                # Get retry configuration for this error type
                retry_config = self._retry_config.get(error_type, self._retry_config[ErrorType.UNKNOWN])
                max_attempts = retry_config["max_retries"] + 1
                
                if attempt < max_attempts - 1 and retry_config["strategy"] != RetryStrategy.NO_RETRY:
                    self._logger.info("Retrying stage after error", 
                                    stage=stage_name, attempt=attempt + 1, 
                                    max_attempts=max_attempts)
                    
                    # Calculate retry delay
                    delay = await self._calculate_retry_delay(error_type, attempt)
                    if delay > 0:
                        await asyncio.sleep(delay)
                    continue
                else:
                    self._logger.error("Stage failed after all retry attempts", 
                                     stage=stage_name, error_type=error_type.value)
                    break
        
        # All attempts failed
        self._stage_retry_counts[stage] = max_attempts - 1
        error_info = self._create_error_info(
            self._categorize_error(str(last_error)) if last_error else ErrorType.UNKNOWN,
            f"STAGE_{stage_name.upper()}_001",
            f"Failed to complete {stage_name.replace('_', ' ')}",
            str(last_error) if last_error else "Unknown error",
            self._get_stage_recovery_suggestions(stage)
        )
        
        self._update_session_stage_info(stage, "failed", error_info.user_message)
        self.session_manager.set_error_info(error_info)
        return False
    
    async def _execute_stage_logic(self, stage: ConnectionStage, device_id: str, 
                                 process_info: Optional[Dict[str, Any]]) -> bool:
        """
        Execute the logic for a specific connection stage.
        
        Args:
            stage: The connection stage to execute
            device_id: Target device identifier
            process_info: Process information
            
        Returns:
            True if stage logic completed successfully, False otherwise
        """
        if stage == ConnectionStage.DEVICE_VALIDATION:
            return await self._validate_device_connection(device_id)
        elif stage == ConnectionStage.PROCESS_VALIDATION:
            return await self._validate_process_selection(device_id, process_info)
        elif stage == ConnectionStage.FRIDA_SERVER_SETUP:
            return await self._setup_frida_server(device_id)
        elif stage == ConnectionStage.HOOK_COMPATIBILITY:
            return await self._validate_hook_compatibility(process_info)
        elif stage == ConnectionStage.PROCESS_ATTACHMENT:
            return await self._attach_to_process(device_id, process_info)
        elif stage == ConnectionStage.SCRIPT_INJECTION:
            return await self._inject_hook_script(process_info)
        elif stage == ConnectionStage.CONNECTION_VERIFICATION:
            return await self._verify_connection_health()
        else:
            raise ValueError(f"Unknown connection stage: {stage}")
    
    async def _validate_device_connection(self, device_id: str) -> bool:
        """Validate device connection and availability."""
        self._logger.debug("Validating device connection", device_id=device_id)
        
        if not self.emulator_service:
            self._logger.warning("Emulator service not available, skipping device validation")
            return True  # Skip validation if service not available

        if not hasattr(self.session_manager, "connect_to_device"):
            self._logger.error("Session manager missing connect_to_device API")
            return False

        try:
            devices = await self.emulator_service.discover_devices()

            target_device = next(
                (device for device in devices if getattr(device, "serial", None) == device_id),
                None
            )

            if not target_device:
                self._logger.error(
                    "Target device not found in available devices",
                    device_id=device_id,
                    available_devices=[getattr(device, "serial", None) for device in devices]
                )
                return False

            success = await self.session_manager.connect_to_device(device_id, self.emulator_service)
            if not success:
                self._logger.error("Failed to connect to specified device", device_id=device_id)
                return False

            self._logger.info("Device connection validated", device_id=device_id)
            return True

        except Exception as e:
            self._logger.error("Device validation failed", device_id=device_id, error=str(e))
            return False
    
    async def _validate_process_selection(self, device_id: str, process_info: Optional[Dict[str, Any]]) -> bool:
        """Validate process selection and availability."""
        self._logger.debug("Validating process selection", process_info=process_info)
        
        if not process_info or not process_info.get("pid"):
            self._logger.warning("No process information provided, skipping validation")
            return True  # Skip if no process info
        
        try:
            # Basic validation of process info structure
            required_fields = ["pid", "package"]
            for field in required_fields:
                if field not in process_info:
                    self._logger.error("Missing required process field", field=field)
                    return False
            
            # Store process info in session manager
            self.session_manager.selected_target_pid = process_info["pid"]
            self.session_manager.selected_target_package = process_info["package"]
            self.session_manager.selected_target_version = process_info.get("version", "Unknown")
            
            self._logger.info("Process selection validated", 
                            pid=process_info["pid"], 
                            package=process_info["package"])
            return True
            
        except Exception as e:
            self._logger.error("Process validation failed", error=str(e))
            return False
    
    async def _setup_frida_server(self, device_id: str) -> bool:
        """Setup and verify Frida server on the device."""
        self._logger.debug("Setting up Frida server", device_id=device_id)
        
        if not self.stage_manager:
            self._logger.warning("Stage manager not available, using emulator service directly")
            if not self.emulator_service:
                self._logger.error("Neither stage manager nor emulator service available")
                return False

            try:
                # Use emulator service directly
                await self.emulator_service.ensure_frida_server_is_running(device_identifier=device_id)
                return True
            except Exception as e:
                self._logger.error("Frida server setup failed", error=str(e))
                return False
        
        try:
            # Use stage manager for comprehensive Frida server setup
            # This includes check, install, start, and verify stages
            success = await self._execute_frida_server_stages(device_id)
            return success
            
        except Exception as e:
            self._logger.error("Frida server setup failed", error=str(e))
            return False
    
    async def _execute_frida_server_stages(self, device_id: str) -> bool:
        """Execute Frida server setup stages using the stage manager."""
        if not self.stage_manager:
            self._logger.error("Stage manager is not available for Frida server setup")
            return False
        try:
            # Create a temporary process info for stage manager
            temp_process_info = {
                "pid": self.session_manager.selected_target_pid or 0,
                "package": self.session_manager.selected_target_package or "unknown",
                "version": self.session_manager.selected_target_version or "unknown"
            }
            # Execute the connection flow up to Frida server verification
            success = await self.stage_manager.execute_connection_flow(device_id, temp_process_info)
            if success:
                self._logger.info("Frida server setup completed successfully")
                return True
            else:
                self._logger.error("Frida server setup failed")
                return False
        except Exception as e:
            self._logger.error("Error executing Frida server stages", error=str(e))
            return False
    
    async def _validate_hook_compatibility(self, process_info: Optional[Dict[str, Any]]) -> bool:
        """Validate hook script compatibility with target process."""
        self._logger.debug("Validating hook compatibility", process_info=process_info)
        
        if not process_info or not process_info.get("package"):
            self._logger.warning("No package information for compatibility check")
            return True  # Skip if no package info
        
        if not self.frida_service:
            self._logger.warning("Frida service not available for compatibility check")
            return True  # Skip if service not available
        
        try:
            package_name = process_info["package"]
            version = process_info.get("version", "Unknown")
            
            # Use frida service to check compatibility
            is_compatible = self.frida_service.check_local_hook_compatibility(package_name, version)
            
            if not is_compatible:
                self._logger.error("Hook script not compatible", 
                                 package=package_name, version=version)
                return False
            
            # Update session manager
            self.session_manager.is_hook_compatible = True
            
            self._logger.info("Hook compatibility validated", 
                            package=package_name, version=version)
            return True
            
        except Exception as e:
            self._logger.error("Hook compatibility validation failed", error=str(e))
            return False
    
    async def _attach_to_process(self, device_id: str, process_info: Optional[Dict[str, Any]]) -> bool:
        """Attach Frida to the target process."""
        self._logger.debug("Attaching to process", process_info=process_info)
        
        if not process_info or not process_info.get("pid"):
            self._logger.error("No PID available for process attachment")
            return False
        
        if not self.frida_service:
            self._logger.error("Frida service not available for process attachment")
            return False
        
        try:
            pid = process_info["pid"]
            
            # Attach to the process
            success = await self.frida_service.attach(pid, device_id)
            
            if not success:
                self._logger.error("Failed to attach to process", pid=pid)
                return False
            
            self._logger.info("Successfully attached to process", pid=pid)
            return True
            
        except Exception as e:
            self._logger.error("Process attachment failed", error=str(e))
            return False
    
    async def _inject_hook_script(self, process_info: Optional[Dict[str, Any]]) -> bool:
        """Inject the hook script into the target process."""
        self._logger.debug("Injecting hook script", process_info=process_info)
        
        if not self.frida_service:
            self._logger.error("Frida service not available for script injection")
            return False
        
        try:
            # Get package name and version from process info
            package_name = process_info.get("package", "") if process_info else ""
            version = process_info.get("version", "Unknown") if process_info else "Unknown"
            
            self._logger.info("Loading script for injection", package_name=package_name, version=version)
            
            # Load the script content using hook script manager
            script_content = await self._load_script_content(package_name, version)
            
            if not script_content:
                self._logger.error("Failed to load script content", package_name=package_name, version=version)
                return False
            
            self._logger.info("Script content loaded successfully", content_length=len(script_content))
            
            # Inject the script with actual content
            success = await self.frida_service.inject_script(script_content)
            
            if not success:
                self._logger.error("Failed to inject hook script")
                return False
            
            self._logger.info("Hook script injected successfully")
            return True
            
        except Exception as e:
            self._logger.error("Script injection failed", error=str(e))
            return False
    
    async def _load_script_content(self, package_name: str, version: str) -> Optional[str]:
        """Load script content for the specified package and version."""
        self._logger.debug("Loading script content", package_name=package_name, version=version)
        
        try:
            # Get the hook script manager from the session manager
            if not hasattr(self.session_manager, 'hook_script_manager') or not self.session_manager.hook_script_manager:
                self._logger.error("Hook script manager not available")
                return None
            
            hook_script_manager = self.session_manager.hook_script_manager
            
            # Get compatible scripts for the package and version
            compatible_scripts = hook_script_manager.get_compatible_scripts(package_name, version)
            
            if not compatible_scripts:
                self._logger.error("No compatible scripts found", package_name=package_name, version=version)
                return None
            
            # Use the first compatible script
            selected_script = compatible_scripts[0]
            script_file_name = selected_script.get("fileName", "")
            
            if not script_file_name:
                self._logger.error("Script file name not found in metadata")
                return None
            
            # Load the script content
            script_content = hook_script_manager.get_script_content(script_file_name)
            
            if not script_content:
                self._logger.error("Failed to load script content", script_file_name=script_file_name)
                return None
            
            self._logger.info("Script content loaded successfully", 
                            script_name=selected_script.get("scriptName", script_file_name),
                            content_length=len(script_content))
            
            return script_content
            
        except Exception as e:
            self._logger.error("Error loading script content", error=str(e))
            return None
    
    async def _verify_connection_health(self) -> bool:
        """Verify the overall connection health and functionality."""
        self._logger.debug("Verifying connection health")
        
        try:
            # Check if Frida service is responsive
            if self.frida_service and hasattr(self.frida_service, 'session') and self.frida_service.session:
                # Basic health check - verify session is still active
                if not self.frida_service.session:
                    self._logger.error("Frida session is not active")
                    return False
            
            # Verify state consistency
            inconsistencies = self.validate_state_consistency()
            if inconsistencies:
                self._logger.warning("State inconsistencies detected during verification", 
                                   count=len(inconsistencies))
                # Try to recover
                if not await self.recover_from_inconsistent_state():
                    self._logger.error("Failed to recover from state inconsistencies")
                    return False
            
            self._logger.info("Connection health verification passed")
            return True
            
        except Exception as e:
            self._logger.error("Connection health verification failed", error=str(e))
            return False
    
    async def _update_state_for_stage_completion(self, stage: ConnectionStage):
        """Update session state based on completed stage."""
        try:
            if stage == ConnectionStage.DEVICE_VALIDATION:
                # Update to process selection sub-state
                self.session_manager.transition_to_state(
                    ConnectionState.CONNECTING, 
                    ConnectionSubState.PROCESS_SELECTION
                )
            elif stage == ConnectionStage.PROCESS_VALIDATION:
                # Stay in connecting state, update to hook activation
                self.session_manager.transition_to_state(
                    ConnectionState.CONNECTING, 
                    ConnectionSubState.HOOK_ACTIVATION
                )
            elif stage == ConnectionStage.FRIDA_SERVER_SETUP:
                # Move to connected state
                self.session_manager.transition_to_state(
                    ConnectionState.CONNECTED, 
                    ConnectionSubState.HOOK_ACTIVATION
                )
            elif stage == ConnectionStage.CONNECTION_VERIFICATION:
                # Final transition to active state
                self.session_manager.transition_to_state(
                    ConnectionState.ACTIVE, 
                    ConnectionSubState.HOOK_ACTIVE
                )
                
        except Exception as e:
            self._logger.warning("Failed to update state for stage completion", 
                               stage=stage.value, error=str(e))
    
    def _update_session_stage_info(self, stage: ConnectionStage, status: str, message: str):
        """Update session manager with stage information."""
        try:
            # Map connection stages to session manager stage names
            stage_mapping = {
                ConnectionStage.DEVICE_VALIDATION: "device_validation",
                ConnectionStage.PROCESS_VALIDATION: "process_validation", 
                ConnectionStage.FRIDA_SERVER_SETUP: "checking_frida",
                ConnectionStage.HOOK_COMPATIBILITY: "validating_hook",
                ConnectionStage.PROCESS_ATTACHMENT: "attaching",
                ConnectionStage.SCRIPT_INJECTION: "injecting_script",
                ConnectionStage.CONNECTION_VERIFICATION: "verifying_connection"
            }
            
            session_stage = stage_mapping.get(stage, stage.value)
            
            # Update session manager - these are read-only properties, so we don't set them directly
            # The stage and message are derived from the connection state
            
            # Create stage progress info
            stage_progress = StageProgress(
                stage_name=session_stage,
                status=StageStatus.IN_PROGRESS if status == "in_progress" 
                       else StageStatus.COMPLETED if status == "completed"
                       else StageStatus.FAILED,
                progress_percent=100 if status == "completed" else 50 if status == "in_progress" else 0,
                message=message,
                start_time=datetime.now() if status == "in_progress" else None,
                end_time=datetime.now() if status in ["completed", "failed"] else None
            )
            
            self.session_manager.update_stage_progress(session_stage, stage_progress)
            
        except Exception as e:
            self._logger.warning("Failed to update session stage info", error=str(e))
    
    # --- Error Handling and Recovery Methods ---
    
    def _categorize_error(self, error_message: str) -> ErrorType:
        """Categorize an error based on its message."""
        error_lower = error_message.lower()
        
        for pattern, error_type in self._error_categorization.items():
            if pattern in error_lower:
                return error_type
        
        return ErrorType.UNKNOWN
    
    def _create_error_info(self, error_type: ErrorType, error_code: str, 
                          user_message: str, technical_details: str, 
                          recovery_suggestions: List[str]) -> ErrorInfo:
        """Create an ErrorInfo object with proper categorization."""
        return ErrorInfo(
            error_type=error_type,
            error_code=error_code,
            user_message=user_message,
            technical_details=technical_details,
            recovery_suggestions=recovery_suggestions,
            is_recoverable=error_type not in [ErrorType.PERMISSION, ErrorType.COMPATIBILITY],
            retry_count=0,
            timestamp=datetime.now()
        )
    
    def _get_recovery_suggestions_for_error(self, error_message: str) -> List[str]:
        """Get recovery suggestions based on error message."""
        error_lower = error_message.lower()
        
        if "connection" in error_lower or "network" in error_lower:
            return [
                "Check device connection and try again",
                "Ensure device is properly connected via ADB",
                "Restart the device and retry"
            ]
        elif "permission" in error_lower or "denied" in error_lower:
            return [
                "Ensure device has root access enabled",
                "Check device security settings",
                "Grant necessary permissions and retry"
            ]
        elif "timeout" in error_lower:
            return [
                "Wait a moment and try again",
                "Check device responsiveness",
                "Restart the connection process"
            ]
        elif "memory" in error_lower or "resource" in error_lower:
            return [
                "Close other applications to free up resources",
                "Restart the device to clear memory",
                "Try again with fewer background processes"
            ]
        else:
            return [
                "Try restarting the connection process",
                "Check device connectivity and permissions",
                "Contact support if the issue persists"
            ]
    
    def _get_stage_recovery_suggestions(self, stage: ConnectionStage) -> List[str]:
        """Get recovery suggestions specific to a connection stage."""
        suggestions = {
            ConnectionStage.DEVICE_VALIDATION: [
                "Check device connection via ADB",
                "Ensure device is properly connected and recognized",
                "Try reconnecting the device"
            ],
            ConnectionStage.PROCESS_VALIDATION: [
                "Ensure the target application is running",
                "Check if the process information is correct",
                "Restart the target application"
            ],
            ConnectionStage.FRIDA_SERVER_SETUP: [
                "Check device root access",
                "Ensure sufficient storage space on device",
                "Try restarting the device"
            ],
            ConnectionStage.HOOK_COMPATIBILITY: [
                "Verify the application version is supported",
                "Check for hook script updates",
                "Try with a different application version"
            ],
            ConnectionStage.PROCESS_ATTACHMENT: [
                "Ensure the target process is running",
                "Check device permissions",
                "Restart the target application"
            ],
            ConnectionStage.SCRIPT_INJECTION: [
                "Check hook script compatibility",
                "Ensure sufficient memory is available",
                "Try restarting the target application"
            ],
            ConnectionStage.CONNECTION_VERIFICATION: [
                "Check overall system health",
                "Verify all components are functioning",
                "Try restarting the entire connection process"
            ]
        }
        
        return suggestions.get(stage, ["Try restarting the connection process"])
    
    async def _calculate_retry_delay(self, error_type: ErrorType, attempt: int) -> float:
        """Calculate retry delay based on error type and attempt number."""
        config = self._retry_config.get(error_type, self._retry_config[ErrorType.UNKNOWN])
        
        if config["strategy"] == RetryStrategy.NO_RETRY:
            return 0.0
        elif config["strategy"] == RetryStrategy.IMMEDIATE:
            return 0.0
        elif config["strategy"] == RetryStrategy.LINEAR_BACKOFF:
            delay = config["base_delay"] * (attempt + 1)
        elif config["strategy"] == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = config["base_delay"] * (2 ** attempt)
        else:
            delay = config["base_delay"]
        
        # Apply maximum delay limit
        delay = min(delay, config["max_delay"])
        
        # Add jitter if configured
        if config.get("jitter", False):
            jitter = random.uniform(0.8, 1.2)
            delay *= jitter
        
        return delay