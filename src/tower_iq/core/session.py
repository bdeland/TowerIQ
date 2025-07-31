"""
TowerIQ Session Management Module

This module provides the SessionManager class for centralized, thread-safe
management of application volatile state.
"""

import structlog
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from PyQt6.QtCore import QObject, pyqtSignal, QMutex, QMutexLocker


class ConnectionState(Enum):
    """Main connection states for the application."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ACTIVE = "active"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


class ConnectionSubState(Enum):
    """Sub-states for more granular connection tracking."""
    DEVICE_SELECTION = "device_selection"
    PROCESS_SELECTION = "process_selection"
    HOOK_ACTIVATION = "hook_activation"
    HOOK_ACTIVE = "hook_active"


class ErrorType(Enum):
    """Categories of errors that can occur during connection."""
    NETWORK = "network"
    PERMISSION = "permission"
    COMPATIBILITY = "compatibility"
    RESOURCE = "resource"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class StageStatus(Enum):
    """Status of individual connection stages."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ErrorInfo:
    """Detailed error information for connection issues."""
    error_type: ErrorType
    error_code: str
    user_message: str
    technical_details: str
    recovery_suggestions: List[str]
    is_recoverable: bool
    retry_count: int
    timestamp: datetime

    def __post_init__(self):
        """Validate error info after initialization."""
        if not self.user_message:
            raise ValueError("user_message cannot be empty")
        if self.retry_count < 0:
            raise ValueError("retry_count cannot be negative")


@dataclass
class StageProgress:
    """Progress information for individual connection stages."""
    stage_name: str
    status: StageStatus
    progress_percent: int
    message: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_info: Optional[ErrorInfo] = None
    retry_count: int = 0

    def __post_init__(self):
        """Validate stage progress after initialization."""
        if not self.stage_name:
            raise ValueError("stage_name cannot be empty")
        if not (0 <= self.progress_percent <= 100):
            raise ValueError("progress_percent must be between 0 and 100")
        if self.retry_count < 0:
            raise ValueError("retry_count cannot be negative")
        if self.end_time and self.start_time and self.end_time < self.start_time:
            raise ValueError("end_time cannot be before start_time")


class StateInconsistency(Enum):
    """Types of state inconsistencies that can be detected."""
    MAIN_SUB_STATE_MISMATCH = "main_sub_state_mismatch"
    DEVICE_WITHOUT_CONNECTION = "device_without_connection"
    PROCESS_WITHOUT_DEVICE = "process_without_device"
    ACTIVE_WITHOUT_PROCESS = "active_without_process"
    ERROR_WITHOUT_INFO = "error_without_info"
    PROGRESS_WITHOUT_STAGE = "progress_without_stage"


@dataclass
class ConnectionStateSnapshot:
    """Complete snapshot of connection state with validation."""
    main_state: ConnectionState
    sub_state: Optional[ConnectionSubState]
    device_id: Optional[str]
    process_info: Optional[Dict[str, Any]]
    error_info: Optional[ErrorInfo]
    stage_progress: Dict[str, StageProgress]
    timestamp: datetime

    def __post_init__(self):
        """Validate state snapshot after initialization."""
        if not self.timestamp:
            self.timestamp = datetime.now()

    def is_consistent(self) -> bool:
        """Check if the state snapshot is internally consistent."""
        return len(self.get_inconsistencies()) == 0

    def get_inconsistencies(self) -> List[StateInconsistency]:
        """Get list of detected state inconsistencies."""
        inconsistencies = []

        # Check main state and sub state alignment
        if self.main_state == ConnectionState.CONNECTING:
            if self.sub_state not in [ConnectionSubState.DEVICE_SELECTION, 
                                    ConnectionSubState.PROCESS_SELECTION, 
                                    ConnectionSubState.HOOK_ACTIVATION]:
                inconsistencies.append(StateInconsistency.MAIN_SUB_STATE_MISMATCH)
        elif self.main_state == ConnectionState.ACTIVE:
            if self.sub_state != ConnectionSubState.HOOK_ACTIVE:
                inconsistencies.append(StateInconsistency.MAIN_SUB_STATE_MISMATCH)
        elif self.main_state == ConnectionState.DISCONNECTED:
            if self.sub_state is not None:
                inconsistencies.append(StateInconsistency.MAIN_SUB_STATE_MISMATCH)

        # Check device connection consistency
        if self.main_state in [ConnectionState.CONNECTED, ConnectionState.ACTIVE]:
            if not self.device_id:
                inconsistencies.append(StateInconsistency.DEVICE_WITHOUT_CONNECTION)

        # Check process selection consistency
        if self.sub_state in [ConnectionSubState.HOOK_ACTIVATION, ConnectionSubState.HOOK_ACTIVE]:
            if not self.process_info:
                inconsistencies.append(StateInconsistency.PROCESS_WITHOUT_DEVICE)

        # Check active state consistency
        if self.main_state == ConnectionState.ACTIVE:
            if not self.process_info:
                inconsistencies.append(StateInconsistency.ACTIVE_WITHOUT_PROCESS)

        # Check error state consistency
        if self.main_state == ConnectionState.ERROR:
            if not self.error_info:
                inconsistencies.append(StateInconsistency.ERROR_WITHOUT_INFO)

        # Check stage progress consistency
        for stage_name, progress in self.stage_progress.items():
            if progress.status == StageStatus.FAILED and not progress.error_info:
                inconsistencies.append(StateInconsistency.PROGRESS_WITHOUT_STAGE)

        return inconsistencies

class SessionManager(QObject):
    """
    Manages volatile application state with signals for reactive UI updates.
    Enhanced with state machine logic and consistency validation.
    """
    # Signals for individual state changes
    round_status_changed = pyqtSignal(bool) # True if a round is active
    available_emulators_changed = pyqtSignal(list)
    available_processes_changed = pyqtSignal(list)
    selected_process_changed = pyqtSignal()
    
    # New state machine signals
    connection_main_state_changed = pyqtSignal(ConnectionState)
    connection_sub_state_changed = pyqtSignal(object)  # Can be ConnectionSubState or None
    state_inconsistency_detected = pyqtSignal(list)  # List of StateInconsistency
    state_recovery_attempted = pyqtSignal(bool)  # True if recovery succeeded

    def __init__(self):
        super().__init__()
        self.logger = structlog.get_logger().bind(source="SessionManager")
        
        # Thread safety
        self._mutex = QMutex()
        
        # State machine properties
        self._connection_main_state = ConnectionState.DISCONNECTED
        self._connection_sub_state = None
        self._state_snapshot = None
        self._stage_progress = {}
        self._last_error_info = None
        
        # Valid state transitions
        self._valid_transitions = {
            ConnectionState.DISCONNECTED: [ConnectionState.CONNECTING, ConnectionState.ERROR],
            ConnectionState.CONNECTING: [ConnectionState.CONNECTED, ConnectionState.DISCONNECTED, ConnectionState.ERROR],
            ConnectionState.CONNECTED: [ConnectionState.ACTIVE, ConnectionState.DISCONNECTING, ConnectionState.ERROR],
            ConnectionState.ACTIVE: [ConnectionState.DISCONNECTING, ConnectionState.ERROR],
            ConnectionState.DISCONNECTING: [ConnectionState.DISCONNECTED, ConnectionState.ERROR],
            ConnectionState.ERROR: [ConnectionState.DISCONNECTED, ConnectionState.CONNECTING]
        }
        
        # Initialize state variables
        with QMutexLocker(self._mutex):
            self._current_round_seed = None
            self._is_round_active = False
            self._connected_emulator_serial = None
            self._available_emulators = []
            self._available_processes = []
            self._selected_target_package = None
            self._selected_target_pid = None
            self._selected_target_version = None
            self._is_hook_compatible = False
            
            # Initialize state machine properties
            self._connection_main_state = ConnectionState.DISCONNECTED
            self._connection_sub_state = None
            self._stage_progress = {}
            self._last_error_info = None
            self._state_snapshot = None

    def _set_property(self, name: str, value: Any, signal: Any = None):
        """Generic thread-safe property setter that emits a signal on change."""
        with QMutexLocker(self._mutex):
            current_value = getattr(self, name)
            if current_value == value:
                return False # No change
            setattr(self, name, value)
        
        if signal:
            signal.emit(value)
        return True

    # --- Properties ---
    @property
    def is_hook_active(self) -> bool:
        with QMutexLocker(self._mutex):
            return self._connection_main_state == ConnectionState.ACTIVE

    @property
    def is_round_active(self) -> bool:
        with QMutexLocker(self._mutex): return self._is_round_active
    @is_round_active.setter
    def is_round_active(self, value: bool):
        self._set_property('_is_round_active', value, self.round_status_changed)

    # Add other properties here using the same pattern if they need signals
    @property
    def current_round_seed(self) -> Optional[Union[int, str]]:
        with QMutexLocker(self._mutex): return self._current_round_seed
    @current_round_seed.setter
    def current_round_seed(self, value: Optional[Union[int, str]]):
        with QMutexLocker(self._mutex): self._current_round_seed = value
        
    @property
    def available_emulators(self) -> List[Dict[str, Any]]:
        with QMutexLocker(self._mutex): return self._available_emulators
    @available_emulators.setter
    def available_emulators(self, value: List[Dict[str, Any]]):
        self._set_property('_available_emulators', value, self.available_emulators_changed)

    # Continue for all other state properties...
    # For brevity, only showing the ones with signals. Implement the rest as needed.
    @property
    def connected_emulator_serial(self) -> Optional[str]:
        with QMutexLocker(self._mutex): return self._connected_emulator_serial
    @connected_emulator_serial.setter
    def connected_emulator_serial(self, value: Optional[str]):
        with QMutexLocker(self._mutex): self._connected_emulator_serial = value

    @property
    def available_processes(self) -> List[Dict[str, Any]]:
        with QMutexLocker(self._mutex): return self._available_processes
    @available_processes.setter
    def available_processes(self, value: List[Dict[str, Any]]):
        self._set_property('_available_processes', value, self.available_processes_changed)

    @property
    def selected_target_pid(self) -> Optional[int]:
        with QMutexLocker(self._mutex): return self._selected_target_pid
    @selected_target_pid.setter
    def selected_target_pid(self, value: Optional[int]):
        with QMutexLocker(self._mutex): self._selected_target_pid = value
        self.selected_process_changed.emit()

    @property
    def is_emulator_connected(self) -> bool:
        with QMutexLocker(self._mutex):
            return self._connection_main_state in [ConnectionState.CONNECTED, ConnectionState.ACTIVE]

    @property
    def selected_target_package(self) -> Optional[str]:
        with QMutexLocker(self._mutex): return self._selected_target_package
    @selected_target_package.setter
    def selected_target_package(self, value: Optional[str]):
        with QMutexLocker(self._mutex): self._selected_target_package = value

    @property
    def selected_target_version(self) -> Optional[str]:
        with QMutexLocker(self._mutex): return self._selected_target_version
    @selected_target_version.setter
    def selected_target_version(self, value: Optional[str]):
        with QMutexLocker(self._mutex): self._selected_target_version = value

    @property
    def is_hook_compatible(self) -> bool:
        with QMutexLocker(self._mutex): return self._is_hook_compatible
    @is_hook_compatible.setter
    def is_hook_compatible(self, value: bool):
        with QMutexLocker(self._mutex): self._is_hook_compatible = value

    @property
    def hook_activation_stage(self) -> str:
        with QMutexLocker(self._mutex):
            return self._get_stage_from_sub_state(self._connection_sub_state) if self._connection_main_state == ConnectionState.CONNECTING else self._connection_main_state.value

    @property
    def hook_activation_message(self) -> str:
        with QMutexLocker(self._mutex):
            # This can be made more sophisticated later if needed
            if self._connection_main_state == ConnectionState.ERROR and self._last_error_info:
                return self._last_error_info.user_message
            return f"Current state: {self.hook_activation_stage.replace('_', ' ').title()}"

    def reset_to_disconnected(self) -> None:
        """Resets all connection-related state and transitions to DISCONNECTED."""
        with QMutexLocker(self._mutex):
            self._connected_emulator_serial = None
            self._available_processes = []
            self._selected_target_package = None
            self._selected_target_pid = None
            self._selected_target_version = None
            self._is_hook_compatible = False
            self.clear_stage_progress()
            self.clear_error_info()
            
            # Finally, perform the transition
            self.transition_to_state(ConnectionState.DISCONNECTED)
        
        # Since this is a hard reset, also clear non-connection state
        # (or decide if this should be separate)
        with QMutexLocker(self._mutex):
             self._current_round_seed = None
             self._is_round_active = False

    def get_status_summary(self) -> dict:
        with QMutexLocker(self._mutex):
            return self.__dict__.copy()

    # --- State Machine Methods ---
    
    @property
    def connection_main_state(self) -> ConnectionState:
        """Get the current main connection state."""
        with QMutexLocker(self._mutex):
            return self._connection_main_state
    
    @property
    def connection_sub_state(self) -> Optional[ConnectionSubState]:
        """Get the current connection sub-state."""
        with QMutexLocker(self._mutex):
            return self._connection_sub_state
    
    def transition_to_state(self, new_state: ConnectionState, 
                           sub_state: Optional[ConnectionSubState] = None,
                           error_info: Optional[ErrorInfo] = None) -> bool:
        """
        Attempt to transition to a new connection state with validation.
        
        Args:
            new_state: The target main state
            sub_state: Optional sub-state for the transition
            error_info: Error information if transitioning to ERROR state
            
        Returns:
            True if transition was successful, False otherwise
        """
        with QMutexLocker(self._mutex):
            current_state = self._connection_main_state
            
            # Validate transition
            if not self._is_valid_transition(current_state, new_state):
                self.logger.warning("Invalid state transition", from_state=current_state, to_state=new_state)
                return False
            
            # Perform atomic state update
            old_main_state = self._connection_main_state
            old_sub_state = self._connection_sub_state
            
            self._connection_main_state = new_state
            self._connection_sub_state = sub_state
            
            if error_info:
                self._last_error_info = error_info
            elif new_state != ConnectionState.ERROR:
                # Clear error info when leaving error state
                self._last_error_info = None
            

        
        # Emit signals outside of mutex lock
        if old_main_state != new_state:
            self.connection_main_state_changed.emit(new_state)
        if old_sub_state != sub_state:
            self.connection_sub_state_changed.emit(sub_state)
        
        self.logger.info("State transition", from_state=f"{old_main_state}({old_sub_state})", to_state=f"{new_state}({sub_state})")
        return True
    
    def _is_valid_transition(self, from_state: ConnectionState, to_state: ConnectionState) -> bool:
        """Check if a state transition is valid."""
        return to_state in self._valid_transitions.get(from_state, [])
    

    
    def _get_stage_from_sub_state(self, sub_state: Optional[ConnectionSubState]) -> str:
        """Convert sub-state to legacy stage string."""
        if sub_state == ConnectionSubState.DEVICE_SELECTION:
            return "device_selection"
        elif sub_state == ConnectionSubState.PROCESS_SELECTION:
            return "process_selection"
        elif sub_state == ConnectionSubState.HOOK_ACTIVATION:
            return "attaching"
        else:
            return "connecting"
    
    def get_current_state_snapshot(self) -> ConnectionStateSnapshot:
        """Get a complete snapshot of the current connection state."""
        with QMutexLocker(self._mutex):
            return ConnectionStateSnapshot(
                main_state=self._connection_main_state,
                sub_state=self._connection_sub_state,
                device_id=self._connected_emulator_serial,
                process_info=self._get_process_info(),
                error_info=self._last_error_info,
                stage_progress=self._stage_progress.copy(),
                timestamp=datetime.now()
            )
    
    def _get_process_info(self) -> Optional[Dict[str, Any]]:
        """Get current process information as a dictionary."""
        if self._selected_target_pid:
            return {
                "pid": self._selected_target_pid,
                "package": self._selected_target_package,
                "version": self._selected_target_version,
                "compatible": self._is_hook_compatible
            }
        return None
    
    def validate_state_consistency(self) -> List[StateInconsistency]:
        """Validate current state consistency and return any issues found."""
        snapshot = self.get_current_state_snapshot()
        inconsistencies = snapshot.get_inconsistencies()
        
        if inconsistencies:
            self.logger.warning("State inconsistencies detected", inconsistencies=[inc.value for inc in inconsistencies])
            self.state_inconsistency_detected.emit(inconsistencies)
        
        return inconsistencies
    
    def attempt_state_recovery(self) -> bool:
        """Attempt to recover from inconsistent state."""
        inconsistencies = self.validate_state_consistency()
        if not inconsistencies:
            return True  # Already consistent
        
        recovery_success = False
        
        with QMutexLocker(self._mutex):
            # Attempt recovery based on inconsistency types
            for inconsistency in inconsistencies:
                if inconsistency == StateInconsistency.MAIN_SUB_STATE_MISMATCH:
                    # Reset sub-state to match main state
                    if self._connection_main_state == ConnectionState.DISCONNECTED:
                        self._connection_sub_state = None
                        recovery_success = True
                    elif self._connection_main_state == ConnectionState.ACTIVE:
                        self._connection_sub_state = ConnectionSubState.HOOK_ACTIVE
                        recovery_success = True
                
                elif inconsistency == StateInconsistency.DEVICE_WITHOUT_CONNECTION:
                    # If we claim to be connected but have no device, go to disconnected
                    if self._connection_main_state in [ConnectionState.CONNECTED, ConnectionState.ACTIVE]:
                        self._connection_main_state = ConnectionState.DISCONNECTED
                        self._connection_sub_state = None
                        recovery_success = True
                
                elif inconsistency == StateInconsistency.ACTIVE_WITHOUT_PROCESS:
                    # If we're active but have no process, go to connected
                    if self._connection_main_state == ConnectionState.ACTIVE:
                        self._connection_main_state = ConnectionState.CONNECTED
                        self._connection_sub_state = ConnectionSubState.PROCESS_SELECTION
                        recovery_success = True
                
                elif inconsistency == StateInconsistency.ERROR_WITHOUT_INFO:
                    # If we're in error state but have no error info, create generic error
                    if self._connection_main_state == ConnectionState.ERROR and not self._last_error_info:
                        self._last_error_info = ErrorInfo(
                            error_type=ErrorType.UNKNOWN,
                            error_code="RECOVERY_001",
                            user_message="Unknown error occurred",
                            technical_details="State recovery detected error state without error information",
                            recovery_suggestions=["Try reconnecting"],
                            is_recoverable=True,
                            retry_count=0,
                            timestamp=datetime.now()
                        )
                        recovery_success = True
        

        
        self.state_recovery_attempted.emit(recovery_success)
        return recovery_success
    
    def update_stage_progress(self, stage_name: str, progress: StageProgress):
        """Update progress for a specific connection stage."""
        with QMutexLocker(self._mutex):
            self._stage_progress[stage_name] = progress
    
    def get_stage_progress(self, stage_name: str) -> Optional[StageProgress]:
        """Get progress for a specific connection stage."""
        with QMutexLocker(self._mutex):
            return self._stage_progress.get(stage_name)
    
    def clear_stage_progress(self):
        """Clear all stage progress information."""
        with QMutexLocker(self._mutex):
            self._stage_progress.clear()
    
    def set_error_info(self, error_info: ErrorInfo):
        """Set error information and transition to error state if not already there."""
        with QMutexLocker(self._mutex):
            self._last_error_info = error_info
            if self._connection_main_state != ConnectionState.ERROR:
                # Transition to error state
                old_state = self._connection_main_state
                self._connection_main_state = ConnectionState.ERROR
                self._connection_sub_state = None
        
        # Emit signal outside mutex
        self.connection_main_state_changed.emit(ConnectionState.ERROR)
        self.logger.error("Error info set", error_type=error_info.error_type.value, message=error_info.user_message)
    
    def get_last_error_info(self) -> Optional[ErrorInfo]:
        """Get the last error information."""
        with QMutexLocker(self._mutex):
            return self._last_error_info
    
    def clear_error_info(self):
        """Clear error information."""
        with QMutexLocker(self._mutex):
            self._last_error_info = None 