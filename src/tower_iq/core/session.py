"""
TowerIQ Session Management Module

This module provides the SessionManager class for centralized, thread-safe
management of application volatile state.
"""

import uuid
import threading
from typing import Optional, List, Dict, Any


class SessionManager:
    """
    Single source of truth for dynamic application state.
    Thread-safe manager for current run ID, game version, and connection statuses.
    """
    
    def __init__(self) -> None:
        """Initialize the session manager with default state."""
        self._lock = threading.Lock()
        
        # Private state variables
        self._current_runId: Optional[str] = None
        self._game_version: Optional[str] = None
        self._is_emulator_connected: bool = False
        self._is_frida_server_running: bool = False
        self._is_hook_active: bool = False
        self._current_monitoring_state: str = "NORMAL"
        
        # New state variables for connection flow
        self._connected_emulator_serial: Optional[str] = None
        self._available_emulators: List[Dict[str, Any]] = []
        self._available_processes: List[Dict[str, Any]] = []
        self._selected_target_package: Optional[str] = None
        self._selected_target_pid: Optional[int] = None
        self._selected_target_version: Optional[str] = None
        self._is_hook_compatible: bool = False
    
    # Properties for current_runId
    @property
    def current_runId(self) -> Optional[str]:
        """Get the current run ID."""
        with self._lock:
            return self._current_runId
    
    @current_runId.setter
    def current_runId(self, value: Optional[str]) -> None:
        """Set the current run ID."""
        with self._lock:
            self._current_runId = value
    
    # Properties for game_version
    @property
    def game_version(self) -> Optional[str]:
        """Get the current game version."""
        with self._lock:
            return self._game_version
    
    @game_version.setter
    def game_version(self, value: Optional[str]) -> None:
        """Set the current game version."""
        with self._lock:
            self._game_version = value
    
    # Properties for is_emulator_connected
    @property
    def is_emulator_connected(self) -> bool:
        """Get the emulator connection status."""
        with self._lock:
            return self._is_emulator_connected
    
    @is_emulator_connected.setter
    def is_emulator_connected(self, value: bool) -> None:
        """Set the emulator connection status."""
        with self._lock:
            self._is_emulator_connected = value
    
    # Properties for is_frida_server_running
    @property
    def is_frida_server_running(self) -> bool:
        """Get the Frida server running status."""
        with self._lock:
            return self._is_frida_server_running
    
    @is_frida_server_running.setter
    def is_frida_server_running(self, value: bool) -> None:
        """Set the Frida server running status."""
        with self._lock:
            self._is_frida_server_running = value
    
    # Properties for is_hook_active
    @property
    def is_hook_active(self) -> bool:
        """Get the hook active status."""
        with self._lock:
            return self._is_hook_active
    
    @is_hook_active.setter
    def is_hook_active(self, value: bool) -> None:
        """Set the hook active status."""
        with self._lock:
            self._is_hook_active = value
    
    # Properties for current_monitoring_state
    @property
    def current_monitoring_state(self) -> str:
        """Get the current monitoring state."""
        with self._lock:
            return self._current_monitoring_state
    
    @current_monitoring_state.setter
    def current_monitoring_state(self, value: str) -> None:
        """Set the current monitoring state."""
        if value not in ["NORMAL", "HIGH_RESOLUTION"]:
            raise ValueError(f"Invalid monitoring state: {value}. Must be 'NORMAL' or 'HIGH_RESOLUTION'")
        
        with self._lock:
            self._current_monitoring_state = value
    
    # Properties for connected_emulator_serial
    @property
    def connected_emulator_serial(self) -> Optional[str]:
        """Get the connected emulator serial."""
        with self._lock:
            return self._connected_emulator_serial
    
    @connected_emulator_serial.setter
    def connected_emulator_serial(self, value: Optional[str]) -> None:
        """Set the connected emulator serial."""
        with self._lock:
            self._connected_emulator_serial = value
    
    # Properties for available_emulators
    @property
    def available_emulators(self) -> List[Dict[str, Any]]:
        """Get the list of available emulators."""
        with self._lock:
            return self._available_emulators.copy()  # Return a copy to prevent external modification
    
    @available_emulators.setter
    def available_emulators(self, value: List[Dict[str, Any]]) -> None:
        """Set the list of available emulators."""
        with self._lock:
            self._available_emulators = value.copy() if value else []
    
    # Properties for available_processes
    @property
    def available_processes(self) -> List[Dict[str, Any]]:
        """Get the list of available processes."""
        with self._lock:
            return self._available_processes.copy()  # Return a copy to prevent external modification
    
    @available_processes.setter
    def available_processes(self, value: List[Dict[str, Any]]) -> None:
        """Set the list of available processes."""
        with self._lock:
            self._available_processes = value.copy() if value else []
    
    # Properties for selected_target_package
    @property
    def selected_target_package(self) -> Optional[str]:
        """Get the selected target package."""
        with self._lock:
            return self._selected_target_package
    
    @selected_target_package.setter
    def selected_target_package(self, value: Optional[str]) -> None:
        """Set the selected target package."""
        with self._lock:
            self._selected_target_package = value
    
    # Properties for selected_target_pid
    @property
    def selected_target_pid(self) -> Optional[int]:
        """Get the selected target PID."""
        with self._lock:
            return self._selected_target_pid
    
    @selected_target_pid.setter
    def selected_target_pid(self, value: Optional[int]) -> None:
        """Set the selected target PID."""
        with self._lock:
            self._selected_target_pid = value
    
    # Properties for selected_target_version
    @property
    def selected_target_version(self) -> Optional[str]:
        """Get the selected target version."""
        with self._lock:
            return self._selected_target_version
    
    @selected_target_version.setter
    def selected_target_version(self, value: Optional[str]) -> None:
        """Set the selected target version."""
        with self._lock:
            self._selected_target_version = value
    
    # Properties for is_hook_compatible
    @property
    def is_hook_compatible(self) -> bool:
        """Get the hook compatibility status."""
        with self._lock:
            return self._is_hook_compatible
    
    @is_hook_compatible.setter
    def is_hook_compatible(self, value: bool) -> None:
        """Set the hook compatibility status."""
        with self._lock:
            self._is_hook_compatible = value
    
    # Additional methods
    def get_monitoring_state(self) -> str:
        """
        Get the current monitoring state.
        
        Returns:
            Current monitoring state ("NORMAL" or "HIGH_RESOLUTION")
        """
        return self.current_monitoring_state
    
    def set_monitoring_state(self, state: str) -> None:
        """
        Set the current monitoring state.
        
        Args:
            state: New monitoring state ("NORMAL" or "HIGH_RESOLUTION")
            
        Raises:
            ValueError: If state is not valid
        """
        self.current_monitoring_state = state
    
    def start_new_run(self) -> str:
        """
        Generate a new UUID for a run, set it as current_runId, and return it.
        
        Returns:
            The new run ID (UUID string)
        """
        new_run_id = str(uuid.uuid4())
        self.current_runId = new_run_id
        return new_run_id
    
    def end_run(self) -> None:
        """Reset current_runId to None."""
        self.current_runId = None
    
    def get_status_summary(self) -> dict:
        """
        Get a summary of all current session state.
        Thread-safe snapshot of all state variables.
        
        Returns:
            Dictionary containing all state variables
        """
        with self._lock:
            return {
                'current_runId': self._current_runId,
                'game_version': self._game_version,
                'is_emulator_connected': self._is_emulator_connected,
                'is_frida_server_running': self._is_frida_server_running,
                'is_hook_active': self._is_hook_active,
                'current_monitoring_state': self._current_monitoring_state,
                'connected_emulator_serial': self._connected_emulator_serial,
                'available_emulators': self._available_emulators.copy(),
                'available_processes': self._available_processes.copy(),
                'selected_target_package': self._selected_target_package,
                'selected_target_pid': self._selected_target_pid,
                'selected_target_version': self._selected_target_version,
                'is_hook_compatible': self._is_hook_compatible
            }
    
    def reset_all_state(self) -> None:
        """
        Reset all state variables to their default values.
        Useful for application shutdown or reset scenarios.
        """
        with self._lock:
            self._current_runId = None
            self._game_version = None
            self._is_emulator_connected = False
            self._is_frida_server_running = False
            self._is_hook_active = False
            self._current_monitoring_state = "NORMAL"
            self._connected_emulator_serial = None
            self._available_emulators = []
            self._available_processes = []
            self._selected_target_package = None
            self._selected_target_pid = None
            self._selected_target_version = None
            self._is_hook_compatible = False
    
    def reset_connection_state(self) -> None:
        """
        Reset only the connection-related state variables.
        Useful when restarting the connection flow.
        """
        with self._lock:
            self._connected_emulator_serial = None
            self._available_emulators = []
            self._available_processes = []
            self._selected_target_package = None
            self._selected_target_pid = None
            self._selected_target_version = None
            self._is_hook_compatible = False
            self._is_emulator_connected = False
            self._is_frida_server_running = False
            self._is_hook_active = False 