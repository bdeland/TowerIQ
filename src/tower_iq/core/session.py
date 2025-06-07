"""
TowerIQ Session Management Module

This module provides the SessionManager class for centralized, thread-safe
management of application volatile state.
"""

import uuid
import threading
from typing import Optional


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
                'current_monitoring_state': self._current_monitoring_state
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