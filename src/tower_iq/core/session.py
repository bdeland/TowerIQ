"""
TowerIQ Session Management Module

This module provides the SessionManager class for centralized, thread-safe
management of application volatile state.
"""

from typing import Optional, List, Dict, Any, Union
from PyQt6.QtCore import QObject, pyqtSignal, QMutex, QMutexLocker

class SessionManager(QObject):
    """
    Manages volatile application state with signals for reactive UI updates.
    """
    # Signals for individual state changes
    connection_state_changed = pyqtSignal(bool) # True if hook is active
    round_status_changed = pyqtSignal(bool) # True if a round is active
    available_emulators_changed = pyqtSignal(list)
    available_processes_changed = pyqtSignal(list)
    selected_process_changed = pyqtSignal()
    hook_activation_stage_changed = pyqtSignal(str)
    hook_activation_message_changed = pyqtSignal(str)
    emulator_connection_changed = pyqtSignal(bool) # True if emulator is connected

    def __init__(self):
        super().__init__()
        self._mutex = QMutex()
        self.reset_all_state()

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
        with QMutexLocker(self._mutex): return self._is_hook_active
    @is_hook_active.setter
    def is_hook_active(self, value: bool):
        if self._set_property('_is_hook_active', value, self.connection_state_changed):
            print(f"Session: Hook active state changed to {value}")

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
        with QMutexLocker(self._mutex): return self._is_emulator_connected
    @is_emulator_connected.setter
    def is_emulator_connected(self, value: bool):
        self._set_property('_is_emulator_connected', value, self.emulator_connection_changed)

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
        with QMutexLocker(self._mutex): return self._hook_activation_stage
    @hook_activation_stage.setter
    def hook_activation_stage(self, value: str):
        self._set_property('_hook_activation_stage', value, self.hook_activation_stage_changed)

    @property
    def hook_activation_message(self) -> str:
        with QMutexLocker(self._mutex): return self._hook_activation_message
    @hook_activation_message.setter
    def hook_activation_message(self, value: str):
        self._set_property('_hook_activation_message', value, self.hook_activation_message_changed)

    def reset_connection_state(self) -> None:
        """Resets only the connection-related state variables."""
        with QMutexLocker(self._mutex):
            self._connected_emulator_serial = None
            self._available_emulators = []
            self._available_processes = []
            self._selected_target_package = None
            self._selected_target_pid = None
            self._selected_target_version = None
            self._is_hook_compatible = False
            self._is_emulator_connected = False
            self._hook_activation_stage = "idle"
            self._hook_activation_message = ""

    # ... and so on for other properties like selected_target_package, version, is_hook_compatible, etc.
    # get_status_summary and reset methods remain useful.

    def get_status_summary(self) -> dict:
        with QMutexLocker(self._mutex):
            return self.__dict__.copy()

    def reset_all_state(self) -> None:
        """Resets all state variables to their default values."""
        with QMutexLocker(self._mutex):
            self._current_round_seed = None
            self._is_hook_active = False
            self._is_round_active = False
            self._connected_emulator_serial = None
            self._available_emulators = []
            self._available_processes = []
            self._selected_target_package = None
            self._selected_target_pid = None
            self._selected_target_version = None
            self._is_hook_compatible = False
            self._is_emulator_connected = False
            self._hook_activation_stage = "idle"  # idle, checking_frida, validating_hook, attaching, failed, success
            self._hook_activation_message = ""    # A user-friendly message for the current stage or error 