"""
Unit tests for SessionManager state machine functionality.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch
from PyQt6.QtCore import QObject

from src.tower_iq.core.session import (
    SessionManager, ConnectionState, ConnectionSubState, ErrorType, StageStatus,
    ErrorInfo, StageProgress, StateInconsistency
)


class TestSessionManagerStateMachine:
    """Test SessionManager state machine functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.session_manager = SessionManager()

    def test_initial_state(self):
        """Test that SessionManager starts in correct initial state."""
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTED
        assert self.session_manager.connection_sub_state is None
        assert self.session_manager.get_last_error_info() is None

    def test_valid_state_transitions(self):
        """Test valid state transitions."""
        # DISCONNECTED -> CONNECTING
        success = self.session_manager.transition_to_state(
            ConnectionState.CONNECTING, 
            ConnectionSubState.DEVICE_SELECTION
        )
        assert success is True
        assert self.session_manager.connection_main_state == ConnectionState.CONNECTING
        assert self.session_manager.connection_sub_state == ConnectionSubState.DEVICE_SELECTION

        # CONNECTING -> CONNECTED
        success = self.session_manager.transition_to_state(
            ConnectionState.CONNECTED,
            ConnectionSubState.PROCESS_SELECTION
        )
        assert success is True
        assert self.session_manager.connection_main_state == ConnectionState.CONNECTED

        # CONNECTED -> ACTIVE
        success = self.session_manager.transition_to_state(
            ConnectionState.ACTIVE,
            ConnectionSubState.HOOK_ACTIVE
        )
        assert success is True
        assert self.session_manager.connection_main_state == ConnectionState.ACTIVE

        # ACTIVE -> DISCONNECTING
        success = self.session_manager.transition_to_state(
            ConnectionState.DISCONNECTING
        )
        assert success is True
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTING

        # DISCONNECTING -> DISCONNECTED
        success = self.session_manager.transition_to_state(
            ConnectionState.DISCONNECTED
        )
        assert success is True
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTED

    def test_invalid_state_transitions(self):
        """Test that invalid state transitions are rejected."""
        # Try to go directly from DISCONNECTED to ACTIVE (invalid)
        success = self.session_manager.transition_to_state(ConnectionState.ACTIVE)
        assert success is False
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTED

        # Try to go from ACTIVE to CONNECTING (invalid)
        self.session_manager.transition_to_state(ConnectionState.CONNECTING)
        self.session_manager.transition_to_state(ConnectionState.CONNECTED)
        self.session_manager.transition_to_state(ConnectionState.ACTIVE)
        
        success = self.session_manager.transition_to_state(ConnectionState.CONNECTING)
        assert success is False
        assert self.session_manager.connection_main_state == ConnectionState.ACTIVE

    def test_error_state_transitions(self):
        """Test transitions to and from error state."""
        # Any state can transition to ERROR
        self.session_manager.transition_to_state(ConnectionState.CONNECTING)
        
        error_info = ErrorInfo(
            error_type=ErrorType.NETWORK,
            error_code="NET001",
            user_message="Connection failed",
            technical_details="Network timeout",
            recovery_suggestions=["Check connection"],
            is_recoverable=True,
            retry_count=0,
            timestamp=datetime.now()
        )
        
        success = self.session_manager.transition_to_state(
            ConnectionState.ERROR,
            error_info=error_info
        )
        assert success is True
        assert self.session_manager.connection_main_state == ConnectionState.ERROR
        assert self.session_manager.get_last_error_info() == error_info

        # ERROR can transition to DISCONNECTED or CONNECTING
        success = self.session_manager.transition_to_state(ConnectionState.DISCONNECTED)
        assert success is True
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTED

    def test_legacy_state_updates(self):
        """Test that legacy state properties are updated correctly."""
        # Test hook active state
        self.session_manager.transition_to_state(ConnectionState.CONNECTING)
        self.session_manager.transition_to_state(ConnectionState.CONNECTED)
        self.session_manager.transition_to_state(ConnectionState.ACTIVE)
        
        assert self.session_manager.is_hook_active is True
        
        self.session_manager.transition_to_state(ConnectionState.DISCONNECTING)
        self.session_manager.transition_to_state(ConnectionState.DISCONNECTED)
        
        assert self.session_manager.is_hook_active is False

        # Test emulator connected state
        self.session_manager.transition_to_state(ConnectionState.CONNECTING)
        self.session_manager.transition_to_state(ConnectionState.CONNECTED)
        
        assert self.session_manager.is_emulator_connected is True
        
        self.session_manager.transition_to_state(ConnectionState.DISCONNECTING)
        self.session_manager.transition_to_state(ConnectionState.DISCONNECTED)
        
        assert self.session_manager.is_emulator_connected is False

    def test_stage_progress_management(self):
        """Test stage progress tracking."""
        progress = StageProgress(
            stage_name="device_connection",
            status=StageStatus.IN_PROGRESS,
            progress_percent=50,
            message="Connecting to device...",
            start_time=datetime.now()
        )
        
        self.session_manager.update_stage_progress("device_connection", progress)
        
        retrieved_progress = self.session_manager.get_stage_progress("device_connection")
        assert retrieved_progress == progress
        
        # Test clearing progress
        self.session_manager.clear_stage_progress()
        assert self.session_manager.get_stage_progress("device_connection") is None

    def test_state_snapshot(self):
        """Test state snapshot functionality."""
        # Set up some state
        self.session_manager.connected_emulator_serial = "emulator-5554"
        self.session_manager.selected_target_pid = 1234
        self.session_manager.selected_target_package = "com.example.app"
        self.session_manager.transition_to_state(
            ConnectionState.CONNECTING,
            ConnectionSubState.DEVICE_SELECTION
        )
        
        snapshot = self.session_manager.get_current_state_snapshot()
        
        assert snapshot.main_state == ConnectionState.CONNECTING
        assert snapshot.sub_state == ConnectionSubState.DEVICE_SELECTION
        assert snapshot.device_id == "emulator-5554"
        assert snapshot.process_info["pid"] == 1234
        assert snapshot.process_info["package"] == "com.example.app"

    def test_state_consistency_validation(self):
        """Test state consistency validation."""
        # Create inconsistent state manually
        self.session_manager._connection_main_state = ConnectionState.ACTIVE
        self.session_manager._connection_sub_state = ConnectionSubState.DEVICE_SELECTION  # Wrong sub-state
        
        inconsistencies = self.session_manager.validate_state_consistency()
        assert StateInconsistency.MAIN_SUB_STATE_MISMATCH in inconsistencies

    def test_state_recovery(self):
        """Test automatic state recovery."""
        # Create inconsistent state
        self.session_manager._connection_main_state = ConnectionState.DISCONNECTED
        self.session_manager._connection_sub_state = ConnectionSubState.DEVICE_SELECTION  # Should be None
        
        # Attempt recovery
        recovery_success = self.session_manager.attempt_state_recovery()
        assert recovery_success is True
        assert self.session_manager.connection_sub_state is None

    def test_error_info_management(self):
        """Test error information management."""
        error_info = ErrorInfo(
            error_type=ErrorType.PERMISSION,
            error_code="PERM001",
            user_message="Permission denied",
            technical_details="Root access required",
            recovery_suggestions=["Enable root access"],
            is_recoverable=True,
            retry_count=1,
            timestamp=datetime.now()
        )
        
        self.session_manager.set_error_info(error_info)
        
        assert self.session_manager.connection_main_state == ConnectionState.ERROR
        assert self.session_manager.get_last_error_info() == error_info
        
        # Clear error info
        self.session_manager.clear_error_info()
        assert self.session_manager.get_last_error_info() is None

    def test_signal_emissions(self):
        """Test that appropriate signals are emitted during state changes."""
        # Mock signal connections
        main_state_signal = Mock()
        sub_state_signal = Mock()
        inconsistency_signal = Mock()
        recovery_signal = Mock()
        
        self.session_manager.connection_main_state_changed.connect(main_state_signal)
        self.session_manager.connection_sub_state_changed.connect(sub_state_signal)
        self.session_manager.state_inconsistency_detected.connect(inconsistency_signal)
        self.session_manager.state_recovery_attempted.connect(recovery_signal)
        
        # Perform state transition
        self.session_manager.transition_to_state(
            ConnectionState.CONNECTING,
            ConnectionSubState.DEVICE_SELECTION
        )
        
        # Verify signals were emitted
        main_state_signal.assert_called_once_with(ConnectionState.CONNECTING)
        sub_state_signal.assert_called_once_with(ConnectionSubState.DEVICE_SELECTION)

    def test_thread_safety(self):
        """Test that state operations are thread-safe."""
        # This is a basic test - in a real scenario you'd use threading
        # For now, just verify that mutex operations don't raise exceptions
        
        # Multiple rapid state changes should not cause issues
        for i in range(10):
            self.session_manager.transition_to_state(ConnectionState.CONNECTING)
            self.session_manager.transition_to_state(ConnectionState.DISCONNECTED)
        
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTED

    def test_reset_state_clears_state_machine(self):
        """Test that reset_all_state clears state machine properties."""
        # Set up some state
        self.session_manager.transition_to_state(ConnectionState.CONNECTING)
        self.session_manager.update_stage_progress("test", StageProgress(
            stage_name="test",
            status=StageStatus.IN_PROGRESS,
            progress_percent=50,
            message="Test"
        ))
        
        error_info = ErrorInfo(
            error_type=ErrorType.NETWORK,
            error_code="NET001",
            user_message="Test error",
            technical_details="Details",
            recovery_suggestions=[],
            is_recoverable=True,
            retry_count=0,
            timestamp=datetime.now()
        )
        self.session_manager.set_error_info(error_info)
        
        # Reset state
        self.session_manager.reset_all_state()
        
        # Verify state machine is reset
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTED
        assert self.session_manager.connection_sub_state is None
        assert self.session_manager.get_last_error_info() is None
        assert self.session_manager.get_stage_progress("test") is None

    def test_recovery_from_multiple_inconsistencies(self):
        """Test recovery from multiple state inconsistencies."""
        # Create multiple inconsistencies
        self.session_manager._connection_main_state = ConnectionState.ACTIVE
        self.session_manager._connection_sub_state = ConnectionSubState.DEVICE_SELECTION  # Wrong
        self.session_manager._connected_emulator_serial = None  # Missing device
        self.session_manager._selected_target_pid = None  # Missing process
        
        # Attempt recovery
        recovery_success = self.session_manager.attempt_state_recovery()
        
        # Should recover to a consistent state
        assert recovery_success is True
        # Should have been downgraded to a consistent state
        assert self.session_manager.connection_main_state == ConnectionState.DISCONNECTED


if __name__ == "__main__":
    pytest.main([__file__])