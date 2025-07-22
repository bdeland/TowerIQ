"""
Unit tests for connection state models and validation.
"""

import pytest
from datetime import datetime, timedelta
from src.tower_iq.core.session import (
    ConnectionState, ConnectionSubState, ErrorType, StageStatus,
    ErrorInfo, StageProgress, ConnectionStateSnapshot, StateInconsistency
)


class TestErrorInfo:
    """Test ErrorInfo dataclass validation."""

    def test_valid_error_info(self):
        """Test creating valid ErrorInfo instance."""
        error = ErrorInfo(
            error_type=ErrorType.NETWORK,
            error_code="NET001",
            user_message="Connection failed",
            technical_details="Socket timeout after 30s",
            recovery_suggestions=["Check network connection", "Retry"],
            is_recoverable=True,
            retry_count=1,
            timestamp=datetime.now()
        )
        assert error.error_type == ErrorType.NETWORK
        assert error.user_message == "Connection failed"
        assert error.is_recoverable is True

    def test_empty_user_message_raises_error(self):
        """Test that empty user_message raises ValueError."""
        with pytest.raises(ValueError, match="user_message cannot be empty"):
            ErrorInfo(
                error_type=ErrorType.NETWORK,
                error_code="NET001",
                user_message="",
                technical_details="Details",
                recovery_suggestions=[],
                is_recoverable=True,
                retry_count=0,
                timestamp=datetime.now()
            )

    def test_negative_retry_count_raises_error(self):
        """Test that negative retry_count raises ValueError."""
        with pytest.raises(ValueError, match="retry_count cannot be negative"):
            ErrorInfo(
                error_type=ErrorType.NETWORK,
                error_code="NET001",
                user_message="Error",
                technical_details="Details",
                recovery_suggestions=[],
                is_recoverable=True,
                retry_count=-1,
                timestamp=datetime.now()
            )


class TestStageProgress:
    """Test StageProgress dataclass validation."""

    def test_valid_stage_progress(self):
        """Test creating valid StageProgress instance."""
        now = datetime.now()
        progress = StageProgress(
            stage_name="device_connection",
            status=StageStatus.IN_PROGRESS,
            progress_percent=50,
            message="Connecting to device...",
            start_time=now,
            retry_count=0
        )
        assert progress.stage_name == "device_connection"
        assert progress.progress_percent == 50
        assert progress.status == StageStatus.IN_PROGRESS

    def test_empty_stage_name_raises_error(self):
        """Test that empty stage_name raises ValueError."""
        with pytest.raises(ValueError, match="stage_name cannot be empty"):
            StageProgress(
                stage_name="",
                status=StageStatus.IN_PROGRESS,
                progress_percent=50,
                message="Test"
            )

    def test_invalid_progress_percent_raises_error(self):
        """Test that invalid progress_percent raises ValueError."""
        with pytest.raises(ValueError, match="progress_percent must be between 0 and 100"):
            StageProgress(
                stage_name="test",
                status=StageStatus.IN_PROGRESS,
                progress_percent=150,
                message="Test"
            )

        with pytest.raises(ValueError, match="progress_percent must be between 0 and 100"):
            StageProgress(
                stage_name="test",
                status=StageStatus.IN_PROGRESS,
                progress_percent=-10,
                message="Test"
            )

    def test_negative_retry_count_raises_error(self):
        """Test that negative retry_count raises ValueError."""
        with pytest.raises(ValueError, match="retry_count cannot be negative"):
            StageProgress(
                stage_name="test",
                status=StageStatus.IN_PROGRESS,
                progress_percent=50,
                message="Test",
                retry_count=-1
            )

    def test_invalid_time_order_raises_error(self):
        """Test that end_time before start_time raises ValueError."""
        now = datetime.now()
        earlier = now - timedelta(minutes=5)
        
        with pytest.raises(ValueError, match="end_time cannot be before start_time"):
            StageProgress(
                stage_name="test",
                status=StageStatus.COMPLETED,
                progress_percent=100,
                message="Test",
                start_time=now,
                end_time=earlier
            )


class TestConnectionStateSnapshot:
    """Test ConnectionStateSnapshot validation and consistency checking."""

    def test_valid_disconnected_state(self):
        """Test valid disconnected state snapshot."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.DISCONNECTED,
            sub_state=None,
            device_id=None,
            process_info=None,
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert snapshot.is_consistent()
        assert len(snapshot.get_inconsistencies()) == 0

    def test_valid_connecting_state(self):
        """Test valid connecting state snapshot."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.CONNECTING,
            sub_state=ConnectionSubState.DEVICE_SELECTION,
            device_id=None,
            process_info=None,
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert snapshot.is_consistent()

    def test_valid_active_state(self):
        """Test valid active state snapshot."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.ACTIVE,
            sub_state=ConnectionSubState.HOOK_ACTIVE,
            device_id="emulator-5554",
            process_info={"pid": 1234, "name": "com.example.app"},
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert snapshot.is_consistent()

    def test_main_sub_state_mismatch(self):
        """Test detection of main/sub state mismatch."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.DISCONNECTED,
            sub_state=ConnectionSubState.DEVICE_SELECTION,  # Should be None
            device_id=None,
            process_info=None,
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert not snapshot.is_consistent()
        inconsistencies = snapshot.get_inconsistencies()
        assert StateInconsistency.MAIN_SUB_STATE_MISMATCH in inconsistencies

    def test_device_without_connection(self):
        """Test detection of missing device ID in connected state."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.CONNECTED,
            sub_state=ConnectionSubState.PROCESS_SELECTION,
            device_id=None,  # Should have device_id
            process_info=None,
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert not snapshot.is_consistent()
        inconsistencies = snapshot.get_inconsistencies()
        assert StateInconsistency.DEVICE_WITHOUT_CONNECTION in inconsistencies

    def test_process_without_device(self):
        """Test detection of missing process info in hook states."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.CONNECTING,
            sub_state=ConnectionSubState.HOOK_ACTIVATION,
            device_id="emulator-5554",
            process_info=None,  # Should have process_info
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert not snapshot.is_consistent()
        inconsistencies = snapshot.get_inconsistencies()
        assert StateInconsistency.PROCESS_WITHOUT_DEVICE in inconsistencies

    def test_active_without_process(self):
        """Test detection of missing process info in active state."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.ACTIVE,
            sub_state=ConnectionSubState.HOOK_ACTIVE,
            device_id="emulator-5554",
            process_info=None,  # Should have process_info
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert not snapshot.is_consistent()
        inconsistencies = snapshot.get_inconsistencies()
        assert StateInconsistency.ACTIVE_WITHOUT_PROCESS in inconsistencies

    def test_error_without_info(self):
        """Test detection of missing error info in error state."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.ERROR,
            sub_state=None,
            device_id=None,
            process_info=None,
            error_info=None,  # Should have error_info
            stage_progress={},
            timestamp=datetime.now()
        )
        assert not snapshot.is_consistent()
        inconsistencies = snapshot.get_inconsistencies()
        assert StateInconsistency.ERROR_WITHOUT_INFO in inconsistencies

    def test_progress_without_stage_error(self):
        """Test detection of failed stage without error info."""
        failed_progress = StageProgress(
            stage_name="test_stage",
            status=StageStatus.FAILED,
            progress_percent=0,
            message="Failed",
            error_info=None  # Should have error_info for failed status
        )
        
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.DISCONNECTED,
            sub_state=None,
            device_id=None,
            process_info=None,
            error_info=None,
            stage_progress={"test_stage": failed_progress},
            timestamp=datetime.now()
        )
        assert not snapshot.is_consistent()
        inconsistencies = snapshot.get_inconsistencies()
        assert StateInconsistency.PROGRESS_WITHOUT_STAGE in inconsistencies

    def test_multiple_inconsistencies(self):
        """Test detection of multiple inconsistencies."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.ACTIVE,
            sub_state=ConnectionSubState.DEVICE_SELECTION,  # Wrong sub state
            device_id=None,  # Missing device ID
            process_info=None,  # Missing process info
            error_info=None,
            stage_progress={},
            timestamp=datetime.now()
        )
        assert not snapshot.is_consistent()
        inconsistencies = snapshot.get_inconsistencies()
        assert len(inconsistencies) >= 3  # Multiple issues detected

    def test_timestamp_auto_set(self):
        """Test that timestamp is automatically set if not provided."""
        snapshot = ConnectionStateSnapshot(
            main_state=ConnectionState.DISCONNECTED,
            sub_state=None,
            device_id=None,
            process_info=None,
            error_info=None,
            stage_progress={},
            timestamp=None
        )
        # timestamp should be set in __post_init__
        assert snapshot.timestamp is not None
        assert isinstance(snapshot.timestamp, datetime)


if __name__ == "__main__":
    pytest.main([__file__])