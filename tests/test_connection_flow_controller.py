"""
Unit tests for ConnectionFlowController

Tests the base structure and functionality of the ConnectionFlowController
including initialization, basic operations, state management, and resource coordination.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from src.tower_iq.services.connection_flow_controller import (
    ConnectionFlowController, CleanupLevel, ConnectionFlowError,
    ConnectionReadinessError, StateTransitionError
)
from src.tower_iq.core.session import (
    SessionManager, ConnectionState, ConnectionSubState, ErrorInfo, ErrorType,
    StateInconsistency
)
from src.tower_iq.core.cleanup_manager import (
    ResourceCleanupManager, ServiceLifecycle, ServiceCleanupResult,
    CleanupResult, ServiceState
)


class MockService(ServiceLifecycle):
    """Mock service for testing."""
    
    def __init__(self, name: str, state: ServiceState = ServiceState.READY):
        self._name = name
        self._state = state
        self._ready = True
    
    async def initialize(self) -> bool:
        return True
    
    async def cleanup(self) -> bool:
        return True
    
    async def reset(self) -> bool:
        return True
    
    def get_state(self) -> ServiceState:
        return self._state
    
    def is_ready_for_connection(self) -> bool:
        return self._ready
    
    @property
    def service_name(self) -> str:
        return self._name


@pytest.fixture
def session_manager():
    """Create a mock session manager."""
    manager = Mock(spec=SessionManager)
    manager.connection_main_state = ConnectionState.DISCONNECTED
    manager.connection_sub_state = None
    manager.connected_emulator_serial = None
    manager.selected_target_pid = None
    manager.selected_target_package = None
    manager.selected_target_version = None
    
    # Mock methods
    manager.transition_to_state = Mock(return_value=True)
    manager.validate_state_consistency = Mock(return_value=[])
    manager.attempt_state_recovery = Mock(return_value=True)
    manager.clear_error_info = Mock()
    manager.clear_stage_progress = Mock()
    manager.reset_connection_state = Mock()
    manager.reset_all_state = Mock()
    manager.set_error_info = Mock()
    
    return manager


@pytest.fixture
def cleanup_manager():
    """Create a mock cleanup manager."""
    manager = Mock(spec=ResourceCleanupManager)
    
    # Mock successful cleanup results
    mock_result = ServiceCleanupResult(
        service_name="test_service",
        result=CleanupResult.SUCCESS,
        duration_seconds=1.0,
        issues=[],
        timestamp=datetime.now()
    )
    
    manager.cleanup_all_services = AsyncMock(return_value={"test_service": mock_result})
    manager.verify_services_ready = AsyncMock(return_value=True)
    manager.force_cleanup_all = AsyncMock()
    
    return manager


@pytest.fixture
def flow_controller(session_manager, cleanup_manager):
    """Create a ConnectionFlowController instance for testing."""
    return ConnectionFlowController(session_manager, cleanup_manager)


class TestConnectionFlowControllerInitialization:
    """Test ConnectionFlowController initialization."""
    
    def test_initialization_with_required_parameters(self, session_manager, cleanup_manager):
        """Test that controller initializes correctly with required parameters."""
        controller = ConnectionFlowController(session_manager, cleanup_manager)
        
        assert controller.session_manager is session_manager
        assert controller.cleanup_manager is cleanup_manager
        assert controller._current_flow is None
        assert controller._flow_start_time is None
        assert controller._flow_callbacks == {}
        assert controller._readiness_validators == []
        assert controller._recovery_strategies == {}
    
    def test_initialization_with_custom_logger(self, session_manager, cleanup_manager):
        """Test initialization with custom logger."""
        mock_logger = Mock()
        controller = ConnectionFlowController(session_manager, cleanup_manager, mock_logger)
        
        assert controller._logger is mock_logger
    
    def test_signals_are_defined(self, flow_controller):
        """Test that all required signals are defined."""
        assert hasattr(flow_controller, 'flow_started')
        assert hasattr(flow_controller, 'flow_completed')
        assert hasattr(flow_controller, 'flow_error')
        assert hasattr(flow_controller, 'state_validation_failed')
        assert hasattr(flow_controller, 'cleanup_completed')


class TestConnectionFlowControllerBasicOperations:
    """Test basic operations of ConnectionFlowController."""
    
    def test_get_connection_state(self, flow_controller, session_manager):
        """Test getting connection state."""
        session_manager.connection_main_state = ConnectionState.CONNECTED
        
        state = flow_controller.get_connection_state()
        assert state == ConnectionState.CONNECTED
    
    def test_validate_state_consistency_success(self, flow_controller, session_manager):
        """Test state consistency validation when state is consistent."""
        session_manager.validate_state_consistency.return_value = []
        
        inconsistencies = flow_controller.validate_state_consistency()
        
        assert inconsistencies == []
        session_manager.validate_state_consistency.assert_called_once()
    
    def test_validate_state_consistency_with_issues(self, flow_controller, session_manager):
        """Test state consistency validation when inconsistencies are found."""
        expected_issues = [StateInconsistency.MAIN_SUB_STATE_MISMATCH]
        session_manager.validate_state_consistency.return_value = expected_issues
        
        # Mock signal emission
        flow_controller.state_validation_failed = Mock()
        
        inconsistencies = flow_controller.validate_state_consistency()
        
        assert inconsistencies == expected_issues
        flow_controller.state_validation_failed.emit.assert_called_once_with(expected_issues)
    
    @pytest.mark.asyncio
    async def test_recover_from_inconsistent_state_success(self, flow_controller, session_manager):
        """Test successful state recovery."""
        session_manager.attempt_state_recovery.return_value = True
        session_manager.connection_main_state = ConnectionState.DISCONNECTED
        
        # Mock prepare_for_new_connection
        flow_controller.prepare_for_new_connection = AsyncMock(return_value=True)
        
        result = await flow_controller.recover_from_inconsistent_state()
        
        assert result is True
        session_manager.attempt_state_recovery.assert_called_once()
        flow_controller.prepare_for_new_connection.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_recover_from_inconsistent_state_failure(self, flow_controller, session_manager):
        """Test failed state recovery."""
        session_manager.attempt_state_recovery.return_value = False
        
        result = await flow_controller.recover_from_inconsistent_state()
        
        assert result is False
        session_manager.attempt_state_recovery.assert_called_once()
    
    def test_flow_status_methods(self, flow_controller):
        """Test flow status tracking methods."""
        # Initially no flow in progress
        assert flow_controller.is_flow_in_progress() is False
        assert flow_controller.get_current_flow_type() is None
        assert flow_controller.get_flow_duration() is None
        
        # Simulate flow in progress
        flow_controller._current_flow = "test_flow"
        flow_controller._flow_start_time = datetime.now()
        
        assert flow_controller.is_flow_in_progress() is True
        assert flow_controller.get_current_flow_type() == "test_flow"
        assert isinstance(flow_controller.get_flow_duration(), float)


class TestConnectionFlowControllerResourceManagement:
    """Test resource management functionality."""
    
    @pytest.mark.asyncio
    async def test_cleanup_all_resources_success(self, flow_controller, cleanup_manager):
        """Test successful resource cleanup."""
        result = await flow_controller.cleanup_all_resources(timeout=2.0)
        
        assert result is True
        cleanup_manager.cleanup_all_services.assert_called_once_with(2.0)
    
    @pytest.mark.asyncio
    async def test_cleanup_all_resources_partial_failure(self, flow_controller, cleanup_manager):
        """Test resource cleanup with some failures."""
        # Mock mixed results
        failed_result = ServiceCleanupResult(
            service_name="failed_service",
            result=CleanupResult.FAILED,
            duration_seconds=1.0,
            issues=[],
            timestamp=datetime.now()
        )
        success_result = ServiceCleanupResult(
            service_name="success_service",
            result=CleanupResult.SUCCESS,
            duration_seconds=1.0,
            issues=[],
            timestamp=datetime.now()
        )
        
        cleanup_manager.cleanup_all_services.return_value = {
            "failed_service": failed_result,
            "success_service": success_result
        }
        
        result = await flow_controller.cleanup_all_resources()
        
        assert result is False  # Should fail if any service fails
    
    @pytest.mark.asyncio
    async def test_cleanup_all_resources_exception(self, flow_controller, cleanup_manager):
        """Test resource cleanup with exception."""
        cleanup_manager.cleanup_all_services.side_effect = Exception("Cleanup failed")
        
        result = await flow_controller.cleanup_all_resources()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_prepare_for_new_connection_success(self, flow_controller, session_manager, cleanup_manager):
        """Test successful preparation for new connection."""
        # Mock all dependencies to succeed
        flow_controller._validate_connection_readiness = AsyncMock(return_value=True)
        
        result = await flow_controller.prepare_for_new_connection()
        
        assert result is True
        session_manager.clear_error_info.assert_called_once()
        session_manager.clear_stage_progress.assert_called_once()
        cleanup_manager.verify_services_ready.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_prepare_for_new_connection_services_not_ready(self, flow_controller, cleanup_manager):
        """Test preparation failure when services not ready."""
        cleanup_manager.verify_services_ready.return_value = False
        
        result = await flow_controller.prepare_for_new_connection()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_prepare_for_new_connection_with_state_recovery(self, flow_controller, session_manager):
        """Test preparation with state inconsistencies that require recovery."""
        # Mock state inconsistencies
        flow_controller.validate_state_consistency = Mock(return_value=[StateInconsistency.MAIN_SUB_STATE_MISMATCH])
        flow_controller.recover_from_inconsistent_state = AsyncMock(return_value=True)
        flow_controller._validate_connection_readiness = AsyncMock(return_value=True)
        
        result = await flow_controller.prepare_for_new_connection()
        
        assert result is True
        flow_controller.recover_from_inconsistent_state.assert_called_once()


class TestConnectionFlowControllerFlowMethods:
    """Test main flow control methods."""
    
    @pytest.mark.asyncio
    async def test_start_connection_flow_success(self, flow_controller, session_manager):
        """Test successful connection flow start."""
        # Mock readiness validation
        flow_controller._validate_connection_readiness = AsyncMock(return_value=True)
        flow_controller._execute_flow_callbacks = AsyncMock()
        flow_controller.flow_started = Mock()
        
        result = await flow_controller.start_connection_flow("device123")
        
        assert result is True
        session_manager.transition_to_state.assert_called_once_with(
            ConnectionState.CONNECTING, ConnectionSubState.DEVICE_SELECTION
        )
        assert session_manager.connected_emulator_serial == "device123"
        flow_controller.flow_started.emit.assert_called_once_with("connection")
    
    @pytest.mark.asyncio
    async def test_start_connection_flow_with_process_info(self, flow_controller, session_manager):
        """Test connection flow start with process information."""
        flow_controller._validate_connection_readiness = AsyncMock(return_value=True)
        flow_controller._execute_flow_callbacks = AsyncMock()
        flow_controller.flow_started = Mock()
        
        process_info = {
            "pid": 1234,
            "package": "com.test.app",
            "version": "1.0.0"
        }
        
        result = await flow_controller.start_connection_flow("device123", process_info)
        
        assert result is True
        assert session_manager.selected_target_pid == 1234
        assert session_manager.selected_target_package == "com.test.app"
        assert session_manager.selected_target_version == "1.0.0"
    
    @pytest.mark.asyncio
    async def test_start_connection_flow_already_in_progress(self, flow_controller):
        """Test connection flow start when another flow is in progress."""
        flow_controller._current_flow = "existing_flow"
        
        result = await flow_controller.start_connection_flow("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_start_connection_flow_not_ready(self, flow_controller):
        """Test connection flow start when system is not ready."""
        flow_controller._validate_connection_readiness = AsyncMock(return_value=False)
        
        result = await flow_controller.start_connection_flow("device123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_disconnect_flow_success(self, flow_controller, session_manager):
        """Test successful disconnect flow."""
        flow_controller._standard_cleanup = AsyncMock(return_value=True)
        flow_controller.flow_started = Mock()
        flow_controller.flow_completed = Mock()
        flow_controller.cleanup_completed = Mock()
        
        result = await flow_controller.disconnect_flow()
        
        assert result is True
        session_manager.transition_to_state.assert_any_call(ConnectionState.DISCONNECTING)
        session_manager.transition_to_state.assert_any_call(ConnectionState.DISCONNECTED)
        session_manager.reset_connection_state.assert_called_once()
        flow_controller.flow_completed.emit.assert_called_once_with("disconnect", True)
        flow_controller.cleanup_completed.emit.assert_called_once_with(True)
    
    @pytest.mark.asyncio
    async def test_disconnect_flow_different_cleanup_levels(self, flow_controller):
        """Test disconnect flow with different cleanup levels."""
        flow_controller._minimal_cleanup = AsyncMock(return_value=True)
        flow_controller._standard_cleanup = AsyncMock(return_value=True)
        flow_controller._full_cleanup = AsyncMock(return_value=True)
        flow_controller.flow_started = Mock()
        flow_controller.flow_completed = Mock()
        flow_controller.cleanup_completed = Mock()
        
        # Test minimal cleanup
        await flow_controller.disconnect_flow(CleanupLevel.MINIMAL)
        flow_controller._minimal_cleanup.assert_called_once()
        
        # Test standard cleanup
        await flow_controller.disconnect_flow(CleanupLevel.STANDARD)
        flow_controller._standard_cleanup.assert_called_once()
        
        # Test full cleanup
        await flow_controller.disconnect_flow(CleanupLevel.FULL)
        flow_controller._full_cleanup.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_reconnect_flow_success(self, flow_controller, session_manager):
        """Test successful reconnect flow."""
        # Set up previous connection info
        session_manager.connected_emulator_serial = "device123"
        session_manager.selected_target_pid = 1234
        session_manager.selected_target_package = "com.test.app"
        session_manager.selected_target_version = "1.0.0"
        session_manager.connection_main_state = ConnectionState.DISCONNECTED
        
        # Mock the start_connection_flow method
        flow_controller.start_connection_flow = AsyncMock(return_value=True)
        
        result = await flow_controller.reconnect_flow()
        
        assert result is True
        expected_process_info = {
            "pid": 1234,
            "package": "com.test.app",
            "version": "1.0.0"
        }
        flow_controller.start_connection_flow.assert_called_once_with("device123", expected_process_info)
    
    @pytest.mark.asyncio
    async def test_reconnect_flow_no_previous_device(self, flow_controller, session_manager):
        """Test reconnect flow when no previous device information is available."""
        session_manager.connected_emulator_serial = None
        flow_controller.flow_error = Mock()
        
        result = await flow_controller.reconnect_flow()
        
        assert result is False
        flow_controller.flow_error.emit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_reconnect_flow_with_disconnect_first(self, flow_controller, session_manager):
        """Test reconnect flow when currently connected (requires disconnect first)."""
        session_manager.connected_emulator_serial = "device123"
        session_manager.connection_main_state = ConnectionState.ACTIVE
        
        flow_controller.disconnect_flow = AsyncMock(return_value=True)
        flow_controller.start_connection_flow = AsyncMock(return_value=True)
        
        result = await flow_controller.reconnect_flow()
        
        assert result is True
        flow_controller.disconnect_flow.assert_called_once_with(CleanupLevel.STANDARD)
        flow_controller.start_connection_flow.assert_called_once()


class TestConnectionFlowControllerRegistrationMethods:
    """Test registration and callback methods."""
    
    def test_add_remove_readiness_validator(self, flow_controller):
        """Test adding and removing readiness validators."""
        def test_validator():
            return True
        
        # Add validator
        flow_controller.add_readiness_validator(test_validator)
        assert test_validator in flow_controller._readiness_validators
        
        # Remove validator
        flow_controller.remove_readiness_validator(test_validator)
        assert test_validator not in flow_controller._readiness_validators
    
    def test_register_unregister_flow_callback(self, flow_controller):
        """Test registering and unregistering flow callbacks."""
        def test_callback():
            pass
        
        # Register callback
        flow_controller.register_flow_callback("test_flow", "start", test_callback)
        assert "test_flow_start" in flow_controller._flow_callbacks
        assert test_callback in flow_controller._flow_callbacks["test_flow_start"]
        
        # Unregister callback
        flow_controller.unregister_flow_callback("test_flow", "start", test_callback)
        assert test_callback not in flow_controller._flow_callbacks["test_flow_start"]


class TestConnectionFlowControllerHelperMethods:
    """Test helper methods."""
    
    @pytest.mark.asyncio
    async def test_validate_connection_readiness_success(self, flow_controller, session_manager, cleanup_manager):
        """Test successful connection readiness validation."""
        session_manager.connection_main_state = ConnectionState.DISCONNECTED
        
        result = await flow_controller._validate_connection_readiness()
        
        assert result is True
        cleanup_manager.verify_services_ready.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_connection_readiness_wrong_state(self, flow_controller, session_manager):
        """Test connection readiness validation with wrong state."""
        session_manager.connection_main_state = ConnectionState.ACTIVE
        
        result = await flow_controller._validate_connection_readiness()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_connection_readiness_custom_validator_failure(self, flow_controller, session_manager):
        """Test connection readiness validation with failing custom validator."""
        session_manager.connection_main_state = ConnectionState.DISCONNECTED
        
        def failing_validator():
            return False
        
        flow_controller.add_readiness_validator(failing_validator)
        
        result = await flow_controller._validate_connection_readiness()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_execute_flow_callbacks(self, flow_controller):
        """Test execution of flow callbacks."""
        sync_callback = Mock()
        async_callback = AsyncMock()
        
        flow_controller.register_flow_callback("test", "phase", sync_callback)
        flow_controller.register_flow_callback("test", "phase", async_callback)
        
        await flow_controller._execute_flow_callbacks("test", "phase")
        
        sync_callback.assert_called_once()
        async_callback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_methods(self, flow_controller, session_manager, cleanup_manager):
        """Test different cleanup methods."""
        # Test minimal cleanup
        result = await flow_controller._minimal_cleanup()
        assert result is True
        session_manager.reset_connection_state.assert_called_once()
        
        # Test standard cleanup
        result = await flow_controller._standard_cleanup()
        assert result is True
        cleanup_manager.cleanup_all_services.assert_called_once()
        
        # Test full cleanup
        result = await flow_controller._full_cleanup()
        assert result is True
        cleanup_manager.force_cleanup_all.assert_called_once()
        session_manager.reset_all_state.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])