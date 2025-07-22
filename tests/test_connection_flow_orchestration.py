"""
Integration tests for ConnectionFlowController robust connection flow orchestration

Tests the comprehensive error handling, retry logic, and proper state transitions
implemented in task 2.2.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from src.tower_iq.services.connection_flow_controller import (
    ConnectionFlowController, CleanupLevel, ConnectionStage, RetryStrategy,
    ConnectionFlowError, ConnectionReadinessError, StateTransitionError
)
from src.tower_iq.core.session import (
    SessionManager, ConnectionState, ConnectionSubState, ErrorInfo, ErrorType,
    StageProgress, StageStatus, StateInconsistency
)
from src.tower_iq.core.cleanup_manager import (
    ResourceCleanupManager, ServiceLifecycle, ServiceCleanupResult,
    CleanupResult, ServiceState
)
from src.tower_iq.services.connection_stage_manager import ConnectionStageManager
from src.tower_iq.services.emulator_service import EmulatorService
from src.tower_iq.services.frida_service import FridaService


class MockEmulatorService:
    """Mock emulator service for testing."""
    
    def __init__(self, should_fail=False, fail_stage=None):
        self.should_fail = should_fail
        self.fail_stage = fail_stage
        self.call_count = 0
    
    async def find_and_connect_device(self, device_id):
        self.call_count += 1
        if self.should_fail and self.fail_stage == "device_validation":
            if self.call_count <= 2:  # Fail first 2 attempts
                raise Exception("Device connection failed")
        return device_id
    
    async def ensure_frida_server_is_running(self, device_id):
        if self.should_fail and self.fail_stage == "frida_setup":
            raise Exception("Frida server setup failed")
        return True
    
    async def is_frida_server_responsive(self, device_id):
        if self.should_fail and self.fail_stage == "frida_verify":
            return False
        return True


class MockFridaService:
    """Mock frida service for testing."""
    
    def __init__(self, should_fail=False, fail_stage=None):
        self.should_fail = should_fail
        self.fail_stage = fail_stage
        self.session = Mock()
    
    def check_local_hook_compatibility(self, package, version):
        if self.should_fail and self.fail_stage == "hook_compatibility":
            return False
        return True
    
    async def attach(self, pid, device_id):
        if self.should_fail and self.fail_stage == "process_attachment":
            return False
        return True
    
    async def inject_script(self, version):
        if self.should_fail and self.fail_stage == "script_injection":
            return False
        return True


class MockStageManager:
    """Mock stage manager for testing."""
    
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
    
    async def execute_connection_flow(self, device_id, process_info):
        if self.should_fail:
            return False
        return True


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
    manager.update_stage_progress = Mock()
    
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
def flow_controller_with_services(session_manager, cleanup_manager):
    """Create a ConnectionFlowController with mock services."""
    emulator_service = MockEmulatorService()
    frida_service = MockFridaService()
    stage_manager = MockStageManager()
    
    controller = ConnectionFlowController(
        session_manager=session_manager,
        cleanup_manager=cleanup_manager,
        stage_manager=stage_manager,
        emulator_service=emulator_service,
        frida_service=frida_service
    )
    
    return controller, emulator_service, frida_service, stage_manager


class TestConnectionFlowOrchestration:
    """Test connection flow orchestration functionality."""
    
    @pytest.mark.asyncio
    async def test_successful_connection_flow_orchestration(self, flow_controller_with_services, session_manager):
        """Test successful complete connection flow orchestration."""
        controller, emulator_service, frida_service, stage_manager = flow_controller_with_services
        
        # Mock successful flow
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        process_info = {
            "pid": 1234,
            "package": "com.test.app",
            "version": "1.0.0"
        }
        
        result = await controller.start_connection_flow("device123", process_info)
        
        assert result is True
        controller.flow_started.emit.assert_called_once_with("connection")
        controller.flow_completed.emit.assert_called_once_with("connection", True)
        
        # Verify state transitions
        assert session_manager.transition_to_state.call_count >= 2
        session_manager.transition_to_state.assert_any_call(
            ConnectionState.CONNECTING, ConnectionSubState.DEVICE_SELECTION
        )
    
    @pytest.mark.asyncio
    async def test_connection_flow_with_device_validation_failure(self, flow_controller_with_services, session_manager):
        """Test connection flow with device validation failure."""
        controller, emulator_service, frida_service, stage_manager = flow_controller_with_services
        
        # Make device validation fail
        emulator_service.should_fail = True
        emulator_service.fail_stage = "device_validation"
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        controller.flow_error = Mock()
        
        result = await controller.start_connection_flow("device123")
        
        assert result is False
        controller.flow_completed.emit.assert_called_once_with("connection", False)
    
    @pytest.mark.asyncio
    async def test_connection_flow_with_retry_logic(self, flow_controller_with_services, session_manager):
        """Test connection flow with retry logic for recoverable errors."""
        controller, emulator_service, frida_service, stage_manager = flow_controller_with_services
        
        # Make device validation fail first 2 attempts, then succeed
        emulator_service.should_fail = True
        emulator_service.fail_stage = "device_validation"
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        # Mock the retry configuration to allow retries for unknown errors (which device validation will be categorized as)
        controller._retry_config[ErrorType.UNKNOWN]["max_retries"] = 3
        
        result = await controller.start_connection_flow("device123")
        
        # Should eventually succeed after retries
        assert emulator_service.call_count >= 2  # Multiple attempts made
    
    @pytest.mark.asyncio
    async def test_connection_flow_with_frida_server_setup_failure(self, flow_controller_with_services, session_manager):
        """Test connection flow with Frida server setup failure."""
        controller, emulator_service, frida_service, stage_manager = flow_controller_with_services
        
        # Make Frida server setup fail
        stage_manager.should_fail = True
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        result = await controller.start_connection_flow("device123")
        
        assert result is False
        controller.flow_completed.emit.assert_called_once_with("connection", False)
    
    @pytest.mark.asyncio
    async def test_connection_flow_with_hook_compatibility_failure(self, flow_controller_with_services, session_manager):
        """Test connection flow with hook compatibility failure."""
        controller, emulator_service, frida_service, stage_manager = flow_controller_with_services
        
        # Make hook compatibility check fail
        frida_service.should_fail = True
        frida_service.fail_stage = "hook_compatibility"
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        process_info = {
            "pid": 1234,
            "package": "com.unsupported.app",
            "version": "1.0.0"
        }
        
        result = await controller.start_connection_flow("device123", process_info)
        
        assert result is False
        controller.flow_completed.emit.assert_called_once_with("connection", False)
    
    @pytest.mark.asyncio
    async def test_connection_flow_with_process_attachment_failure(self, flow_controller_with_services, session_manager):
        """Test connection flow with process attachment failure."""
        controller, emulator_service, frida_service, stage_manager = flow_controller_with_services
        
        # Make process attachment fail
        frida_service.should_fail = True
        frida_service.fail_stage = "process_attachment"
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        process_info = {
            "pid": 1234,
            "package": "com.test.app",
            "version": "1.0.0"
        }
        
        result = await controller.start_connection_flow("device123", process_info)
        
        assert result is False
        controller.flow_completed.emit.assert_called_once_with("connection", False)
    
    @pytest.mark.asyncio
    async def test_connection_flow_with_script_injection_failure(self, flow_controller_with_services, session_manager):
        """Test connection flow with script injection failure."""
        controller, emulator_service, frida_service, stage_manager = flow_controller_with_services
        
        # Make script injection fail
        frida_service.should_fail = True
        frida_service.fail_stage = "script_injection"
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        process_info = {
            "pid": 1234,
            "package": "com.test.app",
            "version": "1.0.0"
        }
        
        result = await controller.start_connection_flow("device123", process_info)
        
        assert result is False
        controller.flow_completed.emit.assert_called_once_with("connection", False)


class TestErrorHandlingAndRecovery:
    """Test comprehensive error handling and recovery mechanisms."""
    
    def test_error_categorization(self, flow_controller_with_services):
        """Test error categorization functionality."""
        controller, _, _, _ = flow_controller_with_services
        
        # Test network errors
        assert controller._categorize_error("connection failed") == ErrorType.NETWORK
        assert controller._categorize_error("network timeout") == ErrorType.NETWORK
        assert controller._categorize_error("socket error") == ErrorType.NETWORK
        
        # Test permission errors
        assert controller._categorize_error("permission denied") == ErrorType.PERMISSION
        assert controller._categorize_error("access denied") == ErrorType.PERMISSION
        assert controller._categorize_error("root required") == ErrorType.PERMISSION
        
        # Test resource errors
        assert controller._categorize_error("out of memory") == ErrorType.RESOURCE
        assert controller._categorize_error("insufficient storage") == ErrorType.RESOURCE
        assert controller._categorize_error("resource busy") == ErrorType.RESOURCE
        
        # Test compatibility errors
        assert controller._categorize_error("version mismatch") == ErrorType.COMPATIBILITY
        assert controller._categorize_error("unsupported architecture") == ErrorType.COMPATIBILITY
        
        # Test unknown errors
        assert controller._categorize_error("random error") == ErrorType.UNKNOWN
    
    def test_retry_configuration(self, flow_controller_with_services):
        """Test retry configuration for different error types."""
        controller, _, _, _ = flow_controller_with_services
        
        # Test network error retry config
        network_config = controller._retry_config[ErrorType.NETWORK]
        assert network_config["max_retries"] == 3
        assert network_config["strategy"] == RetryStrategy.EXPONENTIAL_BACKOFF
        assert network_config["jitter"] is True
        
        # Test permission error retry config (should not retry)
        permission_config = controller._retry_config[ErrorType.PERMISSION]
        assert permission_config["max_retries"] == 0
        assert permission_config["strategy"] == RetryStrategy.NO_RETRY
        
        # Test timeout error retry config
        timeout_config = controller._retry_config[ErrorType.TIMEOUT]
        assert timeout_config["max_retries"] == 2
        assert timeout_config["strategy"] == RetryStrategy.LINEAR_BACKOFF
    
    @pytest.mark.asyncio
    async def test_retry_delay_calculation(self, flow_controller_with_services):
        """Test retry delay calculation for different strategies."""
        controller, _, _, _ = flow_controller_with_services
        
        # Test exponential backoff
        delay1 = await controller._calculate_retry_delay(ErrorType.NETWORK, 0)
        delay2 = await controller._calculate_retry_delay(ErrorType.NETWORK, 1)
        delay3 = await controller._calculate_retry_delay(ErrorType.NETWORK, 2)
        
        # Exponential backoff should increase delays (accounting for jitter)
        assert delay1 >= 0
        assert delay2 > delay1 * 0.8  # Account for jitter
        assert delay3 > delay2 * 0.8
        
        # Test linear backoff
        delay1 = await controller._calculate_retry_delay(ErrorType.TIMEOUT, 0)
        delay2 = await controller._calculate_retry_delay(ErrorType.TIMEOUT, 1)
        
        # Linear backoff should have predictable increases
        assert delay2 == delay1 * 2  # No jitter for timeout
        
        # Test no retry
        delay = await controller._calculate_retry_delay(ErrorType.PERMISSION, 0)
        assert delay == 0.0
        
        # Test immediate retry
        delay = await controller._calculate_retry_delay(ErrorType.RESOURCE, 0)
        assert delay == 0.0
    
    def test_recovery_suggestions(self, flow_controller_with_services):
        """Test recovery suggestions for different error types."""
        controller, _, _, _ = flow_controller_with_services
        
        # Test network error suggestions
        suggestions = controller._get_recovery_suggestions_for_error("connection failed")
        assert any("device connection" in s.lower() for s in suggestions)
        assert any("adb" in s.lower() for s in suggestions)
        
        # Test permission error suggestions
        suggestions = controller._get_recovery_suggestions_for_error("permission denied")
        assert any("root access" in s.lower() for s in suggestions)
        assert any("permissions" in s.lower() for s in suggestions)
        
        # Test timeout error suggestions
        suggestions = controller._get_recovery_suggestions_for_error("timeout occurred")
        assert any("wait" in s.lower() for s in suggestions)
        assert any("try again" in s.lower() for s in suggestions)
        
        # Test memory error suggestions
        suggestions = controller._get_recovery_suggestions_for_error("out of memory")
        assert any("close" in s.lower() for s in suggestions)
        assert any("memory" in s.lower() for s in suggestions)
    
    def test_stage_specific_recovery_suggestions(self, flow_controller_with_services):
        """Test stage-specific recovery suggestions."""
        controller, _, _, _ = flow_controller_with_services
        
        # Test device validation suggestions
        suggestions = controller._get_stage_recovery_suggestions(ConnectionStage.DEVICE_VALIDATION)
        assert any("adb" in s.lower() for s in suggestions)
        assert any("device" in s.lower() for s in suggestions)
        
        # Test Frida server setup suggestions
        suggestions = controller._get_stage_recovery_suggestions(ConnectionStage.FRIDA_SERVER_SETUP)
        assert any("root" in s.lower() for s in suggestions)
        assert any("storage" in s.lower() for s in suggestions)
        
        # Test hook compatibility suggestions
        suggestions = controller._get_stage_recovery_suggestions(ConnectionStage.HOOK_COMPATIBILITY)
        assert any("version" in s.lower() for s in suggestions)
        assert any("supported" in s.lower() for s in suggestions)


class TestStateTransitions:
    """Test proper state transitions during connection flow."""
    
    @pytest.mark.asyncio
    async def test_state_transitions_during_successful_flow(self, flow_controller_with_services, session_manager):
        """Test state transitions during successful connection flow."""
        controller, _, _, _ = flow_controller_with_services
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        # Provide process info for successful flow
        process_info = {
            "pid": 1234,
            "package": "com.test.app",
            "version": "1.0.0"
        }
        
        result = await controller.start_connection_flow("device123", process_info)
        
        assert result is True
        
        # Verify state transition calls
        transition_calls = session_manager.transition_to_state.call_args_list
        
        # Should have multiple state transitions
        assert len(transition_calls) >= 2
        
        # First transition should be to CONNECTING
        first_call = transition_calls[0]
        assert first_call[0][0] == ConnectionState.CONNECTING
        assert first_call[0][1] == ConnectionSubState.DEVICE_SELECTION
    
    @pytest.mark.asyncio
    async def test_state_transitions_during_failed_flow(self, flow_controller_with_services, session_manager):
        """Test state transitions during failed connection flow."""
        controller, emulator_service, _, _ = flow_controller_with_services
        
        # Make device validation fail
        emulator_service.should_fail = True
        emulator_service.fail_stage = "device_validation"
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        result = await controller.start_connection_flow("device123")
        
        assert result is False
        
        # Should still have initial state transition
        session_manager.transition_to_state.assert_called()
        
        # Should set error info
        session_manager.set_error_info.assert_called()
    
    @pytest.mark.asyncio
    async def test_state_validation_during_flow(self, flow_controller_with_services, session_manager):
        """Test state validation during connection flow."""
        controller, _, _, _ = flow_controller_with_services
        
        # Mock state inconsistencies
        session_manager.validate_state_consistency.return_value = [StateInconsistency.MAIN_SUB_STATE_MISMATCH]
        session_manager.attempt_state_recovery.return_value = True
        
        controller.flow_started = Mock()
        controller.flow_completed = Mock()
        
        # Should still succeed after state recovery
        result = await controller.start_connection_flow("device123")
        
        # State validation and recovery should be called during preparation
        await controller.prepare_for_new_connection()
        session_manager.validate_state_consistency.assert_called()
        session_manager.attempt_state_recovery.assert_called()


class TestConnectionReadinessValidation:
    """Test connection readiness validation functionality."""
    
    @pytest.mark.asyncio
    async def test_connection_readiness_validation_success(self, flow_controller_with_services, session_manager, cleanup_manager):
        """Test successful connection readiness validation."""
        controller, _, _, _ = flow_controller_with_services
        
        session_manager.connection_main_state = ConnectionState.DISCONNECTED
        
        result = await controller._validate_connection_readiness()
        
        assert result is True
        cleanup_manager.verify_services_ready.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connection_readiness_validation_wrong_state(self, flow_controller_with_services, session_manager):
        """Test connection readiness validation with wrong state."""
        controller, _, _, _ = flow_controller_with_services
        
        session_manager.connection_main_state = ConnectionState.ACTIVE
        
        result = await controller._validate_connection_readiness()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_connection_readiness_validation_services_not_ready(self, flow_controller_with_services, cleanup_manager):
        """Test connection readiness validation when services not ready."""
        controller, _, _, _ = flow_controller_with_services
        
        cleanup_manager.verify_services_ready.return_value = False
        
        result = await controller._validate_connection_readiness()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_connection_readiness_validation_custom_validators(self, flow_controller_with_services, session_manager):
        """Test connection readiness validation with custom validators."""
        controller, _, _, _ = flow_controller_with_services
        
        session_manager.connection_main_state = ConnectionState.DISCONNECTED
        
        # Add custom validators
        validator1 = Mock(return_value=True)
        validator2 = Mock(return_value=False)  # This one fails
        
        controller.add_readiness_validator(validator1)
        controller.add_readiness_validator(validator2)
        
        result = await controller._validate_connection_readiness()
        
        assert result is False
        validator1.assert_called_once()
        validator2.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])