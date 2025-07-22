"""
Unit tests for ResourceCleanupManager and related components.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock
from src.tower_iq.core.cleanup_manager import (
    ResourceCleanupManager, ServiceLifecycle, ServiceState, CleanupResult,
    CleanupIssue, ServiceCleanupResult
)


class MockService(ServiceLifecycle):
    """Mock service for testing."""
    
    def __init__(self, name: str, cleanup_delay: float = 0.0, 
                 cleanup_success: bool = True, should_timeout: bool = False):
        self._name = name
        self._state = ServiceState.READY
        self._cleanup_delay = cleanup_delay
        self._cleanup_success = cleanup_success
        self._should_timeout = should_timeout
        self._ready_for_connection = True
        
        # Track method calls
        self.initialize_called = False
        self.cleanup_called = False
        self.reset_called = False
    
    async def initialize(self) -> bool:
        self.initialize_called = True
        self._state = ServiceState.READY
        return True
    
    async def cleanup(self) -> bool:
        self.cleanup_called = True
        self._state = ServiceState.CLEANING_UP
        
        if self._should_timeout:
            # Simulate a service that takes too long
            await asyncio.sleep(10.0)
        
        if self._cleanup_delay > 0:
            await asyncio.sleep(self._cleanup_delay)
        
        if self._cleanup_success:
            self._state = ServiceState.READY
            return True
        else:
            self._state = ServiceState.ERROR
            return False
    
    async def reset(self) -> bool:
        self.reset_called = True
        self._state = ServiceState.READY
        self._ready_for_connection = True
        return True
    
    def get_state(self) -> ServiceState:
        return self._state
    
    def is_ready_for_connection(self) -> bool:
        return self._ready_for_connection
    
    @property
    def service_name(self) -> str:
        return self._name
    
    def set_ready_for_connection(self, ready: bool):
        """Test helper to control readiness."""
        self._ready_for_connection = ready


class TestResourceCleanupManager:
    """Test ResourceCleanupManager functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.service1 = MockService("service1")
        self.service2 = MockService("service2")
        self.service3 = MockService("service3")
        self.cleanup_manager = ResourceCleanupManager([self.service1, self.service2, self.service3])
    
    @pytest.mark.asyncio
    async def test_successful_cleanup_all(self):
        """Test successful cleanup of all services."""
        results = await self.cleanup_manager.cleanup_all_services(timeout=5.0)
        
        assert len(results) == 3
        assert all(result.result == CleanupResult.SUCCESS for result in results.values())
        assert all(service.cleanup_called for service in [self.service1, self.service2, self.service3])
        
        # Check that results are recorded in history
        history = self.cleanup_manager.get_cleanup_history()
        assert len(history) == 3
    
    @pytest.mark.asyncio
    async def test_cleanup_with_failure(self):
        """Test cleanup when one service fails."""
        self.service2 = MockService("service2", cleanup_success=False)
        self.cleanup_manager = ResourceCleanupManager([self.service1, self.service2, self.service3])
        
        results = await self.cleanup_manager.cleanup_all_services()
        
        assert results["service1"].result == CleanupResult.SUCCESS
        assert results["service2"].result == CleanupResult.FAILED
        assert results["service3"].result == CleanupResult.SUCCESS
        
        # Check that failure is recorded with issues
        failed_result = results["service2"]
        assert len(failed_result.issues) > 0
        assert any(issue.issue_type == "cleanup_failed" for issue in failed_result.issues)
    
    @pytest.mark.asyncio
    async def test_cleanup_with_timeout(self):
        """Test cleanup when a service times out."""
        self.service2 = MockService("service2", should_timeout=True)
        self.cleanup_manager = ResourceCleanupManager([self.service1, self.service2, self.service3])
        
        results = await self.cleanup_manager.cleanup_all_services(timeout=1.0)
        
        assert results["service1"].result == CleanupResult.SUCCESS
        assert results["service2"].result in [CleanupResult.TIMEOUT, CleanupResult.PARTIAL_SUCCESS]
        assert results["service3"].result == CleanupResult.SUCCESS
        
        # Check that timeout is recorded with issues
        timeout_result = results["service2"]
        assert len(timeout_result.issues) > 0
        assert any(issue.issue_type == "timeout" for issue in timeout_result.issues)
        
        # Verify that forced cleanup was attempted
        assert self.service2.reset_called
    
    @pytest.mark.asyncio
    async def test_cleanup_single_service(self):
        """Test cleanup of a single service."""
        result = await self.cleanup_manager.cleanup_service(self.service1)
        
        assert result.result == CleanupResult.SUCCESS
        assert result.service_name == "service1"
        assert self.service1.cleanup_called
        
        # Check that result is recorded in history
        history = self.cleanup_manager.get_cleanup_history()
        assert len(history) == 1
        assert history[0] == result
    
    @pytest.mark.asyncio
    async def test_force_cleanup_all(self):
        """Test forced cleanup of all services."""
        await self.cleanup_manager.force_cleanup_all()
        
        assert all(service.reset_called for service in [self.service1, self.service2, self.service3])
    
    def test_validate_cleanup_completion_success(self):
        """Test validation when all services are in good state."""
        issues = self.cleanup_manager.validate_cleanup_completion()
        assert len(issues) == 0
    
    def test_validate_cleanup_completion_with_issues(self):
        """Test validation when services have issues."""
        # Set one service to not ready
        self.service1.set_ready_for_connection(False)
        
        # Set another service to error state
        self.service2._state = ServiceState.ERROR
        
        issues = self.cleanup_manager.validate_cleanup_completion()
        
        assert len(issues) >= 2
        issue_types = [issue.issue_type for issue in issues]
        assert "not_ready" in issue_types
        assert "invalid_state" in issue_types
    
    @pytest.mark.asyncio
    async def test_verify_services_ready_success(self):
        """Test service readiness verification when all are ready."""
        ready = await self.cleanup_manager.verify_services_ready()
        assert ready is True
    
    @pytest.mark.asyncio
    async def test_verify_services_ready_failure(self):
        """Test service readiness verification when one is not ready."""
        self.service2.set_ready_for_connection(False)
        
        ready = await self.cleanup_manager.verify_services_ready()
        assert ready is False
    
    def test_service_management(self):
        """Test adding and removing services."""
        new_service = MockService("new_service")
        
        # Test adding service
        self.cleanup_manager.add_service(new_service)
        assert new_service in self.cleanup_manager.services
        
        # Test getting service by name
        found_service = self.cleanup_manager.get_service_by_name("new_service")
        assert found_service == new_service
        
        # Test removing service
        removed = self.cleanup_manager.remove_service(new_service)
        assert removed is True
        assert new_service not in self.cleanup_manager.services
        
        # Test removing non-existent service
        removed = self.cleanup_manager.remove_service(new_service)
        assert removed is False
    
    def test_cleanup_history_management(self):
        """Test cleanup history tracking."""
        # Initially empty
        history = self.cleanup_manager.get_cleanup_history()
        assert len(history) == 0
        
        # Add some mock results
        result1 = ServiceCleanupResult(
            service_name="test1",
            result=CleanupResult.SUCCESS,
            duration_seconds=1.0,
            issues=[],
            timestamp=datetime.now()
        )
        
        self.cleanup_manager.cleanup_history.append(result1)
        
        history = self.cleanup_manager.get_cleanup_history()
        assert len(history) == 1
        assert history[0] == result1
        
        # Test clearing history
        self.cleanup_manager.clear_cleanup_history()
        history = self.cleanup_manager.get_cleanup_history()
        assert len(history) == 0
    
    @pytest.mark.asyncio
    async def test_cleanup_with_exception(self):
        """Test cleanup when a service raises an exception."""
        # Create a service that raises an exception during cleanup
        class ExceptionService(ServiceLifecycle):
            @property
            def service_name(self) -> str:
                return "exception_service"
            
            async def initialize(self) -> bool:
                return True
            
            async def cleanup(self) -> bool:
                raise RuntimeError("Cleanup failed with exception")
            
            async def reset(self) -> bool:
                return True
            
            def get_state(self) -> ServiceState:
                return ServiceState.READY
            
            def is_ready_for_connection(self) -> bool:
                return True
        
        exception_service = ExceptionService()
        cleanup_manager = ResourceCleanupManager([exception_service])
        
        results = await cleanup_manager.cleanup_all_services()
        
        assert len(results) == 1
        result = results["exception_service"]
        assert result.result == CleanupResult.FAILED
        assert len(result.issues) > 0
        assert any(issue.issue_type == "exception" for issue in result.issues)
    
    @pytest.mark.asyncio
    async def test_cleanup_timing(self):
        """Test that cleanup timing is recorded correctly."""
        # Create a service with a known delay
        delayed_service = MockService("delayed", cleanup_delay=0.1)
        cleanup_manager = ResourceCleanupManager([delayed_service])
        
        result = await cleanup_manager.cleanup_service(delayed_service)
        
        assert result.duration_seconds >= 0.1
        assert result.duration_seconds < 1.0  # Should not take too long
    
    def test_cleanup_issue_creation(self):
        """Test CleanupIssue dataclass."""
        issue = CleanupIssue(
            service_name="test_service",
            issue_type="test_issue",
            description="Test description",
            is_critical=True,
            timestamp=datetime.now()
        )
        
        assert issue.service_name == "test_service"
        assert issue.issue_type == "test_issue"
        assert issue.is_critical is True
    
    def test_service_cleanup_result_creation(self):
        """Test ServiceCleanupResult dataclass."""
        issues = [CleanupIssue(
            service_name="test",
            issue_type="test",
            description="Test",
            is_critical=False,
            timestamp=datetime.now()
        )]
        
        result = ServiceCleanupResult(
            service_name="test_service",
            result=CleanupResult.SUCCESS,
            duration_seconds=1.5,
            issues=issues,
            timestamp=datetime.now()
        )
        
        assert result.service_name == "test_service"
        assert result.result == CleanupResult.SUCCESS
        assert result.duration_seconds == 1.5
        assert len(result.issues) == 1


if __name__ == "__main__":
    pytest.main([__file__])