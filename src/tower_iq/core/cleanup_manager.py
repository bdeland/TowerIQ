"""
TowerIQ Resource Cleanup Manager

This module provides the ResourceCleanupManager class for coordinating
cleanup operations across services with timeout handling and validation.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict
import structlog

logger = structlog.get_logger(__name__)


class ServiceState(Enum):
    """States that a service can be in."""
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    READY = "ready"
    ACTIVE = "active"
    CLEANING_UP = "cleaning_up"
    ERROR = "error"


class CleanupResult(Enum):
    """Results of cleanup operations."""
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    TIMEOUT = "timeout"
    FAILED = "failed"


@dataclass
class CleanupIssue:
    """Information about a cleanup issue."""
    service_name: str
    issue_type: str
    description: str
    is_critical: bool
    timestamp: datetime


@dataclass
class ServiceCleanupResult:
    """Result of cleaning up a single service."""
    service_name: str
    result: CleanupResult
    duration_seconds: float
    issues: List[CleanupIssue]
    timestamp: datetime


class ServiceLifecycle(ABC):
    """Abstract interface for services that need lifecycle management."""

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the service. Returns True if successful."""
        pass

    @abstractmethod
    async def cleanup(self) -> bool:
        """Clean up service resources. Returns True if successful."""
        pass

    @abstractmethod
    async def reset(self) -> bool:
        """Reset service to initial state. Returns True if successful."""
        pass

    @abstractmethod
    def get_state(self) -> ServiceState:
        """Get current service state."""
        pass

    @abstractmethod
    def is_ready_for_connection(self) -> bool:
        """Check if service is ready for new connections."""
        pass

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Get the service name for identification."""
        pass


class ResourceCleanupManager:
    """
    Manages resource cleanup across multiple services with timeout handling
    and validation.
    """

    def __init__(self, services: List[ServiceLifecycle], default_timeout: float = 5.0):
        """
        Initialize the cleanup manager.

        Args:
            services: List of services implementing ServiceLifecycle
            default_timeout: Default timeout for cleanup operations in seconds
        """
        self.services = services
        self.default_timeout = default_timeout
        self.cleanup_history: List[ServiceCleanupResult] = []
        self._logger = logger.bind(component="ResourceCleanupManager")

    async def cleanup_all_services(self, timeout: Optional[float] = None) -> Dict[str, ServiceCleanupResult]:
        """
        Clean up all registered services with timeout handling.

        Args:
            timeout: Timeout for the entire cleanup operation

        Returns:
            Dictionary mapping service names to their cleanup results
        """
        if timeout is None:
            timeout = self.default_timeout

        self._logger.info("Starting cleanup of all services",
                         service_count=len(self.services),
                         timeout=timeout)

        results = {}
        cleanup_tasks = []

        # Create cleanup tasks for all services
        for service in self.services:
            task = asyncio.create_task(
                self._cleanup_service_with_timeout(service, timeout / len(self.services))
            )
            cleanup_tasks.append((service.service_name, task))

        # Wait for all cleanup tasks to complete
        for service_name, task in cleanup_tasks:
            try:
                result = await task
                results[service_name] = result
                self.cleanup_history.append(result)
            except Exception as e:
                self._logger.error("Unexpected error during service cleanup",
                                 service=service_name, error=str(e))
                results[service_name] = ServiceCleanupResult(
                    service_name=service_name,
                    result=CleanupResult.FAILED,
                    duration_seconds=0.0,
                    issues=[CleanupIssue(
                        service_name=service_name,
                        issue_type="exception",
                        description=f"Unexpected error: {str(e)}",
                        is_critical=True,
                        timestamp=datetime.now()
                    )],
                    timestamp=datetime.now()
                )

        # Log overall results
        success_count = sum(1 for r in results.values() if r.result == CleanupResult.SUCCESS)
        self._logger.info("Cleanup operation completed",
                         total_services=len(results),
                         successful=success_count,
                         failed=len(results) - success_count)

        return results

    async def _cleanup_service_with_timeout(self, service: ServiceLifecycle,
                                          timeout: float) -> ServiceCleanupResult:
        """
        Clean up a single service with timeout handling.

        Args:
            service: The service to clean up
            timeout: Timeout for this service's cleanup

        Returns:
            ServiceCleanupResult with the outcome
        """
        start_time = datetime.now()
        issues = []

        try:
            # Attempt normal cleanup with timeout
            cleanup_successful = await asyncio.wait_for(
                service.cleanup(),
                timeout=timeout
            )

            duration = (datetime.now() - start_time).total_seconds()

            if cleanup_successful:
                self._logger.info("Service cleanup successful",
                                service=service.service_name,
                                duration=duration)
                return ServiceCleanupResult(
                    service_name=service.service_name,
                    result=CleanupResult.SUCCESS,
                    duration_seconds=duration,
                    issues=issues,
                    timestamp=start_time
                )
            else:
                issues.append(CleanupIssue(
                    service_name=service.service_name,
                    issue_type="cleanup_failed",
                    description="Service cleanup returned False",
                    is_critical=True,
                    timestamp=datetime.now()
                ))

                self._logger.warning("Service cleanup failed",
                                   service=service.service_name,
                                   duration=duration)
                return ServiceCleanupResult(
                    service_name=service.service_name,
                    result=CleanupResult.FAILED,
                    duration_seconds=duration,
                    issues=issues,
                    timestamp=start_time
                )

        except asyncio.TimeoutError:
            duration = (datetime.now() - start_time).total_seconds()
            issues.append(CleanupIssue(
                service_name=service.service_name,
                issue_type="timeout",
                description=f"Cleanup timed out after {timeout} seconds",
                is_critical=True,
                timestamp=datetime.now()
            ))

            self._logger.warning("Service cleanup timed out",
                               service=service.service_name,
                               timeout=timeout,
                               duration=duration)

            # Attempt forced cleanup
            try:
                await self._force_cleanup_service(service)
                issues.append(CleanupIssue(
                    service_name=service.service_name,
                    issue_type="forced_cleanup",
                    description="Forced cleanup attempted after timeout",
                    is_critical=False,
                    timestamp=datetime.now()
                ))
                result = CleanupResult.PARTIAL_SUCCESS
            except Exception as e:
                issues.append(CleanupIssue(
                    service_name=service.service_name,
                    issue_type="forced_cleanup_failed",
                    description=f"Forced cleanup failed: {str(e)}",
                    is_critical=True,
                    timestamp=datetime.now()
                ))
                result = CleanupResult.TIMEOUT

            return ServiceCleanupResult(
                service_name=service.service_name,
                result=result,
                duration_seconds=duration,
                issues=issues,
                timestamp=start_time
            )

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            issues.append(CleanupIssue(
                service_name=service.service_name,
                issue_type="exception",
                description=f"Cleanup exception: {str(e)}",
                is_critical=True,
                timestamp=datetime.now()
            ))

            self._logger.error("Service cleanup exception",
                             service=service.service_name,
                             error=str(e),
                             duration=duration)

            return ServiceCleanupResult(
                service_name=service.service_name,
                result=CleanupResult.FAILED,
                duration_seconds=duration,
                issues=issues,
                timestamp=start_time
            )

    async def _force_cleanup_service(self, service: ServiceLifecycle):
        """
        Attempt forced cleanup of a service that timed out.
        This is a best-effort operation with a very short timeout.
        """
        try:
            # Try reset first as it might be faster
            await asyncio.wait_for(service.reset(), timeout=1.0)
            self._logger.info("Forced service reset successful",
                            service=service.service_name)
        except Exception as e:
            self._logger.warning("Forced service reset failed",
                               service=service.service_name,
                               error=str(e))
            # Could add more aggressive cleanup methods here if needed

    async def cleanup_service(self, service: ServiceLifecycle,
                            timeout: Optional[float] = None) -> ServiceCleanupResult:
        """
        Clean up a single service.

        Args:
            service: The service to clean up
            timeout: Timeout for the cleanup operation

        Returns:
            ServiceCleanupResult with the outcome
        """
        if timeout is None:
            timeout = self.default_timeout

        result = await self._cleanup_service_with_timeout(service, timeout)
        self.cleanup_history.append(result)
        return result

    async def force_cleanup_all(self) -> None:
        """
        Force cleanup of all services without timeout considerations.
        This is a last-resort operation that attempts to reset all services.
        """
        self._logger.warning("Forcing cleanup of all services")

        for service in self.services:
            try:
                await asyncio.wait_for(service.reset(), timeout=2.0)
                self._logger.info("Forced reset successful", service=service.service_name)
            except Exception as e:
                self._logger.error("Forced reset failed",
                                 service=service.service_name,
                                 error=str(e))

    def validate_cleanup_completion(self) -> List[CleanupIssue]:
        """
        Validate that cleanup was completed successfully.

        Returns:
            List of issues found during validation
        """
        issues = []

        for service in self.services:
            try:
                state = service.get_state()
                if state not in [ServiceState.READY, ServiceState.UNINITIALIZED]:
                    issues.append(CleanupIssue(
                        service_name=service.service_name,
                        issue_type="invalid_state",
                        description=f"Service in unexpected state: {state.value}",
                        is_critical=True,
                        timestamp=datetime.now()
                    ))

                if not service.is_ready_for_connection():
                    issues.append(CleanupIssue(
                        service_name=service.service_name,
                        issue_type="not_ready",
                        description="Service reports not ready for connection",
                        is_critical=False,
                        timestamp=datetime.now()
                    ))

            except Exception as e:
                issues.append(CleanupIssue(
                    service_name=service.service_name,
                    issue_type="validation_error",
                    description=f"Error during validation: {str(e)}",
                    is_critical=True,
                    timestamp=datetime.now()
                ))

        if issues:
            self._logger.warning("Cleanup validation found issues",
                               issue_count=len(issues))
        else:
            self._logger.info("Cleanup validation passed")

        return issues

    async def verify_services_ready(self) -> bool:
        """
        Verify that all services are ready for new connections.

        Returns:
            True if all services are ready, False otherwise
        """
        for service in self.services:
            try:
                if not service.is_ready_for_connection():
                    self._logger.warning("Service not ready for connection",
                                       service=service.service_name)
                    return False
            except Exception as e:
                self._logger.error("Error checking service readiness",
                                 service=service.service_name,
                                 error=str(e))
                return False

        self._logger.info("All services ready for connection")
        return True

    def get_cleanup_history(self) -> List[ServiceCleanupResult]:
        """Get the history of cleanup operations."""
        return self.cleanup_history.copy()

    def clear_cleanup_history(self) -> None:
        """Clear the cleanup history."""
        self.cleanup_history.clear()

    def get_service_by_name(self, name: str) -> Optional[ServiceLifecycle]:
        """Get a service by name."""
        for service in self.services:
            if service.service_name == name:
                return service
        return None

    def add_service(self, service: ServiceLifecycle) -> None:
        """Add a service to be managed."""
        if service not in self.services:
            self.services.append(service)
            self._logger.info("Service added to cleanup manager",
                            service=service.service_name)

    def remove_service(self, service: ServiceLifecycle) -> bool:
        """Remove a service from management."""
        if service in self.services:
            self.services.remove(service)
            self._logger.info("Service removed from cleanup manager",
                            service=service.service_name)
            return True
        return False
