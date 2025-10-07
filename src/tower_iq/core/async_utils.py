"""
Async utility functions for replacing sleep commands with proper patterns.

This module provides utilities for:
- Waiting for conditions with exponential backoff + jitter
- Process monitoring with proper wait primitives
- Event-driven async operations
"""

import asyncio
import random
from typing import Any, Awaitable, Callable, Optional


async def wait_for_condition(
    condition: Callable[[], Awaitable[bool]],
    timeout: float = 30.0,
    initial_delay: float = 0.1,
    max_delay: float = 5.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    condition_name: str = "condition"
) -> bool:
    """
    Wait for a condition to become true with exponential backoff + jitter.
    
    This implements Pattern #3: Poll properly with exponential backoff + jitter.
    
    Args:
        condition: Async callable that returns True when condition is met
        timeout: Maximum time to wait in seconds
        initial_delay: Initial delay between checks in seconds
        max_delay: Maximum delay between checks in seconds
        backoff_factor: Multiplier for exponential backoff
        jitter: Whether to add random jitter to delays
        condition_name: Name of condition for logging/errors
        
    Returns:
        True if condition met, False if timeout
        
    Example:
        >>> async def check_server_ready():
        ...     return await check_health_endpoint()
        >>> 
        >>> success = await wait_for_condition(
        ...     check_server_ready,
        ...     timeout=30.0,
        ...     condition_name="server ready"
        ... )
    """
    start_time = asyncio.get_event_loop().time()
    delay = initial_delay
    
    while True:
        # Check if condition is met
        try:
            if await condition():
                return True
        except Exception:
            # Continue checking even if condition check fails
            pass
        
        # Check if we've exceeded timeout
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed >= timeout:
            return False
        
        # Calculate next delay with exponential backoff
        actual_delay = delay
        if jitter:
            # Add +/- 25% jitter to avoid thundering herd
            jitter_amount = delay * 0.25
            actual_delay = delay + random.uniform(-jitter_amount, jitter_amount)
        
        # Don't wait longer than remaining time
        remaining = timeout - elapsed
        actual_delay = min(actual_delay, remaining)
        
        if actual_delay > 0:
            await asyncio.sleep(actual_delay)
        
        # Increase delay for next iteration (exponential backoff)
        delay = min(delay * backoff_factor, max_delay)


async def wait_for_condition_with_result(
    condition: Callable[[], Awaitable[tuple[bool, Any]]],
    timeout: float = 30.0,
    initial_delay: float = 0.1,
    max_delay: float = 5.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    condition_name: str = "condition"
) -> tuple[bool, Any]:
    """
    Wait for a condition and return both success status and result.
    
    Args:
        condition: Async callable that returns (success: bool, result: Any)
        timeout: Maximum time to wait in seconds
        initial_delay: Initial delay between checks in seconds
        max_delay: Maximum delay between checks in seconds
        backoff_factor: Multiplier for exponential backoff
        jitter: Whether to add random jitter to delays
        condition_name: Name of condition for logging/errors
        
    Returns:
        (success: bool, result: Any) - result from last condition check
        
    Example:
        >>> async def check_process_started():
        ...     pid = await get_process_pid()
        ...     return (pid is not None, pid)
        >>> 
        >>> success, pid = await wait_for_condition_with_result(
        ...     check_process_started,
        ...     timeout=10.0
        ... )
    """
    start_time = asyncio.get_event_loop().time()
    delay = initial_delay
    last_result = None
    
    while True:
        # Check if condition is met
        try:
            success, result = await condition()
            last_result = result
            if success:
                return (True, result)
        except Exception as e:
            last_result = e
            # Continue checking even if condition check fails
            pass
        
        # Check if we've exceeded timeout
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed >= timeout:
            return (False, last_result)
        
        # Calculate next delay with exponential backoff
        actual_delay = delay
        if jitter:
            jitter_amount = delay * 0.25
            actual_delay = delay + random.uniform(-jitter_amount, jitter_amount)
        
        remaining = timeout - elapsed
        actual_delay = min(actual_delay, remaining)
        
        if actual_delay > 0:
            await asyncio.sleep(actual_delay)
        
        delay = min(delay * backoff_factor, max_delay)


class AsyncEvent:
    """
    Simple async event for signaling between coroutines.
    
    This implements Pattern #1: Wait for a condition, not a duration.
    
    Example:
        >>> event = AsyncEvent()
        >>> 
        >>> # In one coroutine:
        >>> await event.wait(timeout=5.0)  # Wait up to 5 seconds
        >>> 
        >>> # In another coroutine:
        >>> event.set()  # Signal the event
    """
    
    def __init__(self):
        self._event = asyncio.Event()
    
    def set(self):
        """Set the event, waking up all waiters."""
        self._event.set()
    
    def clear(self):
        """Clear the event."""
        self._event.clear()
    
    def is_set(self) -> bool:
        """Check if event is set."""
        return self._event.is_set()
    
    async def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for the event to be set.
        
        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)
            
        Returns:
            True if event was set, False if timeout
        """
        if timeout is None:
            await self._event.wait()
            return True
        
        try:
            await asyncio.wait_for(self._event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

