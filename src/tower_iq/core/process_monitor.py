"""
Process monitoring utilities that use proper wait primitives instead of polling loops.

This module implements Pattern #4: Use OS/runtime primitives and Pattern #10: 
Use proper readiness contracts instead of sleep-based polling.
"""

import asyncio
import subprocess
from typing import Optional


class ProcessMonitor:
    """
    Monitor subprocess lifecycle with proper wait primitives instead of sleep loops.
    
    Example:
        >>> monitor = ProcessMonitor(process)
        >>> # Wait for process to exit with timeout
        >>> exited = await monitor.wait_for_exit(timeout=5.0)
        >>> if exited:
        ...     print(f"Process exited with code: {monitor.returncode}")
    """
    
    def __init__(self, process: subprocess.Popen):
        """
        Initialize process monitor.
        
        Args:
            process: subprocess.Popen instance to monitor
        """
        self.process = process
        self._exit_event = asyncio.Event()
        self._monitor_task: Optional[asyncio.Task] = None
        self._start_monitoring()
    
    def _start_monitoring(self):
        """Start background task to monitor process."""
        self._monitor_task = asyncio.create_task(self._monitor_process())
    
    async def _monitor_process(self):
        """Background task that waits for process to exit."""
        loop = asyncio.get_event_loop()
        
        # Use run_in_executor to wait for process without blocking
        await loop.run_in_executor(None, self.process.wait)
        
        # Signal that process has exited
        self._exit_event.set()
    
    async def wait_for_exit(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for process to exit.
        
        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)
            
        Returns:
            True if process exited, False if timeout
        """
        if self.process.poll() is not None:
            # Already exited
            return True
        
        if timeout is None:
            await self._exit_event.wait()
            return True
        
        try:
            await asyncio.wait_for(self._exit_event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False
    
    @property
    def returncode(self) -> Optional[int]:
        """Get process return code (None if still running)."""
        return self.process.returncode
    
    @property
    def pid(self) -> int:
        """Get process ID."""
        return self.process.pid
    
    def is_running(self) -> bool:
        """Check if process is still running."""
        return self.process.poll() is None
    
    def terminate(self):
        """Terminate the process."""
        self.process.terminate()
    
    def kill(self):
        """Kill the process."""
        self.process.kill()
    
    async def terminate_and_wait(self, timeout: float = 5.0) -> bool:
        """
        Terminate process and wait for it to exit.
        
        Args:
            timeout: Maximum time to wait for graceful shutdown
            
        Returns:
            True if process exited gracefully, False if had to kill
        """
        if not self.is_running():
            return True
        
        # Send terminate signal
        self.terminate()
        
        # Wait for graceful exit
        exited = await self.wait_for_exit(timeout=timeout)
        
        if not exited:
            # Force kill if didn't exit gracefully
            self.kill()
            await self.wait_for_exit(timeout=2.0)
            return False
        
        return True
    
    def cleanup(self):
        """Cancel monitoring task."""
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()


async def wait_for_process_alive(
    process: subprocess.Popen,
    check_duration: float = 2.0
) -> bool:
    """
    Check if a process stays alive for a minimum duration.
    
    This replaces the pattern of `time.sleep(2); process.poll() is None`.
    
    Args:
        process: subprocess.Popen instance
        check_duration: How long process should stay alive
        
    Returns:
        True if process is still alive after check_duration
    """
    monitor = ProcessMonitor(process)
    
    try:
        # Wait for either process exit or timeout
        exited = await monitor.wait_for_exit(timeout=check_duration)
        
        if exited:
            # Process exited during check period
            return False
        
        # Process still running after check period
        return True
    finally:
        monitor.cleanup()

