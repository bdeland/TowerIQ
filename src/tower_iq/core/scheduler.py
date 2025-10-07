"""
Scheduler utilities for periodic tasks using APScheduler.

This module implements Pattern #6: Use schedulers and jobs instead of loops with sleep.
"""

import asyncio
from typing import Any, Callable, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger


class TaskScheduler:
    """
    Wrapper around APScheduler for managing periodic tasks.
    
    This replaces sleep-based periodic task loops with proper job scheduling.
    
    Example:
        >>> scheduler = TaskScheduler()
        >>> scheduler.start()
        >>> 
        >>> # Schedule a task to run every hour
        >>> scheduler.add_interval_job(
        ...     backup_database,
        ...     interval_seconds=3600,
        ...     job_id="backup",
        ...     initial_delay=300  # Wait 5 minutes before first run
        ... )
        >>> 
        >>> # Later, when shutting down
        >>> await scheduler.shutdown()
    """
    
    def __init__(self, logger: Any = None):
        """
        Initialize the scheduler.
        
        Args:
            logger: Optional logger for task execution
        """
        self.logger = logger
        self.scheduler = AsyncIOScheduler()
        self._running = False
    
    def start(self):
        """Start the scheduler."""
        if not self._running:
            self.scheduler.start()
            self._running = True
            if self.logger:
                self.logger.info("Task scheduler started")
    
    async def shutdown(self, wait: bool = True):
        """
        Shutdown the scheduler.
        
        Args:
            wait: If True, wait for running jobs to complete
        """
        if self._running:
            self.scheduler.shutdown(wait=wait)
            self._running = False
            if self.logger:
                self.logger.info("Task scheduler stopped")
    
    def add_interval_job(
        self,
        func: Callable,
        interval_seconds: float,
        job_id: str,
        initial_delay: float = 0,
        max_instances: int = 1,
        **kwargs
    ) -> str:
        """
        Add a job that runs at regular intervals.
        
        Args:
            func: Function or coroutine to execute
            interval_seconds: Interval between executions in seconds
            job_id: Unique identifier for the job
            initial_delay: Delay before first execution in seconds
            max_instances: Maximum concurrent instances of this job
            **kwargs: Additional arguments to pass to the function
            
        Returns:
            Job ID
            
        Example:
            >>> scheduler.add_interval_job(
            ...     backup_database,
            ...     interval_seconds=86400,  # Daily
            ...     job_id="daily_backup",
            ...     initial_delay=300  # Wait 5 minutes
            ... )
        """
        # Wrap the function to handle errors and logging
        async def wrapped_func():
            try:
                if self.logger:
                    self.logger.debug(f"Running scheduled job: {job_id}")
                
                # Check if function is a coroutine
                if asyncio.iscoroutinefunction(func):
                    await func(**kwargs)
                else:
                    func(**kwargs)
                
                if self.logger:
                    self.logger.debug(f"Scheduled job completed: {job_id}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Scheduled job failed: {job_id}", error=str(e))
        
        # Create trigger with initial delay
        trigger = IntervalTrigger(
            seconds=interval_seconds,
            start_date=None
        )
        
        # Add the job
        job = self.scheduler.add_job(
            wrapped_func,
            trigger=trigger,
            id=job_id,
            max_instances=max_instances,
            replace_existing=True
        )
        
        # If there's an initial delay, pause and reschedule first run
        if initial_delay > 0:
            job.pause()
            
            async def delayed_start():
                await asyncio.sleep(initial_delay)
                job.resume()
            
            asyncio.create_task(delayed_start())
        
        if self.logger:
            self.logger.info(
                f"Scheduled job added: {job_id} "
                f"(interval={interval_seconds}s, initial_delay={initial_delay}s)"
            )
        
        return job_id
    
    def add_cron_job(
        self,
        func: Callable,
        cron_expression: str,
        job_id: str,
        max_instances: int = 1,
        **kwargs
    ) -> str:
        """
        Add a job that runs on a cron schedule.
        
        Args:
            func: Function or coroutine to execute
            cron_expression: Cron expression (e.g., "0 0 * * *" for daily at midnight)
            job_id: Unique identifier for the job
            max_instances: Maximum concurrent instances of this job
            **kwargs: Additional arguments to pass to the function
            
        Returns:
            Job ID
        """
        from apscheduler.triggers.cron import CronTrigger
        
        async def wrapped_func():
            try:
                if self.logger:
                    self.logger.debug(f"Running scheduled job: {job_id}")
                
                if asyncio.iscoroutinefunction(func):
                    await func(**kwargs)
                else:
                    func(**kwargs)
                
                if self.logger:
                    self.logger.debug(f"Scheduled job completed: {job_id}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Scheduled job failed: {job_id}", error=str(e))
        
        trigger = CronTrigger.from_crontab(cron_expression)
        
        self.scheduler.add_job(
            wrapped_func,
            trigger=trigger,
            id=job_id,
            max_instances=max_instances,
            replace_existing=True
        )
        
        if self.logger:
            self.logger.info(f"Scheduled cron job added: {job_id} ({cron_expression})")
        
        return job_id
    
    def remove_job(self, job_id: str) -> bool:
        """
        Remove a scheduled job.
        
        Args:
            job_id: Job identifier
            
        Returns:
            True if job was removed, False if not found
        """
        try:
            self.scheduler.remove_job(job_id)
            if self.logger:
                self.logger.info(f"Removed scheduled job: {job_id}")
            return True
        except Exception:
            return False
    
    def pause_job(self, job_id: str) -> bool:
        """Pause a scheduled job."""
        try:
            self.scheduler.pause_job(job_id)
            return True
        except Exception:
            return False
    
    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        try:
            self.scheduler.resume_job(job_id)
            return True
        except Exception:
            return False
    
    def get_jobs(self) -> list:
        """Get list of all scheduled jobs."""
        return self.scheduler.get_jobs()

