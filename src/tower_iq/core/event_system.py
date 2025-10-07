"""
TowerIQ Event System - Replacement for Qt Signals

This module provides a simple event/callback system to replace PyQt signals.
"""

import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass
class Signal:
    """A simple signal implementation that can emit values to connected callbacks."""
    
    def __init__(self):
        self._callbacks: List[Callable] = []
        self._lock = threading.Lock()
    
    def connect(self, callback: Callable) -> None:
        """Connect a callback to this signal."""
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)
    
    def disconnect(self, callback: Callable) -> None:
        """Disconnect a callback from this signal."""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
    
    def emit(self, *args, **kwargs) -> None:
        """Emit the signal, calling all connected callbacks."""
        with self._lock:
            callbacks = self._callbacks.copy()
        
        for callback in callbacks:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                # Log but don't crash on callback errors
                import structlog
                logger = structlog.get_logger()
                logger.error("Error in signal callback", error=str(e), callback=callback.__name__)
    
    def disconnect_all(self) -> None:
        """Disconnect all callbacks from this signal."""
        with self._lock:
            self._callbacks.clear()

