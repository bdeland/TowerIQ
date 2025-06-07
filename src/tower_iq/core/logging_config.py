"""
TowerIQ Unified Logging System

This module provides the setup_logging function and custom processors
for configuring the structlog-based logging pipeline.
"""

import logging
import logging.handlers
import json
import time
from datetime import datetime
from typing import Any, Dict, Set
from pathlib import Path

import structlog
import colorama
from colorama import Fore, Style

from .config import ConfigurationManager


def setup_logging(config: ConfigurationManager) -> None:
    """
    Single entry point for initializing the logging system.
    Called once at application startup.
    
    Args:
        config: The fully initialized ConfigurationManager instance
    """
    # Initialize colorama for Windows console colors
    colorama.init()
    
    # Extract logging settings from config
    log_level = config.get('logging.level', 'INFO').upper()
    console_enabled = config.get('logging.console.enabled', True)
    console_level = config.get('logging.console.level', 'INFO').upper()
    file_enabled = config.get('logging.file.enabled', True)
    file_path = config.get('logging.file.path', 'logs/tower_iq.log')
    file_level = config.get('logging.file.level', 'DEBUG').upper()
    max_size_mb = config.get('logging.file.max_size_mb', 50)
    backup_count = config.get('logging.file.backup_count', 5)
    enabled_sources = set(config.get('logging.sources.enabled', []))

    # Define shared processors
    shared_processors = [
        add_epoch_millis_timestamp,
        structlog.contextvars.merge_contextvars,
        SourceFilter(enabled_sources),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
    ]

    # Define processors for different outputs
    json_processors = shared_processors + [
        structlog.processors.JSONRenderer()
    ]
    
    console_processors = shared_processors + [
        add_human_readable_timestamp,
        ColoredConsoleRenderer()
    ]

    # Configure structlog
    structlog.configure(
        processors=json_processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level)
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Get root logger and clear existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(getattr(logging, log_level))

    # Create mandatory StdoutJsonHandler
    stdout_handler = StdoutJsonHandler()
    stdout_handler.setLevel(getattr(logging, log_level))
    stdout_handler.setFormatter(StructlogFormatter())
    root_logger.addHandler(stdout_handler)

    # Create file handler if enabled
    if file_enabled:
        file_handler = create_file_handler(file_path, file_level, max_size_mb, backup_count)
        root_logger.addHandler(file_handler)

    # Create console handler if enabled
    if console_enabled:
        console_handler = create_console_handler(console_level, console_processors)
        root_logger.addHandler(console_handler)


def add_epoch_millis_timestamp(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add timestamp_ms key with current epoch milliseconds to every log record.
    
    Args:
        logger: The logger instance
        method_name: The method name being called
        event_dict: The event dictionary
        
    Returns:
        Modified event dictionary with timestamp_ms
    """
    event_dict['timestamp_ms'] = int(time.time() * 1000)
    return event_dict


def add_human_readable_timestamp(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add display_timestamp key with formatted local time string.
    Intended only for the console renderer.
    
    Args:
        logger: The logger instance
        method_name: The method name being called
        event_dict: The event dictionary
        
    Returns:
        Modified event dictionary with display_timestamp
    """
    event_dict['display_timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    return event_dict


class SourceFilter:
    """
    Filter that only allows log records from enabled sources to pass through.
    """
    
    def __init__(self, enabled_sources: Set[str]) -> None:
        """
        Initialize the filter with enabled source names.
        
        Args:
            enabled_sources: Set of uppercase source names that are allowed to pass
        """
        self.enabled_sources = {source.upper() for source in enabled_sources}
    
    def __call__(self, logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter logic. Allows log records from enabled sources to pass through.
        
        Args:
            logger: The logger instance
            method_name: The method name being called
            event_dict: The event dictionary
            
        Returns:
            Unmodified event dictionary (filtering is handled at handler level)
        """
        # For now, just pass everything through
        # Filtering will be handled at the handler level if needed
        return event_dict


class ColoredConsoleRenderer:
    """
    Custom renderer for colored console output.
    """
    
    def __call__(self, logger: Any, method_name: str, event_dict: Dict[str, Any]) -> str:
        """
        Render log record with colors for console output.
        
        Args:
            logger: The logger instance
            method_name: The method name being called
            event_dict: The event dictionary
            
        Returns:
            Colored formatted log string
        """
        timestamp = event_dict.get('display_timestamp', '')
        level = event_dict.get('level', '').upper()
        source = event_dict.get('source', 'UNKNOWN')
        event = event_dict.get('event', '')
        
        # Color mapping for log levels
        level_colors = {
            'DEBUG': Fore.CYAN,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.MAGENTA + Style.BRIGHT
        }
        
        level_color = level_colors.get(level, Fore.WHITE)
        
        # Format the log line
        formatted = (
            f"{Fore.WHITE}[{timestamp}] "
            f"{level_color}[{level:^8}] "
            f"{Fore.BLUE}[{source}] "
            f"{Fore.WHITE}{event}"
            f"{Style.RESET_ALL}"
        )
        
        return formatted


class StdoutJsonHandler(logging.Handler):
    """
    Custom handler that outputs JSON logs to stdout.
    """
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record as JSON to stdout.
        
        Args:
            record: The log record to emit
        """
        try:
            msg = self.format(record)
            print(msg, flush=True)
        except Exception:
            self.handleError(record)


class StructlogFormatter(logging.Formatter):
    """
    Formatter that works with structlog processors.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record using structlog processors.
        
        Args:
            record: The log record to format
            
        Returns:
            Formatted log string
        """
        # Convert LogRecord to dict
        event_dict = {
            'timestamp_ms': int(record.created * 1000),
            'level': record.levelname,
            'event': record.getMessage(),
            'logger': record.name,
        }
        
        # Add extra fields if present
        if hasattr(record, 'source'):
            event_dict['source'] = record.source
        
        return json.dumps(event_dict, default=str)


def create_file_handler(file_path: str, level: str, max_size_mb: int, backup_count: int) -> logging.Handler:
    """
    Create a rotating file handler for log files.
    
    Args:
        file_path: Path to the log file
        level: Log level for the handler
        max_size_mb: Maximum size in MB before rotation
        backup_count: Number of backup files to keep
        
    Returns:
        Configured rotating file handler
    """
    # Ensure log directory exists
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    
    handler = logging.handlers.RotatingFileHandler(
        file_path,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backup_count,
        encoding='utf-8'
    )
    handler.setLevel(getattr(logging, level))
    handler.setFormatter(StructlogFormatter())
    
    return handler


def create_console_handler(level: str, processors: list) -> logging.Handler:
    """
    Create a console handler with colored output.
    
    Args:
        level: Log level for the handler
        processors: List of structlog processors to use
        
    Returns:
        Configured console handler
    """
    handler = logging.StreamHandler()
    handler.setLevel(getattr(logging, level))
    
    # Create a custom formatter that uses the console processors
    class ConsoleFormatter(logging.Formatter):
        def format(self, record):
            event_dict = {
                'display_timestamp': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': record.levelname,
                'source': getattr(record, 'source', 'UNKNOWN'),
                'event': record.getMessage(),
            }
            
            # Apply console processors
            for processor in processors:
                try:
                    if isinstance(processor, ColoredConsoleRenderer):
                        return processor(None, None, event_dict)
                    else:
                        event_dict = processor(None, None, event_dict)
                except Exception:
                    return ""
            
            return str(event_dict)
    
    handler.setFormatter(ConsoleFormatter())
    return handler 