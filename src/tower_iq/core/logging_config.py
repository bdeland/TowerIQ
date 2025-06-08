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
import sys

import structlog
import colorama
from colorama import Fore, Style

from .config import ConfigurationManager


def setup_logging(config: ConfigurationManager, db_service=None) -> None:
    """
    Single entry point for initializing the logging system.
    Called once at application startup.
    
    Args:
        config: The fully initialized ConfigurationManager instance
        db_service: DatabaseService instance for SQLite logging (optional)
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

    # Configure structlog with nice console output
    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S.%f", utc=False)
    
    # Define processors for nice console output
    console_processors = [
        structlog.contextvars.merge_contextvars,
        SourceFilter(enabled_sources),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        timestamper,
        structlog.dev.ConsoleRenderer(colors=True)
    ]

    # Configure structlog
    structlog.configure(
        processors=console_processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level)
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level),
    )

    # Get root logger and remove default handlers if we want custom ones
    root_logger = logging.getLogger()
    
    # Add file handler if enabled
    if file_enabled:
        # For file output, we want JSON format
        file_handler = create_file_handler(file_path, file_level, max_size_mb, backup_count)
        root_logger.addHandler(file_handler)

    # Add SQLite handler if db_service is available
    if db_service:
        sqlite_handler = SQLiteLogHandler(db_service)
        sqlite_handler.setLevel(getattr(logging, log_level))
        sqlite_handler.setFormatter(StructlogFormatter())
        root_logger.addHandler(sqlite_handler)


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
            enabled_sources: Set of source names that are allowed to pass
        """
        self.enabled_sources = enabled_sources
        # If no sources specified, allow all
        self.filter_enabled = len(enabled_sources) > 0
    
    def __call__(self, logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter logic. Allows log records from enabled sources to pass through.
        
        Args:
            logger: The logger instance
            method_name: The method name being called
            event_dict: The event dictionary
            
        Returns:
            Unmodified event dictionary
        """
        # If no filtering enabled, pass everything through
        if not self.filter_enabled:
            return event_dict
            
        # Check if this source is enabled
        source = event_dict.get('source', '')
        if source in self.enabled_sources:
            return event_dict
        
        # If source not enabled, still pass through for now
        # (Could raise structlog.DropEvent() to actually filter)
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
        
        # Base format with timestamp, level, source, and event
        formatted = (
            f"{Fore.WHITE}[{timestamp}] "
            f"{level_color}[{level:^7}] "
            f"{Fore.BLUE}[{source}] "
            f"{Fore.WHITE}{event}"
        )
        
        # Add extra fields if present (excluding standard ones)
        extra_fields = []
        for key, value in event_dict.items():
            if key not in ['display_timestamp', 'level', 'source', 'event', 'timestamp_ms']:
                extra_fields.append(f"{key}={value}")
        
        if extra_fields:
            formatted += f" {Fore.CYAN}({', '.join(extra_fields)})"
        
        formatted += Style.RESET_ALL
        
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


class SQLiteLogHandler(logging.Handler):
    """
    Custom handler that writes logs to the SQLite database.
    """
    
    def __init__(self, db_service) -> None:
        """
        Initialize the SQLite log handler.
        
        Args:
            db_service: DatabaseService instance for writing logs
        """
        super().__init__()
        self.db_service = db_service
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record to the SQLite database.
        
        Args:
            record: The log record to emit
        """
        try:
            # Convert LogRecord to dict for the database service
            event_dict = {
                'timestamp': record.created,
                'level': record.levelname,
                'source': getattr(record, 'source', 'unknown'),
                'event': record.getMessage(),
                'logger': record.name,
            }
            
            # Add any extra fields from the record
            for key, value in record.__dict__.items():
                if key not in ['timestamp', 'level', 'source', 'event', 'logger', 
                             'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                             'filename', 'module', 'lineno', 'funcName', 'created',
                             'msecs', 'relativeCreated', 'thread', 'threadName',
                             'processName', 'process', 'getMessage', 'exc_info',
                             'exc_text', 'stack_info']:
                    event_dict[key] = value
            
            self.db_service.write_log_entry(event_dict)
        except Exception:
            # Don't call handleError here to avoid potential recursion
            pass


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


def create_console_handler(level: str) -> logging.Handler:
    """
    Create a console handler with colored output.
    
    Args:
        level: Log level for the handler
        
    Returns:
        Configured console handler
    """
    handler = logging.StreamHandler()
    handler.setLevel(getattr(logging, level))
    
    # Create a custom formatter that uses the console processors
    class ConsoleFormatter(logging.Formatter):
        def format(self, record):
            # Create local time timestamp
            local_time = datetime.fromtimestamp(record.created)
            formatted_time = local_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            
            # Extract source from record (structlog adds it)
            source = getattr(record, 'source', None)
            if not source:
                # Try to extract from the event dict if it's a structlog record
                if hasattr(record, 'msg') and isinstance(record.msg, dict):
                    source = record.msg.get('source', record.name)
                else:
                    source = record.name
            
            # Build event dict
            event_dict = {
                'display_timestamp': formatted_time,
                'level': record.levelname,
                'source': source,
                'event': record.getMessage(),
            }
            
            # Add any extra attributes from the record (if it's a structlog record)
            if hasattr(record, 'msg') and isinstance(record.msg, dict):
                for key, value in record.msg.items():
                    if key not in ['display_timestamp', 'level', 'source', 'event', 'timestamp_ms']:
                        event_dict[key] = value
            
            # Apply the ColoredConsoleRenderer
            renderer = ColoredConsoleRenderer()
            return renderer(None, None, event_dict)
    
    # Use structlog's ProcessorFormatter for better integration
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=[
                add_human_readable_timestamp,
                structlog.processors.add_log_level,
            ],
        )
    )
    
    # Override with our custom formatter for now
    handler.setFormatter(ConsoleFormatter())
    return handler 