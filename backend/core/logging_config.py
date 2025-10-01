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

# Add this after the imports section
# Category mapping for simplified logging configuration
LOG_SOURCE_CATEGORIES = {
    # Application category - high-level app operations
    'application': {
        'main_entry',
        'MainController',
        'ConfigurationManager',
    },
    # Database category - all database operations
    'database': {
        'DatabaseService',
    },
    # Device category - device/emulator communication
    'device': {
        'EmulatorService',
        'AdbWrapper',
    },
    # Frida category - hook injection and management
    'frida': {
        'FridaService',
    },
    # GUI category - user interface operations
    'gui': {
        'GUI',
    },
    # System category - low-level system operations
    'system': {
        'ResourceCleanupManager',
        'qasync._windows._EventPoller',
        'qasync._windows._EventWorker',
        'qasync._QEventLoop',
        'asyncio',
    }
}

def get_source_category(source_name: str) -> str:
    """
    Get the category for a given source name.
    
    Args:
        source_name: The individual source name (e.g., 'EmulatorService')
        
    Returns:
        The category name (e.g., 'device') or 'unknown' if not found
    """
    for category, sources in LOG_SOURCE_CATEGORIES.items():
        if source_name in sources:
            return category
    return 'unknown'

def get_enabled_sources_from_categories(categories_config: dict) -> set:
    """
    Convert category-based configuration to individual source set.
    
    Args:
        categories_config: Dict with category names as keys and boolean values
        
    Returns:
        Set of enabled individual source names
    """
    enabled_sources = set()
    
    for category, enabled in categories_config.items():
        if enabled and category in LOG_SOURCE_CATEGORIES:
            enabled_sources.update(LOG_SOURCE_CATEGORIES[category])
    
    return enabled_sources

def get_all_available_categories() -> dict:
    """
    Get all available categories with their descriptions.
    
    Returns:
        Dict mapping category names to descriptions
    """
    return {
        'application': 'Application startup and main controller operations',
        'database': 'Database operations and data management',
        'device': 'Device/emulator communication and ADB operations',
        'frida': 'Frida hook injection and script management',
        'gui': 'User interface operations and events',
        'system': 'Low-level system operations (qasync, asyncio, cleanup)',
    }


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
    
    # Capture warnings and redirect them to logging
    logging.captureWarnings(True)
    
    # Extract logging settings from config
    console_enabled = config.get('logging.console.enabled', True)
    console_level = config.get('logging.console.level', 'INFO').upper()
    file_enabled = config.get('logging.file.enabled', True)
    file_path = config.get('logging.file.path', 'logs/tower_iq.log')
    file_level = config.get('logging.file.level', 'DEBUG').upper()
    max_size_mb = config.get('logging.file.max_size_mb', 50)
    backup_count = config.get('logging.file.backup_count', 5)
    
    # Support both old sources list and new categories configuration
    categories_config = config.get('logging.categories', {})
    if categories_config:
        # Use new category-based configuration
        enabled_sources = get_enabled_sources_from_categories(categories_config)
    else:
        # Fallback to old sources list for backward compatibility
        enabled_sources = set(config.get('logging.sources', []))
    
    # Read asyncio logging configuration
    asyncio_debug_enabled = config.get('logging.asyncio.debug_enabled', False)

    # Determine the lowest level needed for any handler
    levels = [console_level, file_level]
    min_level = min(levels, key=lambda lvl: getattr(logging, lvl, 0))

    # Configure structlog as the central logging hub
    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S.%f", utc=False)

    # Define shared processors for all logs
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,  # Add logger name first
        add_logger_name_as_source,  # Then use it to set source
        structlog.stdlib.add_log_level,
        add_epoch_millis_timestamp,
        add_human_readable_timestamp,  # Add display timestamp for console
        timestamper,
    ]

    structlog.configure(
        processors=shared_processors + [
            # Prepare event dict for logging to standard library
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Define the formatter for our handlers
    formatter = structlog.stdlib.ProcessorFormatter(
        # These run ONLY on records originating from the standard library
        foreign_pre_chain=shared_processors,
        # These run on ALL records
        processor=ColoredConsoleRenderer(),
    )

    # Get the root logger and remove any default handlers
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # Set the root logger's level
    root_logger.setLevel(getattr(logging, min_level))

    # Add our custom console handler if enabled
    if console_enabled:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, console_level))
        console_handler.setFormatter(formatter)
        # Add source filter to console handler (for compatibility)
        source_filter = SourceLogFilter(enabled_sources)
        console_handler.addFilter(source_filter)
        root_logger.addHandler(console_handler)

    # Configure the asyncio logger
    asyncio_logger = logging.getLogger("asyncio")
    if asyncio_debug_enabled:
        asyncio_logger.setLevel(logging.DEBUG)
    else:
        asyncio_logger.setLevel(logging.WARNING)
    # By default, the asyncio logger will propagate its records to the root logger.

    # Add file handler if enabled
    if file_enabled:
        # For file output, we want JSON format
        file_handler = create_file_handler(file_path, file_level, max_size_mb, backup_count)
        root_logger.addHandler(file_handler)

    # Add SQLite handler if db_service is available
    if db_service:
        sqlite_handler = SQLiteLogHandler(db_service)
        sqlite_handler.setLevel(getattr(logging, min_level))
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


def add_logger_name_as_source(logger, method_name, event_dict):
    # Always ensure we have a source
    if 'source' not in event_dict:
        # Use the logger name as the source for stdlib loggers
        original_source = event_dict.get('logger', None) or getattr(logger, 'name', 'unknown')
        event_dict['source'] = original_source
    
    # Always set the category for the source (whether it was already set or not)
    if 'category' not in event_dict:
        event_dict['category'] = get_source_category(event_dict['source'])
    
    return event_dict





class SourceLogFilter(logging.Filter):
    """Filter that only allows log records from enabled sources."""
    
    def __init__(self, enabled_sources: Set[str]):
        super().__init__()
        self.enabled_sources = enabled_sources
        self.filter_enabled = len(enabled_sources) > 0
    
    def filter(self, record: logging.LogRecord) -> bool:
        if not self.filter_enabled:
            return True  # Allow all if no sources specified (no filtering)
        
        # Get source from record
        source = getattr(record, 'source', None)
        if not source:
            # Try to extract from logger name for stdlib loggers
            source = record.name
        
        # For structlog records, the source might be in the event dict
        if not source or source == record.name:
            # Try to get source from the event dict if this is a structlog record
            if hasattr(record, 'msg') and isinstance(record.msg, dict):
                source = record.msg.get('source', record.name)
        
        # Check if the source is in the enabled sources
        if source in self.enabled_sources:
            return True
        
        # Also check if the source's category is enabled (for backward compatibility)
        category = get_source_category(source)
        if category in self.enabled_sources:
            return True
        
        return False


class ColoredConsoleRenderer:
    """
    Custom renderer for colored console output with smart formatting.
    """
    
    def __init__(self):
        """Initialize the renderer with message tracking for deduplication."""
        self.last_messages = {}
        self.message_counts = {}
        self.heartbeat_count = 0
    
    def __call__(self, logger: Any, method_name: str, event_dict: Any) -> str:
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
        category = event_dict.get('category', 'UNKNOWN')
        original_source = event_dict.get('source', 'UNKNOWN')
        event = event_dict.get('event', '')
        
        # Handle heartbeat messages specially
        if 'frida_heartbeat' in event or 'Frida script is alive' in event:
            self.heartbeat_count += 1
            if self.heartbeat_count % 4 == 0:  # Show every 4th heartbeat
                event = f"Frida heartbeat active ({self.heartbeat_count} beats)"
            else:
                return ""  # Skip this heartbeat
        
        # Smart truncation for very long messages
        max_event_length = 120
        if len(event) > max_event_length:
            # Try to find a good break point
            if '"' in event and event.count('"') >= 2:
                # For JSON-like messages, truncate at a reasonable point
                truncate_at = event.find('"', max_event_length // 2)
                if truncate_at > max_event_length // 3:
                    event = event[:truncate_at] + '"...'
                else:
                    event = event[:max_event_length] + "..."
            else:
                event = event[:max_event_length] + "..."
        
        # Color mapping for log levels
        level_colors = {
            'DEBUG': Fore.CYAN,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.MAGENTA + Style.BRIGHT
        }
        
        level_color = level_colors.get(level, Fore.WHITE)
        
        # Category-specific formatting
        category_colors = {
            'frida': Fore.MAGENTA,
            'device': Fore.YELLOW,
            'database': Fore.BLUE,
            'application': Fore.GREEN,
            'gui': Fore.CYAN,
            'system': Fore.WHITE
        }
        
        category_color = category_colors.get(category.lower(), Fore.BLUE)
        
        # Base format with timestamp, level, category, and event
        formatted = (
            f"{Fore.WHITE}[{timestamp}] "
            f"{level_color}[{level:^7}] "
            f"{category_color}[{category.title():^8}] "
            f"{Fore.WHITE}{event}"
        )
        
        # Add extra fields if present (excluding standard ones and redundant fields)
        extra_fields = []
        excluded_keys = {
            'display_timestamp', 'level', 'source', 'category', 'event', 'timestamp_ms',
            'logger', 'timestamp'  # Exclude these as they're already shown
        }
        
        # Always add source as context if it's different from category
        if original_source and original_source.lower() != category.lower():
            extra_fields.append(f"source={original_source}")
        
        # Smart handling of extra fields - limit and format nicely
        for key, value in event_dict.items():
            if key not in excluded_keys:
                # Truncate long values
                str_value = str(value)
                if len(str_value) > 50:
                    str_value = str_value[:47] + "..."
                extra_fields.append(f"{key}={str_value}")
        
        # Limit number of extra fields shown
        if len(extra_fields) > 3:
            shown_fields = extra_fields[:3]
            shown_fields.append(f"...+{len(extra_fields)-3} more")
            extra_fields = shown_fields
        
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
            source = getattr(record, 'source', 'unknown')
            event_dict = {
                'timestamp': record.created,
                'level': record.levelname,
                'source': source,
                'category': get_source_category(source),
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
        
        # Add extra fields if present - use getattr with default to avoid type errors
        source = getattr(record, 'source', None)
        if source is not None:
            event_dict['source'] = source
            # Add category for the source
            event_dict['category'] = get_source_category(source)
        
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
            
            # Get category for the source
            category = get_source_category(source)
            
            # Build event dict
            event_dict = {
                'display_timestamp': formatted_time,
                'level': record.levelname,
                'source': source,
                'category': category,
                'event': record.getMessage(),
            }
            
            # Add any extra attributes from the record (if it's a structlog record)
            if hasattr(record, 'msg') and isinstance(record.msg, dict):
                for key, value in record.msg.items():
                    if key not in ['display_timestamp', 'level', 'source', 'category', 'event', 'timestamp_ms']:
                        event_dict[key] = value
            
            # Apply the ColoredConsoleRenderer with proper arguments
            renderer = ColoredConsoleRenderer()
            return renderer(None, "format", event_dict)
    
    # Use structlog's ProcessorFormatter for better integration
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=[
                structlog.processors.add_log_level,
            ],
        )
    )
    
    # Override with our custom formatter for now
    handler.setFormatter(ConsoleFormatter())
    return handler 