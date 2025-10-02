"""
Shared dependencies and utilities for API routers.
Provides dependency injection functions for FastAPI endpoints.
"""

from typing import Any, Optional
import structlog


# Global variables for the backend services
# These will be initialized in the main api_server.py
logger: Any = None
controller: Any = None
db_service: Any = None
query_service: Any = None


def get_logger():
    """Get the global logger instance."""
    global logger
    if logger is None:
        logger = structlog.get_logger()
    return logger


def get_controller():
    """Get the global MainController instance."""
    global controller
    if controller is None:
        raise RuntimeError("MainController not initialized")
    return controller


def get_db_service():
    """Get the global DatabaseService instance."""
    global db_service
    if db_service is None:
        raise RuntimeError("DatabaseService not initialized")
    return db_service


def get_query_service():
    """Get the global QueryService instance."""
    global query_service
    return query_service


def set_logger(log_instance: Any):
    """Set the global logger instance."""
    global logger
    logger = log_instance


def set_controller(controller_instance: Any):
    """Set the global MainController instance."""
    global controller
    controller = controller_instance


def set_db_service(service_instance: Any):
    """Set the global DatabaseService instance."""
    global db_service
    db_service = service_instance


def set_query_service(service_instance: Any):
    """Set the global QueryService instance."""
    global query_service
    query_service = service_instance

