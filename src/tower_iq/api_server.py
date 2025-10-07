"""
TowerIQ API Server - FastAPI backend for Tauri frontend

This module provides a FastAPI server that bridges the React/Tauri frontend
with the existing Python backend services.
"""

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tower_iq.api import dependencies
# Import all routers
from tower_iq.api.routers import (adb, connection, dashboards_v1,
                                  dashboards_v2, data_sources, database,
                                  devices, frida, grafana, health, queries,
                                  scripts)
from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.core.sqlmodel_engine import (get_sqlmodel_engine,
                                           get_sqlmodel_session,
                                           initialize_sqlmodel_engine)
from tower_iq.main_controller import MainController
from tower_iq.models.dashboard_models import QueryService
from tower_iq.services.database_service import DatabaseService


# Configure logging at module level to ensure it's set up before Uvicorn starts
def configure_logging():
    """Configure logging for the API server."""
    app_root = Path(__file__).parent.parent.parent
    config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))
    setup_logging(config)
    config._recreate_logger()

    # Configure all uvicorn loggers to use our system
    import logging
    uvicorn_loggers = [
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "uvicorn.asgi"
    ]
    for logger_name in uvicorn_loggers:
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers = []  # Remove default handlers
        uvicorn_logger.propagate = True  # Let it propagate to our root logger

    return config


# Configure logging immediately when module is imported
config = configure_logging()

# Global variables for the backend services
logger: Any = structlog.get_logger()
controller: Any = None
db_service: Any = None
query_service: Any = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the lifespan of the FastAPI application and backend services."""
    global config, logger, controller, db_service, query_service

    # Initialize paths & environment
    app_root = Path(__file__).parent.parent.parent
    os.chdir(app_root)

    # Initialize configuration
    config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))

    # Set up logging
    setup_logging(config)
    logger = structlog.get_logger()

    # Initialize database service
    db_service = DatabaseService(config, logger)
    db_service.connect()

    # Ensure dashboards table exists (legacy)
    db_service.ensure_dashboards_table_exists()

    # Ensure v2 dashboard system tables exist
    db_service.ensure_v2_tables_exist()

    # Initialize SQLModel engine for type-safe queries
    try:
        # Get database path from config
        database_path = str(Path(config.get('database_path', 'data/toweriq.sqlite')))

        # Initialize SQLModel engine (compatible with SQLCipher)
        initialize_sqlmodel_engine(database_path)

        # Create SQLModel tables
        sqlmodel_engine = get_sqlmodel_engine()
        sqlmodel_engine.create_tables()

        # Initialize query service
        with get_sqlmodel_session() as session:
            query_service = QueryService(session)

        logger.info("SQLModel engine and query service initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize SQLModel: {str(e)}")
        # Continue without SQLModel - fallback to existing system
        query_service = None

    # Link database service to config manager
    config.link_database_service(db_service)

    # Initialize data source manager for v2 dashboard system
    try:
        from tower_iq.services.data_source_executors import \
            initialize_default_data_source
        await initialize_default_data_source(database_path)
        logger.info("Data source manager initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize data source manager: {str(e)}")

    # Initialize main controller (do not start message loop until a script is injected)
    controller = MainController(config, logger, db_service=db_service)

    # Start the loading sequence
    controller.loading_manager.start_loading()
    controller.loading_manager.mark_step_complete('database')
    controller.loading_manager.mark_step_complete('emulator_service')
    controller.loading_manager.mark_step_complete('frida_service')
    controller.loading_manager.mark_step_complete('hook_scripts')

    # Simulate some startup time for services
    await asyncio.sleep(2)  # Simulate 2 seconds of startup time

    # Signal that the API server is ready
    controller.signal_loading_complete()

    # Periodic backup task
    async def _periodic_backup_task():
        try:
            while True:
                try:
                    if config and db_service and bool(config.get('database.backup.enabled', True)):
                        interval = int(config.get('database.backup.interval_seconds', 86400))
                        await asyncio.sleep(max(60, interval))
                        await asyncio.to_thread(db_service.backup_database)
                    else:
                        # Sleep a default period if disabled to avoid tight loop
                        await asyncio.sleep(600)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if logger:
                        logger.warning("Periodic backup failed", error=str(e))
                    await asyncio.sleep(600)
        except Exception:
            pass

    backup_task = asyncio.create_task(_periodic_backup_task())

    # Periodic metrics collection task
    async def _periodic_metrics_collection_task():
        """Periodic task to collect database metrics every 24 hours."""
        try:
            # Wait a bit before starting metrics collection (let services initialize)
            await asyncio.sleep(300)  # Wait 5 minutes after startup

            while True:
                try:
                    if db_service:
                        if logger:
                            logger.info("Starting scheduled database metrics collection")
                        success = await asyncio.to_thread(db_service.collect_and_store_db_metrics)
                        if success:
                            if logger:
                                logger.info("Scheduled database metrics collection completed successfully")
                        else:
                            if logger:
                                logger.warning("Scheduled database metrics collection failed")

                    # Sleep for 24 hours (86400 seconds)
                    await asyncio.sleep(86400)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if logger:
                        logger.warning("Periodic metrics collection failed", error=str(e))
                    # Wait 1 hour before retrying on error
                    await asyncio.sleep(3600)
        except Exception:
            pass

    metrics_task = asyncio.create_task(_periodic_metrics_collection_task())

    # Compute restore suggestion: if db file missing or empty and backups exist
    restore_suggestion = {
        "suggest": False,
        "reason": None,
        "latest_backup": None,
    }
    try:
        if config:
            db_path = Path(str(config.get('database.sqlite_path', 'data/toweriq.sqlite')))
            db_missing = not db_path.exists()
            db_empty = db_path.exists() and db_path.stat().st_size == 0
            if db_missing or db_empty:
                backup_dir = Path(str(config.get('database.backup.backup_dir', 'data/backups')))
                if backup_dir.exists():
                    backups = sorted(
                        list(backup_dir.glob("*.sqlite*")),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True
                    )
                    if backups:
                        restore_suggestion["suggest"] = True
                        restore_suggestion["reason"] = "database missing" if db_missing else "database empty"
                        restore_suggestion["latest_backup"] = str(backups[0])
        globals()['_restore_suggestion_cache'] = restore_suggestion
    except Exception as e:
        if logger:
            logger.warning("Failed to compute restore suggestion", error=str(e))

    # Initialize dependencies for routers
    dependencies.set_logger(logger)
    dependencies.set_controller(controller)
    dependencies.set_db_service(db_service)
    dependencies.set_query_service(query_service)

    # Initialize all routers with their dependencies
    health.initialize(logger, controller, config)
    adb.initialize(logger, controller)
    scripts.initialize(logger, controller)
    devices.initialize(logger, controller)
    connection.initialize(logger, controller)
    frida.initialize(logger, controller)
    queries.initialize(logger, db_service, query_service)
    database.initialize(logger, db_service, config)
    dashboards_v1.initialize(logger, db_service)
    dashboards_v2.initialize(logger, db_service)
    data_sources.initialize(logger, db_service)
    grafana.initialize(logger, db_service, config)

    # Register all routers with the app
    app.include_router(health.router)
    app.include_router(adb.router)
    app.include_router(scripts.router)
    app.include_router(devices.router)
    app.include_router(connection.router)
    app.include_router(frida.router)
    app.include_router(queries.router)
    app.include_router(database.router)
    app.include_router(dashboards_v1.router)
    app.include_router(dashboards_v2.router)
    app.include_router(data_sources.router)
    
    # Conditionally register Grafana router based on settings
    grafana_enabled = bool(config.get('grafana.enabled', False))
    if grafana_enabled:
        app.include_router(grafana.router)
        logger.info("Grafana integration router registered (enabled in settings)")
    else:
        logger.info("Grafana integration router not registered (disabled in settings)")

    logger.info("All API routers registered successfully")

    yield

    # Cleanup
    # Optionally run a shutdown backup
    try:
        if config and db_service and bool(config.get('database.backup.on_shutdown', True)):
            db_service.backup_database()
    except Exception as e:
        if logger:
            logger.warning("Shutdown backup failed", error=str(e))

    # Cancel periodic tasks
    try:
        backup_task.cancel()
    except Exception:
        pass

    try:
        metrics_task.cancel()
    except Exception:
        pass

    if controller:
        if logger:
            logger.info("Shutting down controller")
        controller.shutdown()
    # Ensure database connection is closed and journal files are cleaned
    if db_service:
        try:
            if logger:
                logger.info("Closing database service")
            db_service.close()
        except Exception as e:
            if logger:
                logger.warning("Error during database service close", error=str(e))
    if logger:
        logger.info("TowerIQ API Server shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="TowerIQ API",
    description="API server for TowerIQ Tauri frontend",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware for Tauri frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:1420", "http://127.0.0.1:1420",  # Tauri dev server
        "http://localhost:3000", "http://127.0.0.1:3000",  # React dev server
        "https://tauri.localhost",  # Tauri production build
        "tauri://localhost",  # Tauri custom protocol
        "*",  # Allow all origins for development (remove in production)
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# All API endpoints are now defined in backend/api/routers/
# and registered in the lifespan function above


def start_server(host: str = None, port: int = None):
    """
    Start the FastAPI server.
    
    Args:
        host: Bind address (defaults to config or 127.0.0.1)
        port: Port number (defaults to config or 8000)
    """
    # Read bind settings from configuration
    if host is None:
        host = str(config.get('grafana.bind_address', '127.0.0.1'))
    if port is None:
        port = int(config.get('grafana.port', 8000))
    
    logger.info(f"Starting FastAPI server", host=host, port=port)
    
    # Show warning if binding to 0.0.0.0
    if host == '0.0.0.0':
        logger.warning("Server is binding to 0.0.0.0 - accessible from all network interfaces. "
                      "Ensure your firewall is properly configured.")
    
    uvicorn.run(
        "tower_iq.api_server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    start_server()
if __name__ == "__main__":
    start_server()
