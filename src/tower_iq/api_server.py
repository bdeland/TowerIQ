"""
TowerIQ API Server - FastAPI backend for Tauri frontend

This module provides a FastAPI server that bridges the React/Tauri frontend
with the existing Python backend services.
"""

from __future__ import annotations

import argparse
import asyncio
import os
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
from tower_iq.core.scheduler import TaskScheduler
from tower_iq.core.sqlmodel_engine import (get_sqlmodel_engine,
                                           get_sqlmodel_session,
                                           initialize_sqlmodel_engine)
from tower_iq.main_controller import MainController
from tower_iq.models.dashboard_models import QueryService
from tower_iq.services.database_service import DatabaseService

# Global variables for the backend services (initialized in lifespan)
config: Any = None
logger: Any = None
controller: Any = None
db_service: Any = None
query_service: Any = None
task_scheduler: Any = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the lifespan of the FastAPI application and backend services."""
    global config, logger, controller, db_service, query_service, task_scheduler

    # Initialize paths & environment
    app_root = Path(__file__).parent.parent.parent
    os.chdir(app_root)

    # Initialize configuration
    config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))

    # Set up logging
    setup_logging(config)
    logger = structlog.get_logger()
    
    # Configure uvicorn loggers to use our logging system
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

        # Initialize query service - Note: QueryService will create sessions as needed
        # Don't create a session here since the context manager would close it immediately
        query_service = None  # Will be set to None for now, queries will use get_sqlmodel_session()

        logger.info("SQLModel engine initialized successfully")

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

    # Restart ADB server on startup to ensure device detection works properly
    # This resolves issues where ADB doesn't detect devices if the server was already running
    try:
        logger.info("Restarting ADB server on application startup")
        await controller.emulator_service.restart_adb_server()
        logger.info("ADB server restarted successfully")
    except Exception as e:
        logger.warning("Failed to restart ADB server on startup", error=str(e))

    # Start the loading sequence
    try:
        logger.info("Starting loading sequence")
        controller.loading_manager.start_loading()
        controller.loading_manager.mark_step_complete('database')
        controller.loading_manager.mark_step_complete('emulator_service')
        controller.loading_manager.mark_step_complete('frida_service')
        controller.loading_manager.mark_step_complete('hook_scripts')
        logger.info("Loading sequence steps marked complete")
    except Exception as e:
        logger.error("Failed during loading sequence", error=str(e), exc_info=True)
        raise

    # Signal that the API server is ready (no artificial delays)
    try:
        logger.info("Signaling loading complete")
        controller.signal_loading_complete()
        logger.info("API server is ready")
    except Exception as e:
        logger.error("Failed to signal loading complete", error=str(e), exc_info=True)
        raise

    # Initialize task scheduler for periodic tasks
    try:
        logger.info("Initializing task scheduler")
        task_scheduler = TaskScheduler(logger)
        task_scheduler.start()
        logger.info("Task scheduler started")
    except Exception as e:
        logger.error("Failed to initialize task scheduler", error=str(e), exc_info=True)
        raise

    # Schedule periodic backup task if enabled
    try:
        logger.info("Checking if periodic backup should be scheduled")
        if config and db_service and bool(config.get('database.backup.enabled', True)):
            interval = int(config.get('database.backup.interval_seconds', 86400))
            # Ensure minimum interval of 60 seconds
            interval = max(60, interval)
            
            async def run_backup():
                """Scheduled backup task."""
                try:
                    logger.info("Starting scheduled database backup")
                    await asyncio.to_thread(db_service.backup_database)
                    logger.info("Scheduled database backup completed successfully")
                except Exception as e:
                    logger.warning("Scheduled backup failed", error=str(e))
            
            task_scheduler.add_interval_job(
                run_backup,
                interval_seconds=interval,
                job_id="periodic_backup",
                initial_delay=60  # Wait 1 minute after startup
            )
            logger.info(f"Scheduled periodic backup every {interval}s")
        else:
            logger.info("Periodic backup is disabled")
    except Exception as e:
        logger.error("Failed to schedule periodic backup", error=str(e), exc_info=True)
        raise

    # Schedule periodic metrics collection
    try:
        logger.info("Scheduling periodic metrics collection")
        if db_service:
            async def run_metrics_collection():
                """Scheduled metrics collection task."""
                try:
                    logger.info("Starting scheduled database metrics collection")
                    success = await asyncio.to_thread(db_service.collect_and_store_db_metrics)
                    if success:
                        logger.info("Scheduled database metrics collection completed successfully")
                    else:
                        logger.warning("Scheduled database metrics collection failed")
                except Exception as e:
                    logger.warning("Periodic metrics collection failed", error=str(e))
            
            task_scheduler.add_interval_job(
                run_metrics_collection,
                interval_seconds=86400,  # Daily
                job_id="periodic_metrics",
                initial_delay=300  # Wait 5 minutes after startup
            )
            logger.info("Scheduled periodic metrics collection every 24 hours")
    except Exception as e:
        logger.error("Failed to schedule periodic metrics collection", error=str(e), exc_info=True)
        raise

    # Compute restore suggestion: if db file missing or empty and backups exist
    try:
        logger.info("Computing restore suggestion")
        restore_suggestion = {
            "suggest": False,
            "reason": None,
            "latest_backup": None,
        }
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
        dependencies.set_restore_suggestion(restore_suggestion)
        logger.info("Restore suggestion computed")
    except Exception as e:
        logger.error("Failed to compute restore suggestion", error=str(e), exc_info=True)
        raise

    # Initialize dependencies for routers
    try:
        logger.info("Initializing router dependencies")
        dependencies.set_logger(logger)
        dependencies.set_controller(controller)
        dependencies.set_db_service(db_service)
        dependencies.set_query_service(query_service)
        logger.info("Router dependencies initialized")
    except Exception as e:
        logger.error("Failed to initialize router dependencies", error=str(e), exc_info=True)
        raise

    # Initialize all routers with their dependencies
    try:
        logger.info("Initializing API routers")
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
        logger.info("All routers initialized")
    except Exception as e:
        logger.error("Failed to initialize routers", error=str(e), exc_info=True)
        raise

    # Register all routers with the app
    try:
        logger.info("Registering API routers with FastAPI app")
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
        logger.info("=" * 80)
        logger.info("STARTUP COMPLETE - Application is ready to accept requests")
        logger.info("=" * 80)
    except Exception as e:
        logger.error("Failed to register routers", error=str(e), exc_info=True)
        raise

    yield

    # Cleanup
    # Shutdown task scheduler
    if task_scheduler:
        try:
            logger.info("Shutting down task scheduler")
            await task_scheduler.shutdown(wait=True)
        except Exception as e:
            logger.warning("Error shutting down task scheduler", error=str(e))

    # Optionally run a shutdown backup
    try:
        if config and db_service and bool(config.get('database.backup.on_shutdown', True)):
            logger.info("Running shutdown backup")
            db_service.backup_database()
    except Exception as e:
        if logger:
            logger.warning("Shutdown backup failed", error=str(e))

    if controller:
        if logger:
            logger.info("Shutting down controller")
        controller.shutdown()
    
    # Close SQLModel engine first to release its connection pool
    try:
        from .core.sqlmodel_engine import close_sqlmodel_engine
        logger.info("Closing SQLModel engine")
        close_sqlmodel_engine()
    except Exception as e:
        if logger:
            logger.warning("Error closing SQLModel engine", error=str(e))
    
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
# Only enumerate trusted origins to avoid security misconfiguration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:1420", "http://127.0.0.1:1420",  # Tauri dev server
        "http://localhost:3000", "http://127.0.0.1:3000",  # React dev server
        "https://tauri.localhost",  # Tauri production build
        "tauri://localhost",  # Tauri custom protocol
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# All API endpoints are now defined in backend/api/routers/
# and registered in the lifespan function above


def start_server(host: str | None = None, port: int | None = None):
    """
    Start the FastAPI server.
    
    Args:
        host: Bind address (defaults to config or 127.0.0.1)
        port: Port number (defaults to config or 8000)
    """
    # Initialize config if not already set (needed when called from __main__)
    global config
    if config is None:
        app_root = Path(__file__).parent.parent.parent
        config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))
    
    # Allow environment variables to override configuration defaults
    env_host = os.environ.get("TOWERIQ_BACKEND_HOST")
    env_port = os.environ.get("TOWERIQ_BACKEND_PORT")

    if host is None and env_host:
        host = env_host

    if port is None and env_port:
        try:
            port = int(env_port)
        except ValueError:
            print("Invalid TOWERIQ_BACKEND_PORT environment variable; falling back to configuration value")

    # Read bind settings from configuration
    if host is None:
        host = str(config.get('grafana.bind_address', '127.0.0.1'))
    if port is None:
        port = int(config.get('grafana.port', 8000))
    
    # Use print instead of logger since logging may not be initialized yet
    print(f"Starting FastAPI server on {host}:{port}")
    
    # Show warning if binding to 0.0.0.0
    if host == '0.0.0.0':
        print("WARNING: Server is binding to 0.0.0.0 - accessible from all network interfaces. "
              "Ensure your firewall is properly configured.")
    
    uvicorn.run(
        "tower_iq.api_server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the TowerIQ FastAPI server")
    parser.add_argument("--host", dest="host", default=None, help="Bind address for the API server")
    parser.add_argument("--port", dest="port", type=int, default=None, help="Port for the API server")

    args = parser.parse_args()
    start_server(host=args.host, port=args.port)
