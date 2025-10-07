"""
TowerIQ v1.0 - Main Application Entry Point

This module provides the main entry point for starting the TowerIQ backend application.
The frontend is a React/Tauri application that communicates with this backend via API.
"""

import argparse
import asyncio
import os
import signal
import sys
from pathlib import Path

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.main_controller import MainController


def main() -> None:
    """
    Orchestrates the entire application startup sequence.
    
    This function:
    1. Initializes paths & environment
    2. Creates core components (config, logging)
    3. Starts the backend controller
    4. Runs indefinitely until interrupted
    """
    # Argument parsing for CLI flags
    parser = argparse.ArgumentParser(description="TowerIQ Application")
    parser.add_argument('--reset-frida', action='store_true', help='Update and start frida-server on the first connected device, then exit')
    parser.add_argument('--test-mode', action='store_true', help='Enable test mode with fake data and a temporary test database')
    parser.add_argument('--test-mode-replay', action='store_true', help='Replay existing test_mode.sqlite data as if it were a real run (no new data generated)')
    parser.add_argument('--test-mode-generate', action='store_true', help='Generate a new test_mode.sqlite and populate it with new fake data')
    args, unknown = parser.parse_known_args()

    # Initialize paths & environment
    app_root = Path(__file__).parent.parent.parent
    os.chdir(app_root)

    # Initialize configuration
    config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))

    # Set up logging
    setup_logging(config)
    
    # Recreate the ConfigurationManager logger after logging is configured
    config._recreate_logger()
    
    # Get logger after setup
    import structlog
    logger = structlog.get_logger()
    logger.info("Starting TowerIQ application", version="1.0")

    try:
        # Handle --reset-frida mode
        if args.reset_frida:
            logger.info("Running in reset-frida mode")
            logger.info("Reset-frida mode not yet implemented in current version")
            return
        
        # Handle test mode flags
        if args.test_mode_replay or args.test_mode_generate:
            test_mode = True
            test_mode_replay = args.test_mode_replay
            test_mode_generate = args.test_mode_generate
            test_db_path = app_root / 'data' / 'test_mode.sqlite'
            if args.test_mode_generate:
                # Delete any existing test mode database before starting
                if test_db_path.exists():
                    try:
                        test_db_path.unlink()
                    except Exception as e:
                        logger.warning(f"Failed to delete old test mode database: {e}")
        else:
            test_mode = False
            test_mode_replay = False
            test_mode_generate = False
            test_db_path = None
        
        # Initialize database service early and connect synchronously
        logger.info("Initializing database service")
        from tower_iq.services.database_service import DatabaseService
        if test_db_path is not None:
            db_service = DatabaseService(config, logger, db_path=str(test_db_path))
        else:
            db_service = DatabaseService(config, logger)
        
        # Connect to database synchronously before creating other components
        db_service.connect()
        logger.info("Database connected successfully")
        
        # Link database service to config manager so it can access user settings
        config.link_database_service(db_service)
        logger.info("Database service linked to configuration manager")
        
        # Instantiate Main Controller (database already connected)
        controller = MainController(config, logger, db_service=db_service)
        controller._test_mode = test_mode
        controller._test_mode_replay = test_mode_replay
        controller._test_mode_generate = test_mode_generate
        
        # Start the loading sequence
        controller.loading_manager.start_loading()
        controller.loading_manager.mark_step_complete('database')
        
        # Mark emulator service as ready
        controller.loading_manager.mark_step_complete('emulator_service')
        
        # Mark Frida service as ready
        controller.loading_manager.mark_step_complete('frida_service')
        
        # Mark hook scripts as ready
        controller.loading_manager.mark_step_complete('hook_scripts')
        
        logger.info("Starting backend controller")
        
        # Setup signal handlers for graceful shutdown
        shutdown_event = asyncio.Event()
        
        def signal_handler(sig, frame):
            logger.info("Shutdown signal received", signal=sig)
            shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Start controller in background thread
            controller.start_background_operations()
            
            logger.info("Backend is running. Press Ctrl+C to stop.")
            
            # Run indefinitely until interrupted
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(shutdown_event.wait())
            finally:
                loop.close()
            
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        except Exception as e:
            logger.error("Exception in main loop", error=str(e))
            raise
        finally:
            # Cleanup
            logger.info("Shutting down controller")
            controller.shutdown()
            try:
                if 'db_service' in locals() and db_service:
                    logger.info("Closing database service")
                    db_service.close()
            except Exception as e:
                logger.warning("Error during database service close", error=str(e))
    
    except Exception as e:
        # Handle any startup errors
        if 'logger' in locals():
            logger.error("Fatal error during application startup", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main() 