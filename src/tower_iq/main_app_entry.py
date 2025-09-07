"""
TowerIQ v1.0 - Main Application Entry Point

This module provides the main entry point for starting the TowerIQ GUI application.
It uses Qt's native threading instead of qasync to avoid timer conflicts.
"""

import sys
import os
from pathlib import Path
from typing import NoReturn
import argparse

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont
from PyQt6.QtCore import QThread, QObject, pyqtSignal

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.main_controller import MainController
from tower_iq.gui.main_window import MainWindow
from tower_iq.services.emulator_service import EmulatorService

os.environ["QT_API"] = "pyqt6"


def main() -> None:
    """
    Orchestrates the entire application startup sequence using Qt-native threading.
    
    This function:
    1. Initializes paths & environment
    2. Creates core components (config, logging)
    3. Initializes PyQt Application (no qasync)
    4. Uses QThread for background operations
    5. Runs the application with Qt's native event loop
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
            # Note: This would need to be adapted to Qt threading
            # For now, just exit with a message
            logger.info("Reset-frida mode not yet implemented in current version")
            return
        
        # Handle test mode flags
        if args.test_mode_replay or args.test_mode_generate:
            test_mode = True
            test_mode_replay = args.test_mode_replay
            test_mode_generate = args.test_mode_generate
            test_db_path = app_root / 'data' / f'test_mode.sqlite'
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
        
        # Initialize PyQt Application
        app = QApplication(sys.argv)
        app.setFont(QFont("Roboto", 11))
        app.setApplicationName("TowerIQ")
        app.setApplicationVersion("1.0")

        # Database service is already connected and linked
        
        # Create main window
        window = MainWindow(session_manager=controller.session, config_manager=controller.config, controller=controller)

        try:
            logger.info("Showing main window")
            window.show()
            logger.info("Main window shown successfully")
            logger.info("Starting main event loop")
            
            # Start controller in background thread
            controller.start_background_operations()
            
            # Run Qt's native event loop
            sys.exit(app.exec())
            
        except Exception as e:
            logger.error("Exception in event loop", error=str(e))
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