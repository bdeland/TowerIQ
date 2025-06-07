"""
TowerIQ v1.0 - Main Application Entry Point

This module provides the single, definitive entry point for starting the TowerIQ GUI application.
It sets up the async environment, creates core application objects, and launches the UI.
"""

import sys
import asyncio
from pathlib import Path
from typing import NoReturn

import qasync
import structlog
from PyQt6.QtWidgets import QApplication

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.main_controller import MainController
from tower_iq.gui.main_window import MainWindow


def main() -> NoReturn:
    """
    Orchestrates the entire application startup sequence.
    
    This function:
    1. Initializes paths & environment
    2. Creates core components (config, logging)
    3. Initializes PyQt Application
    4. Sets up async bridge with qasync
    5. Instantiates controller and main window
    6. Runs the application with proper cleanup
    """
    # Initialize paths & environment
    app_root = Path(__file__).parent.parent.parent
    yaml_path = app_root / "config" / "main_config.yaml"
    env_path = app_root / ".env"
    
    try:
        # Create core components
        config = ConfigurationManager(str(yaml_path), str(env_path))
        config.load_and_validate()
        
        # Initialize unified logging system immediately
        setup_logging(config)
        logger = structlog.get_logger("main_entry")
        
        logger.info("Starting TowerIQ application", version="1.0")
        
        # Initialize PyQt Application
        qt_app = QApplication(sys.argv)
        qt_app.setApplicationName("TowerIQ")
        qt_app.setApplicationVersion("1.0")
        
        # Instantiate Controller
        controller = MainController(config, logger)
        
        # Set up Async Bridge (qasync) - Critical step for PyQt + asyncio
        loop = qasync.QEventLoop(qt_app)
        asyncio.set_event_loop(loop)
        
        # Instantiate Main Window
        main_window = MainWindow(controller)
        
        # Run the Application
        try:
            logger.info("Showing main window")
            main_window.show()
            
            # Start the controller's main loop in the background
            logger.info("Starting controller background tasks")
            asyncio.create_task(controller.run())
            
            # Start the combined Qt/asyncio event loop
            logger.info("Starting main event loop")
            loop.run_forever()
            
        finally:
            # Cleanup: gracefully shut down backend services
            logger.info("Shutting down application")
            try:
                # Create a new event loop for cleanup since the main one is closing
                cleanup_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(cleanup_loop)
                cleanup_loop.run_until_complete(controller.stop())
                cleanup_loop.close()
            except Exception as e:
                logger.error("Error during cleanup", error=str(e))
            
            logger.info("TowerIQ application shutdown complete")
    
    except Exception as e:
        # Handle any startup errors
        if 'logger' in locals():
            logger.error("Fatal error during application startup", error=str(e))
        else:
            print(f"Fatal error during application startup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 