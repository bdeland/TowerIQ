"""
TowerIQ v1.0 - Main Application Entry Point

This module provides the single, definitive entry point for starting the TowerIQ GUI application.
It sets up the async environment, creates core application objects, and launches the UI.
"""

import sys
import asyncio
from pathlib import Path
from typing import NoReturn
import argparse
import os
import time

import qasync
import structlog
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont

from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.main_controller import MainController
from tower_iq.gui.main_window import MainWindow
from tower_iq.services.emulator_service import EmulatorService

os.environ["QT_API"] = "pyqt6"

def main() -> None:
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
    # Argument parsing for CLI flags
    parser = argparse.ArgumentParser(description="TowerIQ Application")
    parser.add_argument('--reset-frida', action='store_true', help='Update and start frida-server on the first connected device, then exit')
    parser.add_argument('--test-mode', action='store_true', help='Enable test mode with fake data and a temporary test database')
    parser.add_argument('--test-mode-replay', action='store_true', help='Replay existing test_mode.sqlite data as if it were a real run (no new data generated)')
    parser.add_argument('--test-mode-generate', action='store_true', help='Generate a new test_mode.sqlite and populate it with new fake data')
    args, unknown = parser.parse_known_args()

    # Initialize paths & environment
    app_root = Path(__file__).parent.parent.parent
    yaml_path = app_root / "config" / "main_config.yaml"
    env_path = app_root / ".env"
    
    try:
        # Create core components
        config = ConfigurationManager(str(yaml_path), str(env_path))
        config.load_and_validate()
        
        # Initialize unified logging system with console output initially
        setup_logging(config)
        logger = structlog.get_logger("main_entry")
        
        logger.info("Starting TowerIQ application", version="1.0")
        
        if args.reset_frida:
            # Minimal async routine to reset frida-server
            async def reset_frida():
                logger.info("--reset-frida flag detected, starting frida-server reset workflow")
                emulator_service = EmulatorService(config, logger)
                devices = await emulator_service._get_connected_devices()
                if not devices:
                    print("No connected devices found for frida reset.", file=sys.stderr)
                    sys.exit(2)
                device_id = devices[0]
                print(f"Resetting frida-server on device: {device_id}")
                try:
                    await emulator_service.ensure_frida_server_is_running(device_id)
                    print(f"Frida-server updated and started successfully on device: {device_id}")
                    sys.exit(0)
                except Exception as e:
                    print(f"Failed to reset frida-server: {e}", file=sys.stderr)
                    sys.exit(1)
            asyncio.run(reset_frida())
            return
        
        if args.test_mode_replay or args.test_mode_generate:
            setattr(config, '_test_mode', True)
            setattr(config, '_test_mode_replay', args.test_mode_replay)
            setattr(config, '_test_mode_generate', args.test_mode_generate)
            test_db_path = app_root / 'data' / f'test_mode.sqlite'
            if args.test_mode_generate:
                # Delete any existing test mode database before starting
                if test_db_path.exists():
                    try:
                        test_db_path.unlink()
                    except Exception as e:
                        logger.warning(f"Failed to delete old test mode database: {e}")
            config._override_db_path = str(test_db_path)
        
        # Initialize PyQt Application
        app = QApplication(sys.argv)
        app.setFont(QFont("Roboto", 11))
        app.setApplicationName("TowerIQ")
        app.setApplicationVersion("1.0")
        
        # Instantiate Main Controller
        controller = MainController(config, logger)
        # Instantiate Main Window with controller
        window = MainWindow()
        
        # Run the Application
        try:
            logger.info("Showing main window")
            window.show()
            logger.info("Main window shown successfully")
            
            # Start the event loop
            logger.info("Starting main event loop")
            sys.exit(app.exec())
        except Exception as e:
            logger.error("Exception in event loop", error=str(e))
            raise
    
    except Exception as e:
        # Handle any startup errors
        if 'logger' in locals():
            logger.error("Fatal error during application startup", error=str(e))
        else:
            print(f"Fatal error during application startup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 