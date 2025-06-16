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
        controller_task = None
        try:
            logger.info("Showing main window")
            main_window.show()
            logger.info("Main window shown successfully")
            
            # Start the event loop and create controller task within it
            logger.info("Starting main event loop")
            try:
                with loop:
                    logger.info("Event loop started, creating controller task")
                    # Create the controller task now that the loop is running
                    controller_task = loop.create_task(controller.run())
                    logger.info("Controller task created successfully")
                    
                    # Connect Qt app aboutToQuit signal to stop the controller
                    try:
                        def on_app_quit():
                            logger.info("Application quit signal received")
                            try:
                                # Set shutdown flag immediately to prevent Qt timer creation
                                controller._is_shutting_down = True
                                
                                # Stop the event loop gracefully
                                if loop.is_running():
                                    logger.info("Stopping event loop")
                                    loop.stop()
                            except Exception as quit_error:
                                logger.error("Error stopping event loop", error=str(quit_error))
                        
                        qt_app.aboutToQuit.connect(on_app_quit)
                        logger.info("Qt app quit signal connected")
                    except Exception as e:
                        logger.error("Failed to connect quit signal", error=str(e))
                        raise
                    

                    
                    logger.info("Entering run_forever()")
                    loop.run_forever()
                    logger.info("Event loop exited run_forever()")
            except Exception as e:
                logger.error("Exception in event loop", error=str(e))
                raise
            
        finally:
            # Cleanup: gracefully shut down backend services
            logger.info("Shutting down application")
            try:
                # Stop the controller task first
                if controller_task and not controller_task.cancelled():
                    logger.info("Cancelling controller task")
                    controller_task.cancel()
                    
                # Run cleanup with aggressive timeout to prevent hanging
                logger.info("Running controller cleanup")
                try:
                    # Use the existing loop for cleanup if it's still running
                    if loop and not loop.is_closed():
                        try:
                            # Run cleanup with a very short timeout to prevent hanging
                            cleanup_task = loop.create_task(controller.stop())
                            loop.run_until_complete(asyncio.wait_for(cleanup_task, timeout=2.0))  # Increased from 0.5 to 2.0 seconds for Frida cleanup
                            logger.info("Controller cleanup completed")
                        except asyncio.TimeoutError:
                            logger.warning("Controller cleanup timed out after 2.0 seconds, forcing shutdown")
                            # Cancel the cleanup task if it's still running
                            if not cleanup_task.done():
                                cleanup_task.cancel()
                                try:
                                    loop.run_until_complete(asyncio.wait_for(cleanup_task, timeout=0.5))
                                except (asyncio.TimeoutError, asyncio.CancelledError):
                                    logger.warning("Cleanup task cancellation also timed out")
                        except Exception as cleanup_error:
                            logger.error("Error during controller cleanup", error=str(cleanup_error))
                    else:
                        logger.info("Event loop already closed, calling controller cleanup directly")
                        # If the loop is closed, try calling controller stop directly without asyncio
                        try:
                            # Since the loop is closed, manually clean up what we can
                            controller._is_shutting_down = True
                            controller._is_running = False
                            # Call database close directly
                            controller.db_service.close()
                            logger.info("Direct cleanup completed")
                        except Exception as direct_cleanup_error:
                            logger.error("Error during direct cleanup", error=str(direct_cleanup_error))
                    
                except Exception as cleanup_error:
                    logger.error("Error during controller cleanup", error=str(cleanup_error))
                
            except Exception as e:
                logger.error("Error during application cleanup", error=str(e))
            
            # Close the event loop more gracefully with aggressive task cancellation
            try:
                if loop and not loop.is_closed():
                    # Cancel any remaining tasks with shorter timeout
                    pending_tasks = [task for task in asyncio.all_tasks(loop) if not task.done()]
                    if pending_tasks:
                        logger.info(f"Cancelling {len(pending_tasks)} pending tasks")
                        for task in pending_tasks:
                            task.cancel()
                        
                        # Give tasks less time to cancel to prevent hanging - but more time for Frida cleanup
                        try:
                            loop.run_until_complete(asyncio.wait_for(
                                asyncio.gather(*pending_tasks, return_exceptions=True), 
                                timeout=1.0  # Increased from 0.2 to 1.0 seconds for Frida cleanup
                            ))
                        except asyncio.TimeoutError:
                            logger.warning("Task cancellation timed out after 1.0 seconds, forcing shutdown")
                            # Double-check if any tasks are still running and force kill them
                            still_pending = [task for task in pending_tasks if not task.done()]
                            if still_pending:
                                logger.warning(f"{len(still_pending)} tasks still running after timeout - these will be abandoned")
                        except Exception:
                            pass  # Ignore exceptions during task cancellation
                    
                    logger.info("Closing event loop")
                    # Don't explicitly close the loop here - let qasync handle it
                    
            except Exception as e:
                logger.error("Error during event loop cleanup", error=str(e))
            
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