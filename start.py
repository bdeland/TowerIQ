#!/usr/bin/env python3
"""
TowerIQ Startup Script

This script launches both the FastAPI backend server and the Tauri frontend.
It ensures the backend is running before starting the frontend.
"""

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import aiohttp
import structlog

# Import the same logging configuration as the main application
from tower_iq.core.async_utils import wait_for_condition
from tower_iq.core.config import ConfigurationManager
from tower_iq.core.logging_config import setup_logging
from tower_iq.core.process_monitor import (ProcessMonitor,
                                           wait_for_process_alive)

# Initialize configuration and logging the same way as the main app
app_root = Path(__file__).parent
config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))
setup_logging(config)

# Recreate the ConfigurationManager logger after logging is configured
config._recreate_logger()

logger = structlog.get_logger(__name__)

async def check_backend_health(url: str = "http://127.0.0.1:8000/", timeout: float = 30.0) -> bool:
    """
    Check if the backend server is healthy using proper polling with exponential backoff.
    
    Implements Pattern #3: Poll properly with exponential backoff + jitter.
    """
    async def health_check() -> bool:
        """Check if health endpoint returns 200."""
        try:
            check_timeout = aiohttp.ClientTimeout(total=2)
            async with aiohttp.ClientSession(timeout=check_timeout) as session:
                async with session.get(url) as response:
                    return response.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
    
    logger.info("Waiting for backend server to become healthy", url=url, timeout=timeout)
    
    # Use wait_for_condition with exponential backoff
    success = await wait_for_condition(
        health_check,
        timeout=timeout,
        initial_delay=0.5,
        max_delay=2.0,
        backoff_factor=1.5,
        condition_name="backend health"
    )
    
    if success:
        logger.info("Backend server is healthy", url=url)
    else:
        logger.error("Backend server failed to become healthy within timeout", timeout=timeout)
    
    return success

async def start_backend_server():
    """
    Start the FastAPI backend server.
    
    Implements Pattern #10: Use proper readiness contracts instead of sleep.
    """
    logger.info("Starting TowerIQ FastAPI backend server")
    
    # Get the path to the API server
    script_dir = Path(__file__).parent
    api_server_path = script_dir / "src" / "tower_iq" / "api_server.py"
    
    if not api_server_path.exists():
        logger.error("API server not found", path=str(api_server_path))
        return None
    
    try:
        # Start the FastAPI server with real-time output
        process = subprocess.Popen([
            sys.executable, str(api_server_path)
        ], stdout=None, stderr=None, text=True)  # Don't capture output - show it in real-time
        
        logger.info("Backend server started", pid=process.pid)
        
        # Check if process stays alive (replaces time.sleep(2) + poll())
        is_alive = await wait_for_process_alive(process, check_duration=2.0)
        if not is_alive:
            logger.error("Backend server process exited immediately", returncode=process.returncode)
            return None
        
        logger.info("Backend server process is running")
        return process
    except Exception as e:
        logger.error("Failed to start backend server", error=str(e))
        return None

async def start_tauri_frontend():
    """
    Start the Tauri frontend.
    
    Implements Pattern #10: Use proper readiness contracts.
    """
    logger.info("Starting TowerIQ Tauri frontend")
    
    # Get the path to the Tauri app
    script_dir = Path(__file__).parent
    tauri_dir = script_dir / "frontend"
    
    if not tauri_dir.exists():
        logger.error("Tauri app not found", path=str(tauri_dir))
        return None
    
    original_dir = os.getcwd()
    try:
        # Change to the Tauri directory and start the app
        os.chdir(tauri_dir)
        
        # Check if node_modules exists, if not install dependencies
        if not (tauri_dir / "node_modules").exists():
            logger.info("Installing Tauri dependencies")
            # Try to find npm using PATH resolution
            npm_cmd = shutil.which("npm") or shutil.which("npm.cmd")
            
            if not npm_cmd:
                logger.error("npm not found in PATH. Please install Node.js LTS and ensure npm is available.")
                os.chdir(original_dir)
                return None
            
            try:
                install_process = subprocess.run([npm_cmd, "install"], 
                                               capture_output=True, text=True, timeout=120)
            except FileNotFoundError:
                logger.error("Failed to execute npm. Verify Node.js installation and PATH configuration.")
                os.chdir(original_dir)
                return None
            if install_process.returncode != 0:
                logger.error("Failed to install dependencies", stderr=install_process.stderr)
                os.chdir(original_dir)
                return None
            logger.info("Dependencies installed successfully")
        
        # Try to find npx using PATH resolution
        npx_cmd = shutil.which("npx") or shutil.which("npx.cmd")
        
        if not npx_cmd:
            logger.error("npx not found in PATH. Please install Node.js LTS and ensure npx is available.")
            os.chdir(original_dir)
            return None
        
        # Start the Tauri app using npx to run the local CLI
        # Don't capture output so we can see what's happening
        try:
            process = subprocess.Popen([
                npx_cmd, "@tauri-apps/cli", "dev"
            ], stdout=None, stderr=None, text=True)
        except FileNotFoundError:
            logger.error("Failed to execute npx. Verify Node.js installation and PATH configuration.")
            os.chdir(original_dir)
            return None
        
        logger.info("Tauri frontend started", pid=process.pid)
        return process
    except Exception as e:
        logger.error("Failed to start Tauri frontend", error=str(e))
        # Restore original directory
        try:
            os.chdir(original_dir)
        except OSError:
            pass
        return None

async def main():
    """
    Main startup function.
    
    Implements Pattern #4: Use OS/runtime primitives for process monitoring.
    """
    logger.info("TowerIQ Startup Script", version="1.0.0")
    
    backend_process = None
    frontend_process = None
    backend_monitor = None
    frontend_monitor = None
    
    try:
        # Start Tauri frontend FIRST (with splash screen)
        frontend_process = await start_tauri_frontend()
        if not frontend_process:
            logger.error("Failed to start Tauri frontend. Exiting.")
            return 1
        
        # Create monitor for frontend process
        frontend_monitor = ProcessMonitor(frontend_process)
        
        # Start backend server in background
        backend_process = await start_backend_server()
        if not backend_process:
            logger.error("Failed to start backend server. Exiting.")
            return 1
        
        # Create monitor for backend process
        backend_monitor = ProcessMonitor(backend_process)
        
        # Wait for backend to be healthy
        backend_healthy = await check_backend_health(timeout=30.0)
        if not backend_healthy:
            logger.error("Backend server failed to become healthy. Exiting.")
            return 1
        
        logger.info("TowerIQ is now running", 
                   frontend_url="http://localhost:1420",
                   backend_url="http://localhost:8000",
                   api_docs="http://localhost:8000/docs")
        
        # Use proper wait primitives instead of polling loop
        # Wait for either process to exit
        while True:
            backend_exited = await backend_monitor.wait_for_exit(timeout=1.0)
            if backend_exited:
                logger.error("Backend server stopped unexpectedly", 
                           returncode=backend_monitor.returncode)
                break
            
            frontend_exited = await frontend_monitor.wait_for_exit(timeout=1.0)
            if frontend_exited:
                logger.error("Frontend stopped unexpectedly",
                           returncode=frontend_monitor.returncode)
                break
    
    except KeyboardInterrupt:
        logger.info("Shutting down TowerIQ")
    
    finally:
        # Cleanup processes with proper wait primitives
        if backend_monitor and backend_process:
            logger.info("Stopping backend server")
            # Attempt graceful shutdown via API so DB can cleanup WAL/SHM
            try:
                shutdown_timeout = aiohttp.ClientTimeout(total=2)
                async with aiohttp.ClientSession(timeout=shutdown_timeout) as session:
                    await session.post("http://127.0.0.1:8000/api/shutdown")
            except Exception:
                pass
            
            # Use proper wait primitive instead of manual timeout handling
            graceful = await backend_monitor.terminate_and_wait(timeout=5.0)
            if graceful:
                logger.info("Backend server shut down gracefully")
            else:
                logger.warning("Backend server had to be force-killed")
            
            backend_monitor.cleanup()
        
        if frontend_monitor and frontend_process:
            logger.info("Stopping frontend")
            graceful = await frontend_monitor.terminate_and_wait(timeout=5.0)
            if graceful:
                logger.info("Frontend shut down gracefully")
            else:
                logger.warning("Frontend had to be force-killed")
            
            frontend_monitor.cleanup()
        
        logger.info("TowerIQ shutdown complete")
    
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
