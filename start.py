#!/usr/bin/env python3
"""
TowerIQ Startup Script

This script launches both the FastAPI backend server and the Tauri frontend.
It ensures the backend is running before starting the frontend.
"""

import subprocess
import sys
import time
import os
import shutil
from pathlib import Path
import requests
import structlog

# Import the same logging configuration as the main application
sys.path.insert(0, str(Path(__file__).parent / "backend"))
from backend.core.config import ConfigurationManager
from backend.core.logging_config import setup_logging

# Initialize configuration and logging the same way as the main app
app_root = Path(__file__).parent
config = ConfigurationManager(str(app_root / 'config' / 'main_config.yaml'))
setup_logging(config)

# Recreate the ConfigurationManager logger after logging is configured
config._recreate_logger()

logger = structlog.get_logger(__name__)

def check_backend_health(url: str = "http://127.0.0.1:8000/", max_retries: int = 30) -> bool:
    """Check if the backend server is healthy."""
    for i in range(max_retries):
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                logger.info("Backend server is healthy", url=url)
                return True
        except requests.exceptions.RequestException as e:
            logger.warning("Request failed", error=str(e))
        
        logger.info("Waiting for backend server", attempt=i + 1, max_attempts=max_retries)
        time.sleep(1)
    
    logger.error("Backend server failed to start")
    return False

def start_backend_server():
    """Start the FastAPI backend server."""
    logger.info("Starting TowerIQ FastAPI backend server")
    
    # Get the path to the API server
    script_dir = Path(__file__).parent
    api_server_path = script_dir / "backend" / "api_server.py"
    
    if not api_server_path.exists():
        logger.error("API server not found", path=str(api_server_path))
        return None
    
    try:
        # Start the FastAPI server with real-time output
        process = subprocess.Popen([
            sys.executable, str(api_server_path)
        ], stdout=None, stderr=None, text=True)  # Don't capture output - show it in real-time
        
        logger.info("Backend server started", pid=process.pid)
        
        # Check if process is still running after a moment
        time.sleep(2)
        if process.poll() is not None:
            logger.error("Backend server process exited immediately")
            return None
        
        return process
    except Exception as e:
        logger.error("Failed to start backend server", error=str(e))
        return None

def start_tauri_frontend():
    """Start the Tauri frontend."""
    logger.info("Starting TowerIQ Tauri frontend")
    
    # Get the path to the Tauri app
    script_dir = Path(__file__).parent
    tauri_dir = script_dir / "frontend"
    
    if not tauri_dir.exists():
        logger.error("Tauri app not found", path=str(tauri_dir))
        return None
    
    try:
        # Change to the Tauri directory and start the app
        original_dir = os.getcwd()
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

def main():
    """Main startup function."""
    logger.info("TowerIQ Startup Script", version="1.0.0")
    
    backend_process = None
    frontend_process = None
    
    try:
        # Start Tauri frontend FIRST (with splash screen)
        frontend_process = start_tauri_frontend()
        if not frontend_process:
            logger.error("Failed to start Tauri frontend. Exiting.")
            return 1
        
        # Give frontend a moment to start up
        time.sleep(2)
        
        # Start backend server in background
        backend_process = start_backend_server()
        if not backend_process:
            logger.error("Failed to start backend server. Exiting.")
            return 1
        
        logger.info("TowerIQ is now running", 
                   frontend_url="http://localhost:1420",
                   backend_url="http://localhost:8000",
                   api_docs="http://localhost:8000/docs")
        
        # Wait for processes to complete
        while True:
            if backend_process.poll() is not None:
                logger.error("Backend server stopped unexpectedly")
                break
            if frontend_process.poll() is not None:
                logger.error("Frontend stopped unexpectedly")
                break
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Shutting down TowerIQ")
    
    finally:
        # Cleanup processes
        if backend_process:
            logger.info("Stopping backend server")
            # Attempt graceful shutdown via API so DB can cleanup WAL/SHM
            try:
                requests.post("http://127.0.0.1:8000/api/shutdown", timeout=2)
            except Exception:
                pass
            # Then terminate the process
            backend_process.terminate()
            try:
                backend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend_process.kill()
        
        if frontend_process:
            logger.info("Stopping frontend")
            frontend_process.terminate()
            try:
                frontend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                frontend_process.kill()
        
        logger.info("TowerIQ shutdown complete")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
