#!/usr/bin/env python3
"""
TowerIQ Backend Server Starter

This script starts the FastAPI backend server that the React GUI needs
to communicate with for device scanning and other operations.
"""

import sys
from pathlib import Path

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / 'backend'))

from backend.api_server import start_server

if __name__ == "__main__":
    print("Starting TowerIQ Backend Server...")
    print("Server will be available at: http://127.0.0.1:8000")
    print("Press Ctrl+C to stop the server")
    
    try:
        start_server(host="127.0.0.1", port=8000)
    except KeyboardInterrupt:
        print("\nBackend server stopped.")
    except Exception as e:
        print(f"Error starting backend server: {e}")
        sys.exit(1)
