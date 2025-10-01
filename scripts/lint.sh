#!/bin/bash
# Unix shell script for running Prospector linting
# Usage: ./lint.sh [options]

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "Error: Python not found in PATH"
        exit 1
    else
        PYTHON_CMD="python"
    fi
else
    PYTHON_CMD="python3"
fi

# Make sure the script is executable
chmod +x scripts/lint.py

# Run the Python lint script with all arguments passed through
$PYTHON_CMD scripts/lint.py "$@"

# Exit with the same code as the Python script
exit $?
