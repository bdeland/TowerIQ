@echo off
REM Windows batch script for running Prospector linting
REM Usage: lint.bat [options]

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found in PATH
    exit /b 1
)

REM Run the Python lint script with all arguments passed through
python scripts/lint.py %*

REM Exit with the same code as the Python script
exit /b %errorlevel%
