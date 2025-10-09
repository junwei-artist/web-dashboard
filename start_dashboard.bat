@echo off
REM System Monitor Web Dashboard Launcher for Windows
REM This script activates the virtual environment and starts the application

echo ================================================
echo 🚀 System Monitor Web Dashboard
echo ================================================

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Check if we're in the right directory
if not exist "main.py" (
    echo [ERROR] Required files not found in %SCRIPT_DIR%
    echo [ERROR] Missing: main.py
    echo [ERROR] Please ensure the script is in the correct project directory.
    pause
    exit /b 1
)

if not exist "src" (
    echo [ERROR] Required files not found in %SCRIPT_DIR%
    echo [ERROR] Missing: src/
    echo [ERROR] Please ensure the script is in the correct project directory.
    pause
    exit /b 1
)

echo [INFO] Working directory: %SCRIPT_DIR%

REM Check if virtual environment exists
if not exist "venv" (
    echo [ERROR] Virtual environment not found. Please create it first:
    echo [ERROR] python -m venv venv
    pause
    exit /b 1
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if required packages are installed
python -c "import flask, psutil" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Required packages not found. Installing dependencies...
    pip install -r requirements.txt
)

REM Check port availability (simplified for Windows)
echo [INFO] Checking port 9100 availability...
netstat -an | findstr ":9100 " >nul
if not errorlevel 1 (
    echo [WARNING] Port 9100 is already in use!
    echo [INFO] Please close the application using port 9100 or run with a different port:
    echo [INFO] python main.py --port 9101
    pause
    exit /b 1
)

echo [INFO] ✅ Port 9100 is available
echo [INFO] Starting System Monitor Web Dashboard...
echo [INFO] Dashboard will be available at: http://localhost:9100
echo [INFO] Press Ctrl+C to stop the server
echo.

REM Start the application
python main.py

pause
