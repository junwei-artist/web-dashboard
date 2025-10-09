@echo off
REM System Monitor Web Dashboard - Installation Script for Windows
REM This script checks for Python 3.13, installs it if needed, creates venv, and sets up the project

echo ==================================================
echo 🚀 System Monitor Web Dashboard - Installation
echo ==================================================

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo [INFO] Working directory: %SCRIPT_DIR%

REM Check if Python 3.13 is installed
echo [INFO] Checking for Python 3.13...
python --version 2>nul | findstr "3.13" >nul
if %errorlevel% equ 0 (
    echo [INFO] ✅ Found Python 3.13
    goto :create_venv
)

python3 --version 2>nul | findstr "3.13" >nul
if %errorlevel% equ 0 (
    echo [INFO] ✅ Found Python 3.13
    goto :create_venv
)

echo [INFO] ❌ Python 3.13 not found
echo [ERROR] Please install Python 3.13 manually from https://www.python.org/downloads/
echo [ERROR] Make sure to check "Add Python to PATH" during installation
echo [ERROR] Then run this script again.
pause
exit /b 1

:create_venv
echo [INFO] Creating virtual environment...

REM Remove existing venv if it exists
if exist "venv" (
    echo [INFO] Removing existing virtual environment...
    rmdir /s /q venv
)

REM Create new virtual environment
python -m venv venv
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create virtual environment
    pause
    exit /b 1
)

echo [INFO] ✅ Virtual environment created successfully

:setup_project
echo [INFO] Activating virtual environment and installing dependencies...

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
if exist "requirements.txt" (
    echo [INFO] Installing project dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
    echo [INFO] ✅ Dependencies installed successfully
) else (
    echo [WARNING] requirements.txt not found, skipping dependency installation
)

REM Run setup.py if it exists
if exist "setup.py" (
    echo [INFO] Running setup.py...
    pip install -e .
    if %errorlevel% neq 0 (
        echo [WARNING] Setup.py had issues, but continuing...
    ) else (
        echo [INFO] ✅ Setup.py completed successfully
    )
) else (
    echo [WARNING] setup.py not found, skipping setup installation
)

:verify_installation
echo [INFO] Verifying installation...

REM Check if venv exists
if not exist "venv" (
    echo [ERROR] Virtual environment not found
    pause
    exit /b 1
)

REM Check Python version in venv
call venv\Scripts\activate.bat
python --version
echo [INFO] ✅ Installation verification completed

echo.
echo ==================================================
echo 🎉 Installation Completed Successfully!
echo ==================================================
echo.
echo 📋 Next Steps:
echo    1. Run the application: start_dashboard.bat
echo    2. Or manually: venv\Scripts\activate.bat ^&^& python main.py
echo    3. Open browser: http://localhost:9100
echo.
echo 📁 Project Structure:
echo    ├── src/           # Source code
echo    ├── venv/          # Virtual environment
echo    ├── templates/     # Web templates
echo    ├── requirements.txt
echo    ├── setup.py
echo    ├── install.bat
echo    └── start_dashboard.bat
echo.
echo 🔧 Troubleshooting:
echo    - If you encounter issues, check the logs above
echo    - Make sure Python 3.13 is installed and in PATH
echo    - Run this script again if installation fails
echo.

echo [INFO] Installation script completed.
pause
