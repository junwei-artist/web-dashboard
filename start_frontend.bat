@echo off
REM Next.js Frontend Launcher for Windows
REM This script starts the Next.js frontend on port 9200

echo ================================================
echo 🚀 System Monitor Dashboard - Next.js Frontend
echo ================================================

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Check if frontend-nextjs directory exists
if not exist "frontend-nextjs" (
    echo [ERROR] frontend-nextjs directory not found
    echo [ERROR] Please ensure the Next.js frontend is set up.
    pause
    exit /b 1
)

cd frontend-nextjs

REM Check if node_modules exists
if not exist "node_modules" (
    echo [INFO] Installing dependencies...
    call npm install
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Check port availability
echo [INFO] Checking port 9200 availability...
netstat -an | findstr ":9200 " >nul
if not errorlevel 1 (
    echo [WARNING] Port 9200 is already in use!
    echo [INFO] Please close the application using port 9200
    pause
    exit /b 1
)

echo [INFO] ✅ Port 9200 is available
echo [INFO] Starting Next.js frontend...
echo [INFO] Frontend will be available at: http://localhost:9200
echo [INFO] Make sure the backend is running on port 9100
echo [INFO] Press Ctrl+C to stop the server
echo.

REM Start the application
call npm run dev

pause

