#!/bin/bash
# Next.js Frontend Launcher for macOS/Linux
# This script starts the Next.js frontend on port 9200

echo "================================================"
echo "🚀 System Monitor Dashboard - Next.js Frontend"
echo "================================================"

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if frontend-nextjs directory exists
if [ ! -d "frontend-nextjs" ]; then
    echo "[ERROR] frontend-nextjs directory not found"
    echo "[ERROR] Please ensure the Next.js frontend is set up."
    exit 1
fi

cd frontend-nextjs

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "[INFO] Installing dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install dependencies"
        exit 1
    fi
fi

# Check port availability (simplified check)
if lsof -Pi :9200 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "[WARNING] Port 9200 is already in use!"
    echo "[INFO] Please close the application using port 9200"
    exit 1
fi

echo "[INFO] ✅ Port 9200 is available"
echo "[INFO] Starting Next.js frontend..."
echo "[INFO] Frontend will be available at: http://localhost:9200"
echo "[INFO] Make sure the backend is running on port 9100"
echo "[INFO] Press Ctrl+C to stop the server"
echo ""

# Start the application
npm run dev

