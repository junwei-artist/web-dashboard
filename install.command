#!/bin/bash

# System Monitor Web Dashboard - Installation Script
# This script checks for Python 3.13, installs it if needed, creates venv, and sets up the project

echo "=================================================="
echo "🚀 System Monitor Web Dashboard - Installation"
echo "=================================================="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[INFO] Working directory: $SCRIPT_DIR"

# Function to check if Python 3.13 is installed
check_python313() {
    echo "[INFO] Checking for Python 3.13..."
    
    # Check if python3.13 exists
    if command -v python3.13 &> /dev/null; then
        PYTHON_VERSION=$(python3.13 --version 2>&1)
        echo "[INFO] ✅ Found Python: $PYTHON_VERSION"
        return 0
    fi
    
    # Check if python3 exists and is version 3.13
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1)
        if [[ $PYTHON_VERSION == *"3.13"* ]]; then
            echo "[INFO] ✅ Found Python: $PYTHON_VERSION"
            return 0
        else
            echo "[INFO] ⚠️  Found Python: $PYTHON_VERSION (not 3.13)"
        fi
    fi
    
    echo "[INFO] ❌ Python 3.13 not found"
    return 1
}

# Function to install Python 3.13 using Homebrew
install_python313() {
    echo "[INFO] Installing Python 3.13..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "[ERROR] Homebrew not found. Please install Homebrew first:"
        echo "[ERROR] /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo "[ERROR] Then run this script again."
        exit 1
    fi
    
    echo "[INFO] Installing Python 3.13 using Homebrew..."
    brew install python@3.13
    
    if [ $? -eq 0 ]; then
        echo "[INFO] ✅ Python 3.13 installed successfully"
        
        # Add Python 3.13 to PATH if needed
        PYTHON313_PATH="/opt/homebrew/bin/python3.13"
        if [ -f "$PYTHON313_PATH" ]; then
            echo "[INFO] Python 3.13 available at: $PYTHON313_PATH"
        fi
        
        return 0
    else
        echo "[ERROR] Failed to install Python 3.13"
        exit 1
    fi
}

# Function to create virtual environment
create_venv() {
    echo "[INFO] Creating virtual environment..."
    
    # Remove existing venv if it exists
    if [ -d "venv" ]; then
        echo "[INFO] Removing existing virtual environment..."
        rm -rf venv
    fi
    
    # Create new virtual environment
    if command -v python3.13 &> /dev/null; then
        python3.13 -m venv venv
    elif command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1)
        if [[ $PYTHON_VERSION == *"3.13"* ]]; then
            python3 -m venv venv
        else
            echo "[ERROR] Python 3.13 not available for virtual environment creation"
            exit 1
        fi
    else
        echo "[ERROR] No suitable Python version found"
        exit 1
    fi
    
    if [ $? -eq 0 ]; then
        echo "[INFO] ✅ Virtual environment created successfully"
    else
        echo "[ERROR] Failed to create virtual environment"
        exit 1
    fi
}

# Function to activate virtual environment and install dependencies
setup_project() {
    echo "[INFO] Activating virtual environment and installing dependencies..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    if [ $? -eq 0 ]; then
        echo "[INFO] ✅ Virtual environment activated"
        
        # Upgrade pip
        echo "[INFO] Upgrading pip..."
        pip install --upgrade pip --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
        
        # Install requirements
        if [ -f "requirements.txt" ]; then
            echo "[INFO] Installing project dependencies..."
            pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
            
            if [ $? -eq 0 ]; then
                echo "[INFO] ✅ Dependencies installed successfully"
            else
                echo "[ERROR] Failed to install dependencies"
                exit 1
            fi
        else
            echo "[WARNING] requirements.txt not found, skipping dependency installation"
        fi
        
        # Run setup.py if it exists
        if [ -f "setup.py" ]; then
            echo "[INFO] Running setup.py..."
            pip install -e . --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
            
            if [ $? -eq 0 ]; then
                echo "[INFO] ✅ Setup.py completed successfully"
            else
                echo "[WARNING] Setup.py had issues, but continuing..."
            fi
        else
            echo "[WARNING] setup.py not found, skipping setup installation"
        fi
        
    else
        echo "[ERROR] Failed to activate virtual environment"
        exit 1
    fi
}

# Function to verify installation
verify_installation() {
    echo "[INFO] Verifying installation..."
    
    # Check if venv exists
    if [ ! -d "venv" ]; then
        echo "[ERROR] Virtual environment not found"
        return 1
    fi
    
    # Activate venv and check Python version
    source venv/bin/activate
    PYTHON_VERSION=$(python --version 2>&1)
    echo "[INFO] Virtual environment Python version: $PYTHON_VERSION"
    
    # Check if required packages are installed
    echo "[INFO] Checking installed packages..."
    pip list | grep -E "(Flask|psutil|Werkzeug)" || echo "[WARNING] Some required packages may not be installed"
    
    echo "[INFO] ✅ Installation verification completed"
    return 0
}

# Main installation process
main() {
    echo "[INFO] Starting installation process..."
    
    # Step 1: Check Python 3.13
    if ! check_python313; then
        echo "[INFO] Python 3.13 not found, attempting to install..."
        install_python313
    fi
    
    # Step 2: Create virtual environment
    create_venv
    
    # Step 3: Setup project
    setup_project
    
    # Step 4: Verify installation
    verify_installation
    
    echo ""
    echo "=================================================="
    echo "🎉 Installation Completed Successfully!"
    echo "=================================================="
    echo ""
    echo "📋 Next Steps:"
    echo "   1. Run the application: ./start_dashboard.command"
    echo "   2. Or manually: source venv/bin/activate && python main.py"
    echo "   3. Open browser: http://localhost:9100"
    echo ""
    echo "📁 Project Structure:"
    echo "   ├── src/           # Source code"
    echo "   ├── venv/          # Virtual environment"
    echo "   ├── templates/     # Web templates"
    echo "   ├── requirements.txt"
    echo "   ├── setup.py"
    echo "   ├── install.command"
    echo "   └── start_dashboard.command"
    echo ""
    echo "🔧 Troubleshooting:"
    echo "   - If you encounter issues, check the logs above"
    echo "   - Make sure you have Homebrew installed for Python installation"
    echo "   - Run this script again if installation fails"
    echo ""
}

# Run main function
main

echo "[INFO] Installation script completed."
