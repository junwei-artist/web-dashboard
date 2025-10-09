#!/bin/bash

# System Monitor Web Dashboard Launcher
# This script activates the virtual environment, checks for port conflicts,
# and provides options to handle them before starting the application.

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default port
DEFAULT_PORT=9100

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${PURPLE}🚀 System Monitor Web Dashboard${NC}"
    echo -e "${CYAN}================================================${NC}"
}

# Function to check if port is in use
check_port() {
    local port=$1
    local pid=$(lsof -ti:$port 2>/dev/null)
    
    if [ -n "$pid" ]; then
        # Get process information
        local process_info=$(ps -p $pid -o pid,ppid,command 2>/dev/null | tail -n +2)
        local process_name=$(ps -p $pid -o comm= 2>/dev/null)
        local memory_usage=$(ps -p $pid -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        local cpu_usage=$(ps -p $pid -o %cpu= 2>/dev/null)
        
        echo "true:$pid:$process_name:$memory_usage:$cpu_usage:$process_info"
    else
        echo "false"
    fi
}

# Function to handle port conflicts
handle_port_conflict() {
    local port=$1
    
    print_warning "Port $port is already in use!"
    echo ""
    echo "📋 Process Information:"
    
    local port_info=$(check_port $port)
    if [[ $port_info == true:* ]]; then
        IFS=':' read -r is_used pid process_name memory_usage cpu_usage process_info <<< "$port_info"
        
        echo "   PID: $pid"
        echo "   Name: $process_name"
        echo "   Memory Usage: $memory_usage"
        echo "   CPU Usage: ${cpu_usage}%"
        echo "   Command: $process_info"
        echo ""
        
        echo "🔧 Options:"
        echo "   1. Terminate the process and use port $port"
        echo "   2. Find an alternative port"
        echo "   3. Exit the application"
        echo ""
        
        while true; do
            read -p "Enter your choice (1/2/3): " choice
            case $choice in
                1)
                    print_status "Terminating process $pid..."
                    if kill -9 $pid 2>/dev/null; then
                        sleep 2
                        if ! check_port $port | grep -q "true"; then
                            print_status "Process terminated successfully. Port $port is now available."
                            return $port
                        else
                            print_error "Failed to terminate process. Port $port is still in use."
                            return 1
                        fi
                    else
                        print_error "Failed to terminate process $pid. You may need administrator privileges."
                        return 1
                    fi
                    ;;
                2)
                    find_alternative_port
                    return $?
                    ;;
                3)
                    print_status "Exiting application."
                    exit 0
                    ;;
                *)
                    print_error "Invalid choice. Please enter 1, 2, or 3."
                    ;;
            esac
        done
    fi
}

# Function to find alternative port
find_alternative_port() {
    print_status "Searching for alternative port..."
    
    for port in $(seq 9101 9200); do
        if ! check_port $port | grep -q "true"; then
            print_status "Found available port: $port"
            return $port
        fi
    done
    
    print_error "No available ports found in range 9101-9200"
    return 1
}

# Function to start the application
start_application() {
    local port=$1
    
    print_status "Starting System Monitor Web Dashboard..."
    print_status "Dashboard will be available at: http://localhost:$port"
    print_status "Press Ctrl+C to stop the server"
    echo ""
    
    # Start the application
    python main.py --port $port
}

# Main execution
main() {
    print_header
    
    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Change to the script directory
    cd "$SCRIPT_DIR"
    
    # Check if we're in the right directory
    if [ ! -f "main.py" ] || [ ! -d "src" ] || [ ! -f "requirements.txt" ]; then
        print_error "Required files not found in $SCRIPT_DIR"
        print_error "Missing: main.py, src/, or requirements.txt"
        print_error "Please ensure the script is in the correct project directory."
        exit 1
    fi
    
    print_status "Working directory: $SCRIPT_DIR"
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_error "Virtual environment not found. Please create it first:"
        print_error "python3 -m venv venv"
        exit 1
    fi
    
    # Activate virtual environment
    print_status "Activating virtual environment..."
    source venv/bin/activate
    
    # Check if required packages are installed
    if ! python -c "import flask, psutil" 2>/dev/null; then
        print_warning "Required packages not found. Installing dependencies..."
        pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
    fi
    
    # Check port availability
    print_status "Checking port $DEFAULT_PORT availability..."
    
    local port_info=$(check_port $DEFAULT_PORT)
    if [[ $port_info == "false" ]]; then
        print_status "✅ Port $DEFAULT_PORT is available"
        start_application $DEFAULT_PORT
    else
        handle_port_conflict $DEFAULT_PORT
        local selected_port=$?
        
        if [ $selected_port -gt 0 ]; then
            start_application $selected_port
        else
            print_error "Failed to resolve port conflict. Exiting."
            exit 1
        fi
    fi
}

# Handle script interruption
trap 'print_status "Application stopped by user."; exit 0' INT

# Run main function
main "$@"
