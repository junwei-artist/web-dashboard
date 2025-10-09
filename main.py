#!/usr/bin/env python3
"""
Main entry point for the System Monitor Web Dashboard.
"""

import sys
import os
import argparse

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.frontend import app, start_background_monitoring
from src.backend import SystemMonitor

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='System Monitor Web Dashboard')
    parser.add_argument('--port', type=int, default=9100, help='Port to run the server on (default: 9100)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the server to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', default=True, help='Enable debug mode (default: True)')
    
    args = parser.parse_args()
    
    # Initialize with some data
    monitor = SystemMonitor()
    
    # Start background monitoring
    start_background_monitoring()
    
    print("Starting System Monitor Web Dashboard...")
    print(f"Dashboard will be available at: http://localhost:{args.port}")
    print("Press Ctrl+C to stop the server")
    
    app.run(debug=args.debug, host=args.host, port=args.port)

if __name__ == '__main__':
    main()
