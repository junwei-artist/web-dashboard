#!/usr/bin/env python3
"""
Main entry point for the System Monitor Web Dashboard.
"""

import sys
import os
import argparse

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.frontend import app, socketio, start_background_monitoring
from src.backend import SystemMonitor
from src.config_manager import ConfigManager

def main():
    # Load configuration
    config_manager = ConfigManager()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='System Monitor Web Dashboard')
    parser.add_argument('--port', type=int, default=config_manager.get('server.port', 9100), 
                       help='Port to run the server on')
    parser.add_argument('--host', type=str, default=config_manager.get('server.host', '0.0.0.0'), 
                       help='Host to bind the server to')
    parser.add_argument('--debug', action='store_true', 
                       default=config_manager.get('server.debug', True), 
                       help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Initialize with some data
    monitor = SystemMonitor()
    
    # Start background monitoring
    start_background_monitoring()
    
    # Display security information
    security_config = config_manager.get_security_config()
    if security_config.get('enable_ip_restriction', False):
        allowed_ips = security_config.get('allowed_ips', [])
        print("🔒 IP Restriction ENABLED")
        print(f"📋 Allowed IPs: {', '.join(allowed_ips)}")
    else:
        print("🔓 IP Restriction DISABLED - All IPs allowed")
    
    print("Starting System Monitor Web Dashboard...")
    print(f"Dashboard will be available at: http://localhost:{args.port}")
    print("Press Ctrl+C to stop the server")
    
    socketio.run(app, debug=args.debug, host=args.host, port=args.port)

if __name__ == '__main__':
    main()
