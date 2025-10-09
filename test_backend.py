#!/usr/bin/env python3
"""
Test script for the System Monitor Backend.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.backend import SystemMonitor
import json

if __name__ == '__main__':
    monitor = SystemMonitor()
    
    print("System Monitor Backend")
    print("=" * 50)
    
    # Test individual functions
    print("\n1. System Information:")
    system_info = monitor.get_system_info()
    for key, value in system_info.items():
        print(f"   {key}: {value}")
    
    print(f"\n2. Running Services (Top 10):")
    services = monitor.get_running_services()
    for i, service in enumerate(services[:10]):
        print(f"   {i+1}. {service['name']} (PID: {service['pid']}, CPU: {service['cpu_percent']}%)")
    
    print(f"\n3. Active Ports:")
    ports = monitor.get_active_ports()
    for i, port in enumerate(ports[:10]):
        print(f"   {i+1}. {port['local_address']} - {port['status']}")
    
    print(f"\n4. MySQL Status:")
    mysql_status = monitor.check_mysql_status()
    print(f"   Status: {mysql_status['status']}")
    print(f"   Port Accessible: {mysql_status['port_accessible']}")
    
    print(f"\n5. PostgreSQL Status:")
    postgres_status = monitor.check_postgresql_status()
    print(f"   Status: {postgres_status['status']}")
    print(f"   Port Accessible: {postgres_status['port_accessible']}")
    
    print(f"\n6. All Data (JSON):")
    all_data = monitor.get_all_monitoring_data()
    print(json.dumps(all_data, indent=2, default=str))
