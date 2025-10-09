#!/usr/bin/env python3
"""
Backend service for system monitoring dashboard.
Monitors running services, active ports, and database status.
"""

import subprocess
import socket
import psutil
import json
import time
from datetime import datetime
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SystemMonitor:
    """Main class for monitoring system resources and services."""
    
    def __init__(self):
        self.start_time = datetime.now()
    
    def get_running_services(self) -> List[Dict[str, Any]]:
        """Get list of currently running services."""
        try:
            services = []
            for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    cpu_percent = proc_info['cpu_percent'] if proc_info['cpu_percent'] is not None else 0
                    memory_percent = proc_info['memory_percent'] if proc_info['memory_percent'] is not None else 0
                    services.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'status': proc_info['status'],
                        'cpu_percent': round(cpu_percent, 2),
                        'memory_percent': round(memory_percent, 2)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage
            services.sort(key=lambda x: x['cpu_percent'], reverse=True)
            return services[:50]  # Return top 50 processes
            
        except Exception as e:
            logger.error(f"Error getting running services: {e}")
            return []
    
    def get_active_ports(self) -> List[Dict[str, Any]]:
        """Get list of active network connections and listening ports."""
        try:
            connections = []
            
            # Get all network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    try:
                        connections.append({
                            'pid': conn.pid,
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            'status': conn.status,
                            'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6'
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                        continue
            
            # Sort by port number
            connections.sort(key=lambda x: int(x['local_address'].split(':')[-1]) if ':' in x['local_address'] and x['local_address'] != 'N/A' else 0)
            return connections
            
        except Exception as e:
            logger.error(f"Error getting active ports: {e}")
            return []
    
    def check_mysql_status(self) -> Dict[str, Any]:
        """Check if MySQL is running and get connection info."""
        try:
            # Check if MySQL process is running
            mysql_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'mysql' in proc.info['name'].lower():
                        mysql_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else 'N/A'
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Try to connect to MySQL
            mysql_connection = False
            mysql_port = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', 3306))
                if result == 0:
                    mysql_connection = True
                    mysql_port = 3306
                sock.close()
            except:
                pass
            
            return {
                'running': len(mysql_processes) > 0,
                'processes': mysql_processes,
                'port_accessible': mysql_connection,
                'port': mysql_port,
                'status': 'Running' if len(mysql_processes) > 0 else 'Not Running'
            }
            
        except Exception as e:
            logger.error(f"Error checking MySQL status: {e}")
            return {'running': False, 'processes': [], 'port_accessible': False, 'port': None, 'status': 'Error'}
    
    def check_postgresql_status(self) -> Dict[str, Any]:
        """Check if PostgreSQL is running and get connection info."""
        try:
            # Check if PostgreSQL process is running
            postgres_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'postgres' in proc.info['name'].lower():
                        postgres_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else 'N/A'
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Try to connect to PostgreSQL
            postgres_connection = False
            postgres_port = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', 5432))
                if result == 0:
                    postgres_connection = True
                    postgres_port = 5432
                sock.close()
            except:
                pass
            
            return {
                'running': len(postgres_processes) > 0,
                'processes': postgres_processes,
                'port_accessible': postgres_connection,
                'port': postgres_port,
                'status': 'Running' if len(postgres_processes) > 0 else 'Not Running'
            }
            
        except Exception as e:
            logger.error(f"Error checking PostgreSQL status: {e}")
            return {'running': False, 'processes': [], 'port_accessible': False, 'port': None, 'status': 'Error'}
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get general system information."""
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}
    
    def get_all_monitoring_data(self) -> Dict[str, Any]:
        """Get all monitoring data in one call."""
        return {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.get_system_info(),
            'running_services': self.get_running_services(),
            'active_ports': self.get_active_ports(),
            'mysql_status': self.check_mysql_status(),
            'postgresql_status': self.check_postgresql_status(),
            'monitor_uptime': str(datetime.now() - self.start_time)
        }

def main():
    """Main function for testing the backend."""
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

if __name__ == "__main__":
    main()
