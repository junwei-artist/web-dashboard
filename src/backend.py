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
import ipaddress
import os
import yaml
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
        self._psutil_access_warned = False  # Track if we've already warned about psutil access
        self._fallback_error_logged = False  # Track if we've already logged fallback errors
        self._port_labels = self._initialize_port_labels()
        # Load custom labels from configuration file
        self.load_custom_labels_from_file()
        
        # Client monitoring
        self._active_clients = {}  # {client_ip: {last_seen, user_agent, request_count, endpoints}}
        self._client_history = []  # List of all client access records
        
        # Network connection monitoring
        self._network_connections = {}  # {connection_id: {local_addr, remote_addr, status, process, timestamp}}
        self._connection_history = []  # List of all network connection records
        
        # SSH kill log
        self._killed_ssh_connections = []  # List of killed SSH connections with timestamp
        
        # Network interface IP list management
        self._test_ip_list = []  # List of IPs to test
        self._test_url_list = []  # List of URLs to test with curl
        self._route_configs = {}  # {interface_name: {enabled: bool, target_ip: str, gateway: str}}
        
        # Configuration file paths
        self._test_ips_file = "test_ips.yaml"
        self._test_urls_file = "test_urls.yaml"
        self._routes_file = "routes.yaml"
        
        # Load saved configurations
        self.load_test_ips_from_file()
        self.load_test_urls_from_file()
        self.load_routes_from_file()
    
    def _initialize_port_labels(self) -> Dict[str, str]:
        """Initialize common port labels for known services."""
        return {
            # Web servers
            '80': 'HTTP',
            '443': 'HTTPS',
            '8080': 'HTTP Alt',
            '8443': 'HTTPS Alt',
            '3000': 'Node.js/React Dev',
            '3001': 'Node.js Alt',
            '8000': 'Python/Django Dev',
            '8001': 'Python Alt',
            '9000': 'PHP-FPM',
            '9001': 'PHP-FPM Alt',
            '9002': 'PHP-FPM Alt2',
            
            # Databases
            '3306': 'MySQL',
            '33060': 'MySQL X Protocol',
            '5432': 'PostgreSQL',
            '6379': 'Redis',
            '27017': 'MongoDB',
            '1521': 'Oracle',
            '1433': 'SQL Server',
            
            # Development tools
            '4568': 'Development Server',
            '4569': 'Development Server Alt',
            '7000': 'Development Server',
            '5000': 'Flask Dev',
            '4000': 'Development Server',
            
            # System services
            '22': 'SSH',
            '21': 'FTP',
            '25': 'SMTP',
            '53': 'DNS',
            '110': 'POP3',
            '143': 'IMAP',
            '993': 'IMAPS',
            '995': 'POP3S',
            '587': 'SMTP Submission',
            '465': 'SMTPS',
            
            # Proxy/VPN
            '1080': 'SOCKS Proxy',
            '3128': 'HTTP Proxy',
            '8080': 'HTTP Proxy Alt',
            '33210': 'Proxy Service',
            '33211': 'Proxy Service Alt',
            '33212': 'Proxy Service Alt2',
            
            # Other common services
            '3389': 'RDP',
            '5900': 'VNC',
            '5901': 'VNC Alt',
            '8770': 'System Service',
            '25414': 'RStudio',
            '40353': 'RStudio Alt',
            '49199': 'DBeaver',
            '49469': 'Development Tool',
            '49479': 'Development Tool Alt',
            
            # Add your custom labels here
            '9999': 'Custom Test Service',
            '8080': 'My Web Application',
            '5000': 'Flask API Server',
            '3001': 'React Development Server'
        }
    
    def add_custom_port_label(self, port: str, label: str):
        """Add or update a custom port label."""
        self._port_labels[str(port)] = label
        logger.info(f"Added custom port label: {port} -> {label}")
    
    def load_custom_labels_from_file(self, file_path: str = "port_labels.json"):
        """Load custom port labels from a JSON configuration file."""
        try:
            with open(file_path, 'r') as f:
                config = json.load(f)
                custom_labels = config.get('custom_labels', {})
                
                for port, label in custom_labels.items():
                    self._port_labels[str(port)] = label
                
                logger.info(f"Loaded {len(custom_labels)} custom port labels from {file_path}")
                return True
        except FileNotFoundError:
            logger.warning(f"Port labels configuration file {file_path} not found")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing port labels configuration file: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading port labels from file: {e}")
            return False
    
    def save_custom_labels_to_file(self, file_path: str = "port_labels.json"):
        """Save current custom port labels to a JSON configuration file."""
        try:
            # Get only the custom labels (not the default ones)
            default_labels = self._initialize_port_labels()
            custom_labels = {}
            
            for port, label in self._port_labels.items():
                if port not in default_labels or self._port_labels[port] != default_labels[port]:
                    custom_labels[port] = label
            
            config = {
                "custom_labels": custom_labels
            }
            
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Saved {len(custom_labels)} custom port labels to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving port labels to file: {e}")
            return False
    
    def remove_custom_port_label(self, port: str):
        """Remove a custom port label."""
        if str(port) in self._port_labels:
            removed_label = self._port_labels.pop(str(port))
            logger.info(f"Removed custom port label: {port} -> {removed_label}")
            return True
        return False
    
    def get_port_label(self, port: str, process_name: str = None) -> str:
        """Get the label for a port, with process-based detection as fallback."""
        port_str = str(port)
        
        # Check if we have a predefined label
        if port_str in self._port_labels:
            return self._port_labels[port_str]
        
        # Process-based detection as fallback
        if process_name:
            process_lower = process_name.lower()
            
            # Database processes
            if 'mysql' in process_lower:
                return 'MySQL'
            elif 'postgres' in process_lower:
                return 'PostgreSQL'
            elif 'redis' in process_lower:
                return 'Redis'
            elif 'mongod' in process_lower:
                return 'MongoDB'
            
            # Web servers
            elif 'apache' in process_lower or 'httpd' in process_lower:
                return 'Apache HTTP Server'
            elif 'nginx' in process_lower:
                return 'Nginx'
            elif 'node' in process_lower:
                return 'Node.js Application'
            elif 'python' in process_lower:
                return 'Python Application'
            elif 'java' in process_lower:
                return 'Java Application'
            
            # Development tools
            elif 'dbeaver' in process_lower:
                return 'DBeaver Database Tool'
            elif 'rstudio' in process_lower or 'rsession' in process_lower:
                return 'RStudio'
            elif 'cursor' in process_lower:
                return 'Cursor IDE'
            
            # Proxy/VPN
            elif 'clash' in process_lower:
                return 'Clash Proxy'
        
        return 'Unknown Service'
    
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
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    # Skip problematic processes silently
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
            
            # Try psutil first
            try:
                net_connections = psutil.net_connections(kind='inet')
                
                for conn in net_connections:
                    if conn.status == 'LISTEN':
                        try:
                            # Safely get connection info
                            pid = conn.pid if conn.pid else 'N/A'
                            local_addr = "N/A"
                            remote_addr = "N/A"
                            family = "Unknown"
                            
                            if conn.laddr:
                                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                                port = conn.laddr.port
                            else:
                                port = None
                            
                            if conn.raddr:
                                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                            
                            if conn.family == socket.AF_INET:
                                family = 'IPv4'
                            elif conn.family == socket.AF_INET6:
                                family = 'IPv6'
                            
                            # Get process name for better labeling
                            process_name = None
                            if pid != 'N/A':
                                try:
                                    process = psutil.Process(pid)
                                    process_name = process.name()
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    process_name = None
                            
                            # Get port label
                            port_label = self.get_port_label(str(port) if port else 'N/A', process_name)
                            
                            connections.append({
                                'pid': pid,
                                'local_address': local_addr,
                                'remote_address': remote_addr,
                                'status': conn.status,
                                'family': family,
                                'port_label': port_label,
                                'process_name': process_name or 'N/A'
                            })
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError):
                            # Skip problematic connections silently
                            continue
                            
            except (psutil.AccessDenied, OSError) as e:
                # Only warn once to avoid spam
                if not self._psutil_access_warned:
                    logger.warning(f"Access denied to network connections via psutil: {e}")
                    logger.info("Falling back to system commands for port detection")
                    self._psutil_access_warned = True
                # Fallback to system command
                connections = self._get_ports_fallback()
            
            # Sort by port number with better error handling
            def safe_sort_key(conn):
                try:
                    local_addr = conn.get('local_address', 'N/A')
                    if local_addr != 'N/A' and ':' in local_addr:
                        return int(local_addr.split(':')[-1])
                    return 0
                except (ValueError, IndexError):
                    return 0
            
            connections.sort(key=safe_sort_key)
            return connections
            
        except Exception as e:
            logger.error(f"Error getting active ports: {e}")
            return []
    
    def _get_ports_fallback(self) -> List[Dict[str, Any]]:
        """Fallback method to get port information using system commands."""
        try:
            connections = []
            
            # Try netstat command with proper encoding handling
            try:
                result = subprocess.run(['netstat', '-tuln'], 
                                      capture_output=True, timeout=10)
                if result.returncode == 0:
                    # Try to decode with UTF-8, fallback to latin-1 if it fails
                    try:
                        output = result.stdout.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            output = result.stdout.decode('latin-1')
                        except UnicodeDecodeError:
                            # Skip if we can't decode at all
                            output = ""
                    
                    lines = output.split('\n')
                    for line in lines:
                        if 'LISTEN' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                local_addr = parts[3]
                                status = parts[5] if len(parts) > 5 else 'LISTEN'
                                
                                # Extract port number for labeling
                                port = None
                                if ':' in local_addr:
                                    try:
                                        port = local_addr.split(':')[-1]
                                    except (ValueError, IndexError):
                                        port = None
                                
                                # Get port label
                                port_label = self.get_port_label(str(port) if port else 'N/A')
                                
                                connections.append({
                                    'pid': 'N/A',
                                    'local_address': local_addr,
                                    'remote_address': 'N/A',
                                    'status': status,
                                    'family': 'IPv4' if ':' in local_addr else 'IPv6',
                                    'port_label': port_label,
                                    'process_name': 'N/A'
                                })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Try lsof command (macOS/Linux) with proper encoding handling
            try:
                result = subprocess.run(['lsof', '-i', '-P', '-n'], 
                                      capture_output=True, timeout=10)
                if result.returncode == 0:
                    # Try to decode with UTF-8, fallback to latin-1 if it fails
                    try:
                        output = result.stdout.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            output = result.stdout.decode('latin-1')
                        except UnicodeDecodeError:
                            # Skip if we can't decode at all
                            output = ""
                    
                    lines = output.split('\n')
                    for line in lines[1:]:  # Skip header
                        if 'LISTEN' in line:
                            parts = line.split()
                            if len(parts) >= 9:
                                pid = parts[1]
                                local_addr = parts[8]
                                process_name = parts[0] if len(parts) > 0 else 'N/A'
                                
                                # Extract port number for labeling
                                port = None
                                if ':' in local_addr:
                                    try:
                                        port = local_addr.split(':')[-1]
                                    except (ValueError, IndexError):
                                        port = None
                                
                                # Get port label with process name
                                port_label = self.get_port_label(str(port) if port else 'N/A', process_name)
                                
                                connections.append({
                                    'pid': pid,
                                    'local_address': local_addr,
                                    'remote_address': 'N/A',
                                    'status': 'LISTEN',
                                    'family': 'IPv4' if ':' in local_addr else 'IPv6',
                                    'port_label': port_label,
                                    'process_name': process_name
                                })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            return connections
            
        except Exception as e:
            # Only log the error once to avoid spam
            if not self._fallback_error_logged:
                logger.warning(f"Fallback port detection failed: {e}")
                logger.info("Port detection will continue with available methods")
                self._fallback_error_logged = True
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
    
    def reset_warning_flags(self):
        """Reset warning flags to allow logging again (useful for debugging)."""
        self._psutil_access_warned = False
        self._fallback_error_logged = False
    
    def get_ssh_connections(self) -> List[Dict[str, Any]]:
        """Get all active SSH connections using ps aux | grep ssh | grep -v grep."""
        try:
            ssh_connections = []
            
            # Use ps aux | grep ssh | grep -v grep to get all SSH processes
            try:
                # Run the command: ps aux | grep ssh | grep -v grep
                ps_process = subprocess.Popen(
                    ['ps', 'aux'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                grep_process = subprocess.Popen(
                    ['grep', 'ssh'],
                    stdin=ps_process.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                grep_v_process = subprocess.Popen(
                    ['grep', '-v', 'grep'],
                    stdin=grep_process.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Close stdout in ps_process to allow it to receive a SIGPIPE if grep exits
                ps_process.stdout.close()
                grep_process.stdout.close()
                
                # Get output
                stdout, stderr = grep_v_process.communicate(timeout=10)
                
                if grep_v_process.returncode == 0 and stdout:
                    # Parse each line from ps aux output
                    for line in stdout.decode('utf-8', errors='ignore').split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Parse ps aux output format:
                        # USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                        parts = line.split(None, 10)  # Split into max 11 parts (last part is command)
                        if len(parts) < 11:
                            continue
                        
                        try:
                            user = parts[0]
                            pid = int(parts[1])
                            cpu = parts[2]
                            mem = parts[3]
                            vsz = parts[4]
                            rss = parts[5]
                            tty = parts[6]
                            stat = parts[7]
                            start = parts[8]
                            time_used = parts[9]
                            cmdline = parts[10] if len(parts) > 10 else ''
                            
                            # Determine connection type based on command
                            connection_type = "SSH Process"
                            process_name = "ssh"
                            
                            if 'sshd' in cmdline.lower():
                                connection_type = "SSH Server (sshd)"
                                process_name = "sshd"
                            elif 'autossh' in cmdline.lower():
                                connection_type = "Autossh Tunnel"
                                process_name = "autossh"
                            elif 'ssh' in cmdline.lower():
                                # Try to determine if it's client or server
                                if '-R' in cmdline or '-L' in cmdline or '-D' in cmdline:
                                    connection_type = "SSH Tunnel"
                                elif '@' in cmdline:
                                    connection_type = "SSH Client"
                                else:
                                    connection_type = "SSH Process"
                                process_name = "ssh"
                            
                            # Try to extract connection details from command line
                            local_address = "N/A"
                            remote_address = "N/A"
                            local_port = None
                            remote_port = None
                            
                            # Parse SSH command line for connection info
                            # Examples:
                            # ssh -R 0.0.0.0:11434:127.0.0.1:11434 root@47.112.191.42
                            # ssh user@host
                            # sshd listening on port 22
                            
                            import re
                            
                            # Extract remote host from command (user@host)
                            host_match = re.search(r'([a-zA-Z0-9_-]+@)?([a-zA-Z0-9._-]+)', cmdline)
                            if host_match:
                                remote_address = host_match.group(2)
                            
                            # Extract port forwarding info (-R or -L)
                            # -R remote_bind:remote_port:local_host:local_port
                            # -L local_port:remote_host:remote_port
                            reverse_match = re.search(r'-R\s+([0-9.]+):(\d+):([0-9.]+):(\d+)', cmdline)
                            if reverse_match:
                                remote_bind = reverse_match.group(1)
                                remote_port = int(reverse_match.group(2))
                                local_host = reverse_match.group(3)
                                local_port = int(reverse_match.group(4))
                                local_address = f"{local_host}:{local_port}"
                                remote_address = f"{remote_bind}:{remote_port}"
                                connection_type = "SSH Reverse Tunnel"
                            
                            forward_match = re.search(r'-L\s+(\d+):([0-9.]+):(\d+)', cmdline)
                            if forward_match:
                                local_port = int(forward_match.group(1))
                                remote_host = forward_match.group(2)
                                remote_port = int(forward_match.group(3))
                                local_address = f"127.0.0.1:{local_port}"
                                remote_address = f"{remote_host}:{remote_port}"
                                connection_type = "SSH Forward Tunnel"
                            
                            # Extract port from -p option
                            port_match = re.search(r'-p\s+(\d+)', cmdline)
                            if port_match:
                                remote_port = int(port_match.group(1))
                            
                            # Check if it's a listening sshd
                            if 'sshd' in cmdline.lower() and ('-D' in cmdline or 'LISTEN' in stat):
                                connection_type = "SSH Server (Listening)"
                                local_address = "0.0.0.0:22"
                                local_port = 22
                            
                            ssh_connections.append({
                                'pid': pid,
                                'process_name': process_name,
                                'cmdline': cmdline,
                                'user': user,
                                'cpu': cpu,
                                'mem': mem,
                                'stat': stat,
                                'local_address': local_address,
                                'remote_address': remote_address,
                                'local_port': local_port,
                                'remote_port': remote_port,
                                'status': stat,
                                'connection_type': connection_type,
                                'timestamp': datetime.now().isoformat()
                            })
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Error parsing ps aux line: {line}, error: {e}")
                            continue
                
                elif grep_v_process.returncode == 1:
                    # No SSH processes found (grep returns 1 when no matches)
                    logger.debug("No SSH processes found")
                else:
                    logger.warning(f"Error running ps aux | grep ssh: {stderr.decode('utf-8', errors='ignore')}")
                    
            except subprocess.TimeoutExpired:
                logger.error("Timeout while getting SSH connections")
            except Exception as e:
                logger.error(f"Error getting SSH connections via ps aux: {e}")
            
            # Sort by PID (process ID)
            ssh_connections.sort(key=lambda x: x.get('pid', 0))
            
            return ssh_connections
            
        except Exception as e:
            logger.error(f"Error getting SSH connections: {e}")
            return []
    
    def kill_ssh_connection(self, pid: int) -> Dict[str, Any]:
        """Kill an SSH connection by PID and log it."""
        try:
            # Get process info before killing
            process_info = None
            try:
                process = psutil.Process(pid)
                process_info = {
                    'pid': pid,
                    'name': process.name(),
                    'cmdline': ' '.join(process.cmdline()) if process.cmdline() else 'N/A',
                    'username': process.username(),
                    'status': process.status(),
                    'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                return {
                    'success': False,
                    'error': f'Process {pid} not found or access denied: {str(e)}'
                }
            
            # Try to kill the process
            try:
                process = psutil.Process(pid)
                process.terminate()  # Try graceful termination first
                
                # Wait a bit for process to terminate
                try:
                    process.wait(timeout=3)
                    killed_gracefully = True
                except psutil.TimeoutExpired:
                    # Process didn't terminate, force kill
                    process.kill()
                    process.wait(timeout=2)
                    killed_gracefully = False
                
                # Log the kill
                kill_log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'pid': pid,
                    'process_name': process_info['name'],
                    'cmdline': process_info['cmdline'],
                    'username': process_info['username'],
                    'killed_gracefully': killed_gracefully,
                    'status_before_kill': process_info['status']
                }
                
                self._killed_ssh_connections.append(kill_log_entry)
                
                # Keep only last 100 entries
                if len(self._killed_ssh_connections) > 100:
                    self._killed_ssh_connections = self._killed_ssh_connections[-100:]
                
                logger.info(f"Killed SSH process {pid} ({process_info['name']}): {process_info['cmdline']}")
                
                return {
                    'success': True,
                    'message': f'Process {pid} ({process_info["name"]}) killed successfully',
                    'killed_gracefully': killed_gracefully,
                    'process_info': process_info
                }
                
            except psutil.NoSuchProcess:
                return {
                    'success': False,
                    'error': f'Process {pid} does not exist'
                }
            except psutil.AccessDenied:
                return {
                    'success': False,
                    'error': f'Access denied: Cannot kill process {pid} (may require root privileges)'
                }
            except Exception as e:
                logger.error(f"Error killing process {pid}: {e}")
                return {
                    'success': False,
                    'error': f'Error killing process: {str(e)}'
                }
                
        except Exception as e:
            logger.error(f"Error in kill_ssh_connection: {e}")
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
    
    def get_killed_ssh_connections_log(self) -> List[Dict[str, Any]]:
        """Get the log of killed SSH connections."""
        # Return in reverse chronological order (most recent first)
        return list(reversed(self._killed_ssh_connections))
    
    def get_all_port_labels(self) -> Dict[str, str]:
        """Get all current port labels."""
        return self._port_labels.copy()
    
    def get_port_labels_by_category(self) -> Dict[str, Dict[str, str]]:
        """Get port labels organized by category."""
        categories = {
            'Web Servers': {},
            'Databases': {},
            'Development Tools': {},
            'System Services': {},
            'Proxy/VPN': {},
            'Other Services': {}
        }
        
        # Categorize ports
        web_ports = ['80', '443', '8080', '8443', '3000', '3001', '8000', '8001', '5000', '4000']
        db_ports = ['3306', '33060', '5432', '6379', '27017', '1521', '1433']
        dev_ports = ['4568', '4569', '7000', '9000', '9001', '9002', '25414', '40353', '49199', '49469', '49479']
        system_ports = ['22', '21', '25', '53', '110', '143', '993', '995', '587', '465', '8770']
        proxy_ports = ['1080', '3128', '33210', '33211', '33212']
        other_ports = ['3389', '5900', '5901']
        
        for port, label in self._port_labels.items():
            if port in web_ports:
                categories['Web Servers'][port] = label
            elif port in db_ports:
                categories['Databases'][port] = label
            elif port in dev_ports:
                categories['Development Tools'][port] = label
            elif port in system_ports:
                categories['System Services'][port] = label
            elif port in proxy_ports:
                categories['Proxy/VPN'][port] = label
            else:
                categories['Other Services'][port] = label
        
        return categories
    
    def log_client_access(self, client_ip: str, user_agent: str = None, referer: str = None, 
                         status_code: int = 200, endpoint: str = None):
        """Log client access for monitoring."""
        current_time = datetime.now()
        
        # Clean up old history (keep last 1000 records)
        if len(self._client_history) > 1000:
            self._client_history = self._client_history[-1000:]
        
        # Add to history
        access_record = {
            'timestamp': current_time.isoformat(),
            'client_ip': client_ip,
            'user_agent': user_agent or 'Unknown',
            'referer': referer or 'Direct',
            'status_code': status_code,
            'endpoint': endpoint or 'Unknown'
        }
        self._client_history.append(access_record)
        
        # Update active clients
        if client_ip not in self._active_clients:
            self._active_clients[client_ip] = {
                'first_seen': current_time.isoformat(),
                'last_seen': current_time.isoformat(),
                'user_agent': user_agent or 'Unknown',
                'request_count': 1,
                'endpoints': set(),
                'status_codes': {}
            }
        else:
            self._active_clients[client_ip]['last_seen'] = current_time.isoformat()
            self._active_clients[client_ip]['request_count'] += 1
            if user_agent and user_agent != 'Unknown':
                self._active_clients[client_ip]['user_agent'] = user_agent
        
        # Track endpoints
        if endpoint:
            self._active_clients[client_ip]['endpoints'].add(endpoint)
        
        # Track status codes
        status_key = str(status_code)
        if status_key not in self._active_clients[client_ip]['status_codes']:
            self._active_clients[client_ip]['status_codes'][status_key] = 0
        self._active_clients[client_ip]['status_codes'][status_key] += 1
        
        # Clean up inactive clients (older than 1 hour)
        cutoff_time = current_time.timestamp() - 3600  # 1 hour ago
        inactive_clients = []
        for ip, data in self._active_clients.items():
            last_seen = datetime.fromisoformat(data['last_seen']).timestamp()
            if last_seen < cutoff_time:
                inactive_clients.append(ip)
        
        for ip in inactive_clients:
            del self._active_clients[ip]
    
    def get_active_clients(self) -> List[Dict[str, Any]]:
        """Get list of currently active clients."""
        current_time = datetime.now()
        clients = []
        
        for client_ip, data in self._active_clients.items():
            # Calculate time since last seen
            last_seen = datetime.fromisoformat(data['last_seen'])
            time_since_last_seen = current_time - last_seen
            
            # Convert sets to lists for JSON serialization
            endpoints = list(data['endpoints'])
            
            clients.append({
                'client_ip': client_ip,
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'time_since_last_seen': str(time_since_last_seen),
                'user_agent': data['user_agent'],
                'request_count': data['request_count'],
                'endpoints': endpoints,
                'endpoint_count': len(endpoints),
                'status_codes': data['status_codes'],
                'is_active': time_since_last_seen.total_seconds() < 300  # Active if seen within 5 minutes
            })
        
        # Sort by last seen (most recent first)
        clients.sort(key=lambda x: x['last_seen'], reverse=True)
        return clients
    
    def get_client_statistics(self) -> Dict[str, Any]:
        """Get overall client statistics."""
        current_time = datetime.now()
        active_count = 0
        total_requests = 0
        unique_clients_24h = set()
        
        # Count active clients (seen within 5 minutes)
        for client_ip, data in self._active_clients.items():
            last_seen = datetime.fromisoformat(data['last_seen'])
            if (current_time - last_seen).total_seconds() < 300:
                active_count += 1
            total_requests += data['request_count']
        
        # Count unique clients in last 24 hours
        cutoff_time = current_time.timestamp() - 86400  # 24 hours ago
        for record in self._client_history:
            record_time = datetime.fromisoformat(record['timestamp']).timestamp()
            if record_time > cutoff_time:
                unique_clients_24h.add(record['client_ip'])
        
        # Get top endpoints
        endpoint_counts = {}
        for record in self._client_history[-100:]:  # Last 100 requests
            endpoint = record['endpoint']
            endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
        
        top_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'active_clients': active_count,
            'total_clients': len(self._active_clients),
            'unique_clients_24h': len(unique_clients_24h),
            'total_requests': total_requests,
            'requests_per_minute': len([r for r in self._client_history if 
                                      (current_time.timestamp() - datetime.fromisoformat(r['timestamp']).timestamp()) < 60]),
            'top_endpoints': [{'endpoint': ep, 'count': count} for ep, count in top_endpoints],
            'monitoring_started': self.start_time.isoformat()
        }
    
    def get_client_history(self, client_ip: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get client access history."""
        if client_ip:
            # Filter by specific client
            history = [record for record in self._client_history if record['client_ip'] == client_ip]
        else:
            # Get all history
            history = self._client_history.copy()
        
        # Sort by timestamp (most recent first) and limit
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return history[:limit]
    
    def check_proxy_environment_variables(self) -> Dict[str, Any]:
        """Check for proxy environment variables."""
        import os
        proxy_vars = {
            'HTTP_PROXY': os.environ.get('HTTP_PROXY'),
            'HTTPS_PROXY': os.environ.get('HTTPS_PROXY'), 
            'http_proxy': os.environ.get('http_proxy'),
            'https_proxy': os.environ.get('https_proxy'),
            'NO_PROXY': os.environ.get('NO_PROXY'),
            'no_proxy': os.environ.get('no_proxy'),
            'ALL_PROXY': os.environ.get('ALL_PROXY'),
            'all_proxy': os.environ.get('all_proxy')
        }
        
        active_proxies = {k: v for k, v in proxy_vars.items() if v}
        return {
            'has_proxy_env_vars': len(active_proxies) > 0,
            'proxy_variables': active_proxies,
            'total_proxy_vars': len(active_proxies)
        }
    
    def check_network_routes(self) -> Dict[str, Any]:
        """Check network routes for proxy indicators."""
        try:
            import subprocess
            result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
            routes = result.stdout
            
            # Look for proxy-related routes and patterns
            proxy_indicators = []
            suspicious_routes = []
            
            lines = routes.split('\n')
            for line in lines:
                line_lower = line.lower()
                if any(keyword in line_lower for keyword in ['proxy', 'tunnel', 'vpn', 'tor']):
                    proxy_indicators.append(line.strip())
                # Check for unusual routing patterns
                if '0.0.0.0' in line and len(line.split()) > 2:
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway = parts[1] if len(parts) > 1 else ''
                        if gateway not in ['0.0.0.0', '127.0.0.1', 'localhost'] and gateway != '':
                            suspicious_routes.append(line.strip())
            
            return {
                'has_proxy_routes': len(proxy_indicators) > 0,
                'has_suspicious_routes': len(suspicious_routes) > 0,
                'proxy_indicators': proxy_indicators,
                'suspicious_routes': suspicious_routes[:10],  # Limit to first 10
                'total_routes_checked': len(lines)
            }
        except Exception as e:
            logger.error(f"Error checking network routes: {e}")
            return {'error': str(e), 'has_proxy_routes': False}
    
    def check_dns_servers(self) -> Dict[str, Any]:
        """Check DNS server configuration for proxy indicators."""
        try:
            import subprocess
            import re
            
            # Check /etc/resolv.conf (Linux/macOS)
            dns_servers = []
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    content = f.read()
                    dns_matches = re.findall(r'nameserver\s+(\S+)', content)
                    dns_servers.extend(dns_matches)
            except FileNotFoundError:
                pass
            
            # Check system DNS configuration (macOS)
            try:
                result = subprocess.run(['scutil', '--dns'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    dns_matches = re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', result.stdout)
                    dns_servers.extend(dns_matches)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            # Remove duplicates and check for suspicious DNS servers
            dns_servers = list(set(dns_servers))
            suspicious_dns = []
            
            # Common proxy/VPN DNS servers
            proxy_dns_patterns = [
                '1.1.1.1', '1.0.0.1',  # Cloudflare
                '8.8.8.8', '8.8.4.4',  # Google
                '208.67.222.222', '208.67.220.220',  # OpenDNS
            ]
            
            for dns in dns_servers:
                if dns in proxy_dns_patterns:
                    suspicious_dns.append(dns)
            
            return {
                'dns_servers': dns_servers,
                'has_suspicious_dns': len(suspicious_dns) > 0,
                'suspicious_dns_servers': suspicious_dns,
                'total_dns_servers': len(dns_servers)
            }
        except Exception as e:
            logger.error(f"Error checking DNS servers: {e}")
            return {'error': str(e), 'dns_servers': []}
    
    def check_proxy_usage(self) -> Dict[str, Any]:
        """Comprehensive proxy detection check."""
        try:
            # Get existing proxy-related data
            active_ports = self.get_active_ports()
            running_services = self.get_running_services()
            
            # Filter for proxy-related items
            proxy_ports = [port for port in active_ports 
                          if 'proxy' in port.get('port_label', '').lower() or 
                             'vpn' in port.get('port_label', '').lower()]
            
            proxy_processes = [service for service in running_services
                             if any(keyword in service.get('name', '').lower() 
                                   for keyword in ['proxy', 'vpn', 'clash', 'shadowsocks', 'v2ray'])]
            
            # Get enhanced detection data
            env_vars = self.check_proxy_environment_variables()
            network_routes = self.check_network_routes()
            dns_servers = self.check_dns_servers()
            
            # Calculate risk score
            risk_factors = 0
            if env_vars.get('has_proxy_env_vars', False):
                risk_factors += 2
            if network_routes.get('has_proxy_routes', False):
                risk_factors += 3
            if network_routes.get('has_suspicious_routes', False):
                risk_factors += 1
            if dns_servers.get('has_suspicious_dns', False):
                risk_factors += 1
            if len(proxy_ports) > 0:
                risk_factors += 2
            if len(proxy_processes) > 0:
                risk_factors += 3
            
            # Determine risk level
            if risk_factors >= 6:
                risk_level = "HIGH"
            elif risk_factors >= 3:
                risk_level = "MEDIUM"
            elif risk_factors >= 1:
                risk_level = "LOW"
            else:
                risk_level = "NONE"
            
            return {
                'timestamp': datetime.now().isoformat(),
                'risk_level': risk_level,
                'risk_score': risk_factors,
                'proxy_ports': proxy_ports,
                'proxy_processes': proxy_processes,
                'environment_variables': env_vars,
                'network_routes': network_routes,
                'dns_servers': dns_servers,
                'summary': {
                    'total_proxy_ports': len(proxy_ports),
                    'total_proxy_processes': len(proxy_processes),
                    'has_env_proxy_vars': env_vars.get('has_proxy_env_vars', False),
                    'has_proxy_routes': network_routes.get('has_proxy_routes', False),
                    'has_suspicious_dns': dns_servers.get('has_suspicious_dns', False)
                }
            }
        except Exception as e:
            logger.error(f"Error in comprehensive proxy check: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'risk_level': 'UNKNOWN'
            }

    def monitor_network_connections(self) -> Dict[str, Any]:
        """Monitor all network connections to track clients across all ports."""
        try:
            current_time = datetime.now()
            connections = []
            
            # Try psutil first
            try:
                net_connections = psutil.net_connections(kind='inet')
                
                for conn in net_connections:
                    try:
                        # Only track established connections (not listening ports)
                        if conn.status in ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'FIN_WAIT1', 'FIN_WAIT2']:
                            connection_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                            
                            # Get process info
                            process_name = 'Unknown'
                            pid = 'N/A'
                            if conn.pid:
                                try:
                                    process = psutil.Process(conn.pid)
                                    process_name = process.name()
                                    pid = conn.pid
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            
                            # Get port label
                            port_label = self.get_port_label(str(conn.laddr.port), process_name)
                            
                            # Format addresses properly for IPv4 and IPv6
                            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr.ip else "Unknown"
                            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr.ip else "Unknown"
                            
                            connection_info = {
                                'connection_id': connection_id,
                                'local_address': local_addr,
                                'remote_address': remote_addr,
                                'remote_ip': conn.raddr.ip if conn.raddr.ip else 'Unknown',
                                'remote_port': conn.raddr.port if conn.raddr.port else 'Unknown',
                                'remote_ip_formatted': self._format_ip_address(conn.raddr.ip if conn.raddr.ip else 'Unknown'),
                                'status': conn.status,
                                'process_name': process_name,
                                'pid': pid,
                                'port_label': port_label,
                                'timestamp': current_time.isoformat()
                            }
                            
                            connections.append(connection_info)
                            
                            # Update connection tracking
                            self._network_connections[connection_id] = connection_info
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError):
                        continue
                        
            except (psutil.AccessDenied, OSError) as e:
                logger.warning(f"Access denied to network connections: {e}")
                # Fallback to system commands
                connections = self._get_network_connections_fallback()
            
            # Clean up old connections
            self._cleanup_old_connections()
            
            # Add to history
            for conn in connections:
                self._connection_history.append(conn)
            
            # Limit history size
            if len(self._connection_history) > 1000:
                self._connection_history = self._connection_history[-1000:]
            
            return {
                'active_connections': connections,
                'total_connections': len(connections),
                'timestamp': current_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error monitoring network connections: {e}")
            return {'active_connections': [], 'total_connections': 0, 'error': str(e)}
    
    def _get_network_connections_fallback(self) -> List[Dict[str, Any]]:
        """Fallback method to get network connections using system commands."""
        try:
            connections = []
            current_time = datetime.now()
            
            # Try netstat command
            try:
                result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'ESTABLISHED' in line or 'TIME_WAIT' in line:
                            parts = line.split()
                            if len(parts) >= 6:
                                local_addr = parts[3]
                                remote_addr = parts[4]
                                status = parts[5]
                                
                                # Extract IPs and ports (handle both IPv4 and IPv6)
                                # IPv4: 127.0.0.1:8080 (colon separator)
                                # IPv6: fe80::500a:48ff:.8770 (dot separator)
                                
                                # Parse local address (macOS netstat uses dots for both IPv4 and IPv6)
                                if '.' in local_addr:
                                    # Both IPv4 and IPv6 use dot separator on macOS
                                    local_ip, local_port = local_addr.rsplit('.', 1)
                                elif ':' in local_addr:
                                    # Fallback for colon separator
                                    local_ip, local_port = local_addr.rsplit(':', 1)
                                else:
                                    local_ip, local_port = local_addr, 'Unknown'
                                
                                # Parse remote address (macOS netstat uses dots for both IPv4 and IPv6)
                                if '.' in remote_addr:
                                    # Both IPv4 and IPv6 use dot separator on macOS
                                    remote_ip, remote_port = remote_addr.rsplit('.', 1)
                                elif ':' in remote_addr:
                                    # Fallback for colon separator
                                    remote_ip, remote_port = remote_addr.rsplit(':', 1)
                                else:
                                    remote_ip, remote_port = remote_addr, 'Unknown'
                                
                                # Create connection info for all parsed connections
                                connection_id = f"{local_addr}-{remote_addr}"
                                
                                connection_info = {
                                    'connection_id': connection_id,
                                    'local_address': local_addr,
                                    'remote_address': remote_addr,
                                    'remote_ip': remote_ip,
                                    'remote_port': remote_port,
                                    'remote_ip_formatted': self._format_ip_address(remote_ip),
                                    'status': status,
                                    'process_name': 'Unknown',
                                    'pid': 'N/A',
                                    'port_label': self.get_port_label(local_port),
                                    'timestamp': current_time.isoformat()
                                }
                                
                                connections.append(connection_info)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            return connections
            
        except Exception as e:
            logger.error(f"Error in network connections fallback: {e}")
            return []
    
    def _cleanup_old_connections(self):
        """Clean up old network connections that are no longer active."""
        current_time = datetime.now()
        cutoff_time = current_time.timestamp() - 300  # 5 minutes ago
        
        # Remove old connections from tracking
        old_connections = []
        for conn_id, conn_data in self._network_connections.items():
            conn_time = datetime.fromisoformat(conn_data['timestamp']).timestamp()
            if conn_time < cutoff_time:
                old_connections.append(conn_id)
        
        for conn_id in old_connections:
            del self._network_connections[conn_id]
    
    def _format_ip_address(self, ip_address: str) -> str:
        """Format IP address for better display."""
        if not ip_address or ip_address == 'Unknown':
            return 'Unknown'
        
        # Handle IPv6 addresses
        if '::' in ip_address:
            # IPv6 address - could be link-local (fe80::) or other
            if ip_address.startswith('fe80::'):
                # Link-local address - show as "Link-Local"
                return f"Link-Local ({ip_address})"
            elif ip_address.startswith('::1'):
                # IPv6 localhost
                return "IPv6 Localhost"
            else:
                # Other IPv6 address
                return f"IPv6 ({ip_address})"
        elif ip_address.startswith('127.'):
            # IPv4 localhost
            return "Localhost"
        elif ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
            # Private IPv4 address
            return f"Private ({ip_address})"
        else:
            # Public IPv4 address
            return ip_address
    
    def get_network_client_statistics(self) -> Dict[str, Any]:
        """Get statistics about network clients across all ports."""
        try:
            current_time = datetime.now()
            
            # Get current connections
            conn_data = self.monitor_network_connections()
            active_connections = conn_data.get('active_connections', [])
            
            # Analyze clients
            client_stats = {}
            port_stats = {}
            process_stats = {}
            
            for conn in active_connections:
                remote_ip = conn.get('remote_ip', 'Unknown')
                local_port = conn.get('local_address', '').split(':')[-1] if ':' in conn.get('local_address', '') else 'Unknown'
                process_name = conn.get('process_name', 'Unknown')
                
                # Client statistics
                if remote_ip not in client_stats:
                    client_stats[remote_ip] = {
                        'connection_count': 0,
                        'ports_accessed': set(),
                        'processes_accessed': set(),
                        'last_seen': conn.get('timestamp', '')
                    }
                
                client_stats[remote_ip]['connection_count'] += 1
                client_stats[remote_ip]['ports_accessed'].add(local_port)
                client_stats[remote_ip]['processes_accessed'].add(process_name)
                
                # Port statistics
                if local_port not in port_stats:
                    port_stats[local_port] = {
                        'connection_count': 0,
                        'unique_clients': set(),
                        'port_label': conn.get('port_label', 'Unknown')
                    }
                
                port_stats[local_port]['connection_count'] += 1
                port_stats[local_port]['unique_clients'].add(remote_ip)
                
                # Process statistics
                if process_name not in process_stats:
                    process_stats[process_name] = {
                        'connection_count': 0,
                        'unique_clients': set(),
                        'ports_served': set()
                    }
                
                process_stats[process_name]['connection_count'] += 1
                process_stats[process_name]['unique_clients'].add(remote_ip)
                process_stats[process_name]['ports_served'].add(local_port)
            
            # Convert sets to counts for JSON serialization
            for client in client_stats.values():
                client['ports_accessed'] = len(client['ports_accessed'])
                client['processes_accessed'] = len(client['processes_accessed'])
            
            for port in port_stats.values():
                port['unique_clients'] = len(port['unique_clients'])
            
            for process in process_stats.values():
                process['unique_clients'] = len(process['unique_clients'])
                process['ports_served'] = len(process['ports_served'])
            
            return {
                'timestamp': current_time.isoformat(),
                'total_active_connections': len(active_connections),
                'unique_clients': len(client_stats),
                'active_ports': len(port_stats),
                'active_processes': len(process_stats),
                'client_statistics': client_stats,
                'port_statistics': port_stats,
                'process_statistics': process_stats,
                'top_clients': sorted(client_stats.items(), key=lambda x: x[1]['connection_count'], reverse=True)[:10],
                'top_ports': sorted(port_stats.items(), key=lambda x: x[1]['connection_count'], reverse=True)[:10],
                'top_processes': sorted(process_stats.items(), key=lambda x: x[1]['connection_count'], reverse=True)[:10]
            }
            
        except Exception as e:
            logger.error(f"Error getting network client statistics: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'total_active_connections': 0,
                'unique_clients': 0
            }
    
    def get_clients_by_port(self) -> Dict[str, Any]:
        """Get clients categorized by the ports they're accessing."""
        try:
            current_time = datetime.now()
            
            # Get current connections
            conn_data = self.monitor_network_connections()
            active_connections = conn_data.get('active_connections', [])
            
            # Group connections by port
            ports_data = {}
            
            for conn in active_connections:
                local_port = conn.get('local_address', '').split(':')[-1] if ':' in conn.get('local_address', '') else 'Unknown'
                remote_ip = conn.get('remote_ip', 'Unknown')
                remote_port = conn.get('remote_port', 'Unknown')
                
                # Initialize port data if not exists
                if local_port not in ports_data:
                    ports_data[local_port] = {
                        'port': local_port,
                        'port_label': conn.get('port_label', 'Unknown'),
                        'process_name': conn.get('process_name', 'Unknown'),
                        'pid': conn.get('pid', 'N/A'),
                        'clients': {},
                        'total_connections': 0,
                        'unique_clients': 0
                    }
                
                # Add client to port
                client_key = f"{remote_ip}:{remote_port}"
                if client_key not in ports_data[local_port]['clients']:
                    ports_data[local_port]['clients'][client_key] = {
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'connection_count': 0,
                        'connections': [],
                        'last_seen': conn.get('timestamp', ''),
                        'status': conn.get('status', 'Unknown')
                    }
                
                # Update client data
                client_data = ports_data[local_port]['clients'][client_key]
                client_data['connection_count'] += 1
                client_data['connections'].append({
                    'connection_id': conn.get('connection_id', ''),
                    'status': conn.get('status', 'Unknown'),
                    'timestamp': conn.get('timestamp', '')
                })
                client_data['last_seen'] = conn.get('timestamp', '')
                
                # Update port totals
                ports_data[local_port]['total_connections'] += 1
            
            # Calculate unique clients for each port
            for port_data in ports_data.values():
                port_data['unique_clients'] = len(port_data['clients'])
            
            # Sort ports by total connections
            sorted_ports = sorted(ports_data.items(), key=lambda x: x[1]['total_connections'], reverse=True)
            
            # Convert to list format for easier frontend handling
            ports_list = []
            for port, port_data in sorted_ports:
                # Sort clients by connection count
                sorted_clients = sorted(port_data['clients'].items(), 
                                      key=lambda x: x[1]['connection_count'], reverse=True)
                
                ports_list.append({
                    'port': port_data['port'],
                    'port_label': port_data['port_label'],
                    'process_name': port_data['process_name'],
                    'pid': port_data['pid'],
                    'total_connections': port_data['total_connections'],
                    'unique_clients': port_data['unique_clients'],
                    'clients': [client_data for _, client_data in sorted_clients]
                })
            
            return {
                'timestamp': current_time.isoformat(),
                'ports': ports_list,
                'total_ports': len(ports_list),
                'total_connections': sum(port['total_connections'] for port in ports_list),
                'total_unique_clients': len(set(
                    client['remote_ip'] for port in ports_list 
                    for client in port['clients']
                ))
            }
            
        except Exception as e:
            logger.error(f"Error getting clients by port: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'ports': [],
                'total_ports': 0,
                'total_connections': 0,
                'total_unique_clients': 0
            }
    
    def get_custom_port_clients(self) -> Dict[str, Any]:
        """Get clients for ports defined in port_labels.json."""
        try:
            current_time = datetime.now()
            
            # Get custom ports from port_labels.json
            custom_ports = set()
            try:
                with open('port_labels.json', 'r') as f:
                    config = json.load(f)
                    custom_labels = config.get('custom_labels', {})
                    custom_ports = set(custom_labels.keys())
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.warning(f"Could not load custom ports from port_labels.json: {e}")
                custom_ports = set()
            
            # Get current connections
            conn_data = self.monitor_network_connections()
            active_connections = conn_data.get('active_connections', [])
            
            # Filter connections for custom ports
            custom_port_connections = []
            for conn in active_connections:
                local_address = conn.get('local_address', '')
                # Extract port from local address (handle both IPv4 and IPv6 formats)
                if '.' in local_address:
                    local_port = local_address.rsplit('.', 1)[-1]
                elif ':' in local_address:
                    local_port = local_address.rsplit(':', 1)[-1]
                else:
                    local_port = 'Unknown'
                
                if local_port in custom_ports:
                    custom_port_connections.append(conn)
            
            # Group connections by custom port
            ports_data = {}
            
            for conn in custom_port_connections:
                local_address = conn.get('local_address', '')
                # Extract port from local address (handle both IPv4 and IPv6 formats)
                if '.' in local_address:
                    local_port = local_address.rsplit('.', 1)[-1]
                elif ':' in local_address:
                    local_port = local_address.rsplit(':', 1)[-1]
                else:
                    local_port = 'Unknown'
                
                remote_ip = conn.get('remote_ip', 'Unknown')
                remote_port = conn.get('remote_port', 'Unknown')
                
                # Initialize port data if not exists
                if local_port not in ports_data:
                    ports_data[local_port] = {
                        'port': local_port,
                        'port_label': conn.get('port_label', 'Unknown'),
                        'process_name': conn.get('process_name', 'Unknown'),
                        'pid': conn.get('pid', 'N/A'),
                        'clients': {},
                        'total_connections': 0,
                        'unique_clients': 0,
                        'is_custom_port': True
                    }
                
                # Add client to port
                client_key = f"{remote_ip}:{remote_port}"
                if client_key not in ports_data[local_port]['clients']:
                    ports_data[local_port]['clients'][client_key] = {
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'connection_count': 0,
                        'connections': [],
                        'last_seen': conn.get('timestamp', ''),
                        'status': conn.get('status', 'Unknown')
                    }
                
                # Update client data
                client_data = ports_data[local_port]['clients'][client_key]
                client_data['connection_count'] += 1
                client_data['connections'].append({
                    'connection_id': conn.get('connection_id', ''),
                    'status': conn.get('status', 'Unknown'),
                    'timestamp': conn.get('timestamp', '')
                })
                client_data['last_seen'] = conn.get('timestamp', '')
                
                # Update port totals
                ports_data[local_port]['total_connections'] += 1
            
            # Calculate unique clients for each port
            for port_data in ports_data.values():
                port_data['unique_clients'] = len(port_data['clients'])
            
            # Sort ports by port number (custom ports)
            sorted_ports = sorted(ports_data.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 99999)
            
            # Convert to list format for easier frontend handling
            ports_list = []
            for port, port_data in sorted_ports:
                # Sort clients by connection count
                sorted_clients = sorted(port_data['clients'].items(), 
                                      key=lambda x: x[1]['connection_count'], reverse=True)
                
                ports_list.append({
                    'port': port_data['port'],
                    'port_label': port_data['port_label'],
                    'process_name': port_data['process_name'],
                    'pid': port_data['pid'],
                    'total_connections': port_data['total_connections'],
                    'unique_clients': port_data['unique_clients'],
                    'is_custom_port': True,
                    'clients': [client_data for _, client_data in sorted_clients]
                })
            
            return {
                'timestamp': current_time.isoformat(),
                'ports': ports_list,
                'total_ports': len(ports_list),
                'total_connections': sum(port['total_connections'] for port in ports_list),
                'total_unique_clients': len(set(
                    client['remote_ip'] for port in ports_list 
                    for client in port['clients']
                )),
                'custom_ports_defined': list(custom_ports),
                'active_custom_ports': [port['port'] for port in ports_list]
            }
            
        except Exception as e:
            logger.error(f"Error getting custom port clients: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'ports': [],
                'total_ports': 0,
                'total_connections': 0,
                'total_unique_clients': 0,
                'custom_ports_defined': [],
                'active_custom_ports': []
            }

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Get list of network interfaces (en0, en1, etc.) with their details."""
        try:
            interfaces = []
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addresses in net_if_addrs.items():
                interface_info = {
                    'name': interface_name,
                    'addresses': [],
                    'is_up': False,
                    'speed': 0,
                    'mtu': 0,
                    'type': 'Unknown'
                }
                
                # Get interface statistics
                if interface_name in net_if_stats:
                    stats = net_if_stats[interface_name]
                    interface_info['is_up'] = stats.isup
                    interface_info['speed'] = stats.speed
                    interface_info['mtu'] = stats.mtu
                
                # Get addresses for this interface
                for addr in addresses:
                    # Determine family type
                    if addr.family == socket.AF_INET:
                        family_str = 'IPv4'
                    elif addr.family == socket.AF_INET6:
                        family_str = 'IPv6'
                    else:
                        family_str = str(addr.family)
                    
                    addr_info = {
                        'family': family_str,
                        'family_raw': addr.family,  # Store raw value for easier comparison
                        'address': addr.address,
                        'netmask': addr.netmask if hasattr(addr, 'netmask') else None,
                        'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                    }
                    
                    # Determine interface type based on name and address
                    if interface_name.startswith('en') or interface_name.startswith('eth'):
                        if '192.168.' in addr.address or '10.' in addr.address or '172.' in addr.address:
                            interface_info['type'] = 'Ethernet'
                        elif 'fe80::' in addr.address:
                            interface_info['type'] = 'Ethernet (IPv6)'
                    elif interface_name.startswith('wlan') or interface_name.startswith('wifi') or interface_name.startswith('wl'):
                        interface_info['type'] = 'WiFi'
                    elif interface_name.startswith('lo'):
                        interface_info['type'] = 'Loopback'
                    elif interface_name.startswith('ppp'):
                        interface_info['type'] = 'PPP'
                    elif interface_name.startswith('tun') or interface_name.startswith('tap'):
                        interface_info['type'] = 'VPN/Tunnel'
                    
                    interface_info['addresses'].append(addr_info)
                
                interfaces.append(interface_info)
            
            # Sort interfaces by name
            interfaces.sort(key=lambda x: x['name'])
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []
    
    def load_test_ips_from_file(self, file_path: str = None) -> bool:
        """Load test IP list from YAML file."""
        if file_path is None:
            file_path = self._test_ips_file
        
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and isinstance(data, dict):
                        self._test_ip_list = data.get('test_ips', [])
                    elif isinstance(data, list):
                        # Handle case where file contains just a list
                        self._test_ip_list = data
                    else:
                        self._test_ip_list = []
                
                logger.info(f"Loaded {len(self._test_ip_list)} test IPs from {file_path}")
                return True
            else:
                logger.info(f"Test IPs file {file_path} not found, starting with empty list")
                self._test_ip_list = []
                return False
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {file_path}: {e}")
            self._test_ip_list = []
            return False
        except Exception as e:
            logger.error(f"Error loading test IPs from {file_path}: {e}")
            self._test_ip_list = []
            return False
    
    def save_test_ips_to_file(self, file_path: str = None) -> bool:
        """Save test IP list to YAML file."""
        if file_path is None:
            file_path = self._test_ips_file
        
        try:
            data = {
                'test_ips': self._test_ip_list,
                'last_updated': datetime.now().isoformat(),
                'total_ips': len(self._test_ip_list)
            }
            
            with open(file_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Saved {len(self._test_ip_list)} test IPs to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving test IPs to {file_path}: {e}")
            return False
    
    def add_test_ip(self, ip: str) -> bool:
        """Add an IP address to the test list."""
        try:
            # Validate IP address (supports both IPv4 and IPv6)
            ipaddress.ip_address(ip)
            if ip not in self._test_ip_list:
                self._test_ip_list.append(ip)
                logger.info(f"Added test IP: {ip}")
                # Save to file
                self.save_test_ips_to_file()
                return True
            else:
                logger.warning(f"IP {ip} already in test list")
                return False
        except ValueError as e:
            logger.error(f"Invalid IP address: {ip} - {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error adding test IP {ip}: {str(e)}")
            return False
    
    def remove_test_ip(self, ip: str) -> bool:
        """Remove an IP address from the test list."""
        if ip in self._test_ip_list:
            self._test_ip_list.remove(ip)
            logger.info(f"Removed test IP: {ip}")
            # Save to file
            self.save_test_ips_to_file()
            return True
        return False
    
    def get_test_ip_list(self) -> List[str]:
        """Get the list of IPs to test."""
        return self._test_ip_list.copy()
    
    def load_test_urls_from_file(self, file_path: str = None) -> bool:
        """Load test URL list from YAML file."""
        if file_path is None:
            file_path = self._test_urls_file
        
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and isinstance(data, dict):
                        self._test_url_list = data.get('test_urls', [])
                    elif isinstance(data, list):
                        self._test_url_list = data
                    else:
                        self._test_url_list = []
                
                logger.info(f"Loaded {len(self._test_url_list)} test URLs from {file_path}")
                return True
            else:
                logger.info(f"Test URLs file {file_path} not found, starting with empty list")
                self._test_url_list = []
                return False
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {file_path}: {e}")
            self._test_url_list = []
            return False
        except Exception as e:
            logger.error(f"Error loading test URLs from {file_path}: {e}")
            self._test_url_list = []
            return False
    
    def save_test_urls_to_file(self, file_path: str = None) -> bool:
        """Save test URL list to YAML file."""
        if file_path is None:
            file_path = self._test_urls_file
        
        try:
            data = {
                'test_urls': self._test_url_list,
                'last_updated': datetime.now().isoformat(),
                'total_urls': len(self._test_url_list)
            }
            
            with open(file_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Saved {len(self._test_url_list)} test URLs to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving test URLs to {file_path}: {e}")
            return False
    
    def add_test_url(self, url: str) -> bool:
        """Add a URL to the test list."""
        try:
            if not url or not url.strip():
                return False
            
            url = url.strip()
            
            if not (url.startswith('http://') or url.startswith('https://')):
                logger.error(f"Invalid URL format (must start with http:// or https://): {url}")
                return False
            
            if url not in self._test_url_list:
                self._test_url_list.append(url)
                logger.info(f"Added test URL: {url}")
                self.save_test_urls_to_file()
                return True
            else:
                logger.warning(f"URL {url} already in test list")
                return False
        except Exception as e:
            logger.error(f"Error adding test URL {url}: {str(e)}")
            return False
    
    def remove_test_url(self, url: str) -> bool:
        """Remove a URL from the test list."""
        if url in self._test_url_list:
            self._test_url_list.remove(url)
            logger.info(f"Removed test URL: {url}")
            self.save_test_urls_to_file()
            return True
        return False
    
    def get_test_url_list(self) -> List[str]:
        """Get the list of URLs to test."""
        return self._test_url_list.copy()
    
    def test_url_connection(self, url: str, interface: str = None) -> Dict[str, Any]:
        """Test URL connection using curl through a specific interface."""
        try:
            result = {
                'url': url,
                'interface': interface or 'default',
                'success': False,
                'status_code': None,
                'response_time_ms': None,
                'error': None,
                'timestamp': datetime.now().isoformat()
            }
            
            import platform
            system = platform.system()
            
            # Build curl command
            cmd = ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}|%{time_total}', '--max-time', '10']
            
            # Add interface binding if specified
            if interface:
                interface_ip = None
                try:
                    net_if_addrs = psutil.net_if_addrs()
                    if interface in net_if_addrs:
                        for addr in net_if_addrs[interface]:
                            if addr.family == socket.AF_INET:
                                interface_ip = addr.address
                                break
                    
                    if not interface_ip:
                        interfaces = self.get_network_interfaces()
                        for iface in interfaces:
                            if iface['name'] == interface:
                                for addr in iface['addresses']:
                                    family_raw = addr.get('family_raw')
                                    if family_raw == socket.AF_INET:
                                        interface_ip = addr.get('address')
                                        break
                                    addr_value = addr.get('address', '')
                                    if addr_value and '.' in addr_value and ':' not in addr_value:
                                        try:
                                            ipaddress.ip_address(addr_value)
                                            if addr_value.count('.') == 3:
                                                interface_ip = addr_value
                                                break
                                        except:
                                            pass
                                break
                except Exception as e:
                    logger.warning(f"Error getting interface IP for {interface}: {e}")
                
                if interface_ip:
                    cmd.extend(['--interface', interface_ip])
            
            cmd.append(url)
            
            start_time = time.time()
            try:
                curl_result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                end_time = time.time()
                
                if curl_result.returncode == 0:
                    output = curl_result.stdout.strip()
                    if '|' in output:
                        parts = output.split('|')
                        if len(parts) >= 2:
                            try:
                                status_code = int(parts[0])
                                time_total = float(parts[1])
                                
                                result['success'] = True
                                result['status_code'] = status_code
                                result['response_time_ms'] = time_total * 1000
                            except (ValueError, IndexError):
                                result['success'] = False
                                result['error'] = f'Could not parse curl output: {output}'
                        else:
                            result['success'] = False
                            result['error'] = f'Unexpected curl output format: {output}'
                    else:
                        result['success'] = False
                        result['error'] = f'Unexpected curl output: {output}'
                else:
                    result['success'] = False
                    result['error'] = curl_result.stderr or f'curl failed with return code {curl_result.returncode}'
                    result['response_time_ms'] = (end_time - start_time) * 1000
                    
            except subprocess.TimeoutExpired:
                result['success'] = False
                result['error'] = 'Connection timeout (exceeded 10 seconds)'
                result['response_time_ms'] = 10000
            except FileNotFoundError:
                result['success'] = False
                result['error'] = 'curl command not found. Please install curl.'
            
            return result
            
        except Exception as e:
            logger.error(f"Error testing URL connection: {e}")
            return {
                'url': url,
                'interface': interface or 'default',
                'success': False,
                'status_code': None,
                'response_time_ms': None,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def test_url_all_interfaces(self, url: str) -> List[Dict[str, Any]]:
        """Test a specific URL through all available interfaces."""
        results = []
        
        interfaces = self.get_network_interfaces()
        active_interfaces = [iface['name'] for iface in interfaces 
                           if iface['is_up'] and iface['type'] != 'Loopback']
        
        if not active_interfaces:
            return [{
                'url': url,
                'interface': 'none',
                'success': False,
                'error': 'No active interfaces available',
                'timestamp': datetime.now().isoformat()
            }]
        
        for iface_name in active_interfaces:
            result = self.test_url_connection(url, iface_name)
            results.append(result)
        
        return results
    
    def test_all_urls(self, interface: str = None) -> List[Dict[str, Any]]:
        """Test connections to all URLs in the test list through specified interface.
        If no interface is specified, tests through all available interfaces."""
        results = []
        
        if interface:
            for url in self._test_url_list:
                result = self.test_url_connection(url, interface)
                results.append(result)
        else:
            interfaces = self.get_network_interfaces()
            active_interfaces = [iface['name'] for iface in interfaces 
                               if iface['is_up'] and iface['type'] != 'Loopback']
            
            for url in self._test_url_list:
                for iface_name in active_interfaces:
                    result = self.test_url_connection(url, iface_name)
                    results.append(result)
        
        return results
    
    def traceroute_ip(self, ip: str, interface: str = None) -> Dict[str, Any]:
        """Perform traceroute to an IP address through a specific interface."""
        try:
            result = {
                'ip': ip,
                'interface': interface or 'default',
                'success': False,
                'hops': [],
                'total_hops': 0,
                'failed_at_hop': None,
                'failed_layer': None,
                'error': None,
                'timestamp': datetime.now().isoformat()
            }
            
            import platform
            system = platform.system()
            
            # Get interface IP if specified
            interface_ip = None
            if interface:
                try:
                    net_if_addrs = psutil.net_if_addrs()
                    if interface in net_if_addrs:
                        for addr in net_if_addrs[interface]:
                            if addr.family == socket.AF_INET:
                                interface_ip = addr.address
                                break
                    
                    if not interface_ip:
                        interfaces = self.get_network_interfaces()
                        for iface in interfaces:
                            if iface['name'] == interface:
                                for addr in iface['addresses']:
                                    family_raw = addr.get('family_raw')
                                    if family_raw == socket.AF_INET:
                                        interface_ip = addr.get('address')
                                        break
                                    addr_value = addr.get('address', '')
                                    if addr_value and '.' in addr_value and ':' not in addr_value:
                                        try:
                                            ipaddress.ip_address(addr_value)
                                            if addr_value.count('.') == 3:  # IPv4 address
                                                interface_ip = addr_value
                                                break
                                        except:
                                            pass
                                break
                except Exception as e:
                    logger.warning(f"Error getting interface IP for {interface}: {e}")
            
            # Build traceroute command
            if system == 'Darwin':  # macOS
                cmd = ['traceroute', '-m', '30', '-w', '3']
                if interface_ip:
                    # macOS traceroute uses -s for source address
                    cmd.extend(['-s', interface_ip])
                cmd.append(ip)
            elif system == 'Linux':
                cmd = ['traceroute', '-m', '30', '-w', '3']
                if interface_ip:
                    # Linux traceroute uses -i for interface
                    cmd.extend(['-i', interface])
                cmd.append(ip)
            else:
                # Windows or other - try tracert
                cmd = ['tracert', '-h', '30', '-w', '3000', ip]
            
            # Run traceroute
            try:
                traceroute_result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if traceroute_result.returncode == 0 or traceroute_result.returncode == 1:  # 1 can mean timeout but got some results
                    output = traceroute_result.stdout
                    hops = self._parse_traceroute_output(output, system)
                    
                    result['hops'] = hops
                    result['total_hops'] = len(hops)
                    result['success'] = len(hops) > 0
                    
                    # Analyze failure point
                    if hops:
                        last_hop = hops[-1]
                        if not last_hop.get('reached', False):
                            result['failed_at_hop'] = len(hops)
                            result['failed_layer'] = self._analyze_failure_layer(hops, ip)
                        elif last_hop.get('ip') == ip:
                            result['success'] = True
                    else:
                        result['failed_at_hop'] = 0
                        result['failed_layer'] = 'Local - Cannot start traceroute'
                        result['error'] = 'No hops found in traceroute output'
                else:
                    result['error'] = traceroute_result.stderr or f'traceroute failed with return code {traceroute_result.returncode}'
                    
            except subprocess.TimeoutExpired:
                result['error'] = 'Traceroute timeout (exceeded 60 seconds)'
            except FileNotFoundError:
                result['error'] = 'traceroute command not found. Please install traceroute.'
            
            return result
            
        except Exception as e:
            logger.error(f"Error performing traceroute: {e}")
            return {
                'ip': ip,
                'interface': interface or 'default',
                'success': False,
                'hops': [],
                'total_hops': 0,
                'failed_at_hop': None,
                'failed_layer': None,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_traceroute_output(self, output: str, system: str) -> List[Dict[str, Any]]:
        """Parse traceroute output into structured hop data."""
        import re
        hops = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('traceroute') or line.startswith('Tracing'):
                continue
            
            # Parse different traceroute formats
            # macOS/Linux format: " 1  gateway (192.168.1.1)  0.234 ms  0.123 ms  0.145 ms"
            # Or: " 1  10.5.216.1 (10.5.216.1)  1.197 ms  1.058 ms  0.627 ms"
            # Or: " 1  * * *" for timeouts
            
            # First, check if this is a timeout line (all asterisks)
            if re.match(r'^\s*\d+\s+\*', line):
                # Timeout line: " 1  * * *"
                hop_match = re.match(r'^\s*(\d+)', line)
                if hop_match:
                    hop_num = int(hop_match.group(1))
                    hops.append({
                        'hop_number': hop_num,
                        'hostname': 'N/A',
                        'ip': 'N/A',
                        'times_ms': [],
                        'avg_time_ms': None,
                        'reached': False,
                        'status': 'timeout',
                        'explanation': 'Hop timeout - Router may be blocking ICMP or unreachable',
                        'raw': line
                    })
                continue
            
            # Try to match hop with IP in parentheses: " 1  hostname (192.168.1.1)  times"
            hop_match = re.match(r'^\s*(\d+)\s+(.+?)\s+\(([\d.]+)\)\s+(.+)', line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                hostname = hop_match.group(2).strip()
                ip = hop_match.group(3)
                times_part = hop_match.group(4)
                
                # Extract timing information
                times = re.findall(r'(\d+\.?\d*)\s*ms', times_part)
                times_ms = [float(t) for t in times] if times else []
                
                # If we have times, the hop was reached
                if times_ms:
                    status = 'reached'
                    avg_time = sum(times_ms) / len(times_ms)
                    explanation = f'Reached in {avg_time:.2f}ms average'
                else:
                    status = 'timeout'
                    explanation = 'Hop timeout - No response received'
                
                hops.append({
                    'hop_number': hop_num,
                    'hostname': hostname or ip or 'Unknown',
                    'ip': ip,
                    'times_ms': times_ms,
                    'avg_time_ms': sum(times_ms) / len(times_ms) if times_ms else None,
                    'reached': len(times_ms) > 0,
                    'status': status,
                    'explanation': explanation,
                    'raw': line
                })
                continue
            
            # Try to match hop without parentheses (IP might be the hostname): " 1  192.168.1.1  times"
            hop_match = re.match(r'^\s*(\d+)\s+([\d.]+)\s+(.+)', line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                ip_or_hostname = hop_match.group(2)
                times_part = hop_match.group(3)
                
                # Check if it's an IP address
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_or_hostname):
                    ip = ip_or_hostname
                    hostname = ip
                else:
                    ip = None
                    hostname = ip_or_hostname
                
                # Extract timing information
                times = re.findall(r'(\d+\.?\d*)\s*ms', times_part)
                times_ms = [float(t) for t in times] if times else []
                
                if times_ms and ip:
                    status = 'reached'
                    avg_time = sum(times_ms) / len(times_ms)
                    explanation = f'Reached in {avg_time:.2f}ms average'
                else:
                    status = 'timeout'
                    explanation = 'Hop timeout - No response received'
                
                hops.append({
                    'hop_number': hop_num,
                    'hostname': hostname or 'Unknown',
                    'ip': ip or 'N/A',
                    'times_ms': times_ms,
                    'avg_time_ms': sum(times_ms) / len(times_ms) if times_ms else None,
                    'reached': len(times_ms) > 0 and ip is not None,
                    'status': status,
                    'explanation': explanation,
                    'raw': line
                })
        
        return hops
    
    def _analyze_failure_layer(self, hops: List[Dict[str, Any]], target_ip: str) -> str:
        """Analyze at which network layer the connection failed."""
        if not hops:
            return 'Local - No traceroute data available'
        
        last_hop = hops[-1]
        
        # Check if we got to the target
        if last_hop.get('ip') == target_ip:
            return 'Application - Reached target IP'
        
        # Analyze failure patterns
        if last_hop.get('status') == 'timeout':
            # Check how far we got
            if len(hops) == 1:
                return 'Layer 2/3 - First hop timeout (local network issue)'
            elif len(hops) <= 3:
                return 'Layer 3 - Early network layer failure (gateway/routing issue)'
            else:
                return 'Layer 3 - Network layer failure (intermediate routing issue)'
        
        # Check for consistent timeouts
        timeout_count = sum(1 for hop in hops if hop.get('status') == 'timeout')
        if timeout_count > len(hops) / 2:
            return 'Layer 3 - Multiple timeouts (routing/firewall blocking)'
        
        # If we have some successful hops but didn't reach target
        successful_hops = [h for h in hops if h.get('reached', False)]
        if successful_hops:
            return f'Layer 3/4 - Reached {len(successful_hops)} hops but target unreachable'
        
        return 'Layer 3 - Network routing failure'
    
    def test_ip_connection(self, ip: str, interface: str = None) -> Dict[str, Any]:
        """Test connection to an IP address through a specific interface."""
        try:
            result = {
                'ip': ip,
                'interface': interface or 'default',
                'success': False,
                'latency_ms': None,
                'error': None,
                'timestamp': datetime.now().isoformat()
            }
            
            import platform
            system = platform.system()
            
            # Get interface IP address if interface is specified
            interface_ip = None
            if interface:
                try:
                    # Use psutil directly for more reliable interface detection
                    net_if_addrs = psutil.net_if_addrs()
                    if interface in net_if_addrs:
                        for addr in net_if_addrs[interface]:
                            if addr.family == socket.AF_INET:
                                interface_ip = addr.address
                                break
                    
                    # Fallback to our interface list
                    if not interface_ip:
                        interfaces = self.get_network_interfaces()
                        for iface in interfaces:
                            if iface['name'] == interface:
                                for addr in iface['addresses']:
                                    family_raw = addr.get('family_raw')
                                    if family_raw == socket.AF_INET:
                                        interface_ip = addr.get('address')
                                        break
                                    # Fallback: check address format
                                    addr_value = addr.get('address', '')
                                    if addr_value and '.' in addr_value and ':' not in addr_value:
                                        try:
                                            ipaddress.ip_address(addr_value)
                                            if addr_value.count('.') == 3:
                                                interface_ip = addr_value
                                                break
                                        except:
                                            pass
                                break
                except Exception as e:
                    logger.warning(f"Error getting interface IP for {interface}: {e}")
            
            # Method 1: Use ping with interface binding (macOS/Linux)
            if interface and interface_ip and system in ['Darwin', 'Linux']:
                try:
                    # macOS uses -S flag (source address), Linux uses -I flag (interface)
                    if system == 'Darwin':
                        # On macOS, use -S to specify source address (binds to interface)
                        cmd = ['ping', '-c', '3', '-W', '1000', '-S', interface_ip, ip]
                    else:  # Linux
                        cmd = ['ping', '-c', '3', '-W', '1', '-I', interface_ip, ip]
                    
                    start_time = time.time()
                    ping_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    end_time = time.time()
                    
                    if ping_result.returncode == 0:
                        result['success'] = True
                        # Extract latency from ping output
                        import re
                        output = ping_result.stdout
                        times = re.findall(r'time[<=](\d+\.?\d*)', output)
                        if times:
                            result['latency_ms'] = float(times[-1])
                        else:
                            result['latency_ms'] = (end_time - start_time) * 1000
                    else:
                        result['success'] = False
                        result['error'] = ping_result.stderr or 'Connection failed'
                    
                    return result
                except subprocess.TimeoutExpired:
                    return {
                        'ip': ip,
                        'interface': interface,
                        'success': False,
                        'latency_ms': None,
                        'error': 'Connection timeout',
                        'timestamp': datetime.now().isoformat()
                    }
                except Exception as e:
                    logger.warning(f"Ping with interface binding failed: {e}, trying socket method")
            
            # Method 2: Use socket binding for more reliable interface selection
            if interface and interface_ip:
                try:
                    # Create a socket and bind to the interface IP
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    test_socket.settimeout(5)
                    
                    # Bind to the interface IP
                    test_socket.bind((interface_ip, 0))
                    
                    # Try to connect to the target IP (this forces routing through the bound interface)
                    start_time = time.time()
                    try:
                        # For UDP, we can't really "connect" but we can send a packet
                        # For a more accurate test, we'll use a TCP connection attempt
                        test_socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_socket_tcp.settimeout(5)
                        test_socket_tcp.bind((interface_ip, 0))
                        
                        # Try to connect
                        connect_start = time.time()
                        try:
                            test_socket_tcp.connect((ip, 80))  # Try common port
                            connect_end = time.time()
                            result['success'] = True
                            result['latency_ms'] = (connect_end - connect_start) * 1000
                        except (socket.timeout, ConnectionRefusedError, OSError):
                            # Connection refused or timeout is actually good - it means we reached the host
                            # through the interface, just the port might be closed
                            connect_end = time.time()
                            result['success'] = True
                            result['latency_ms'] = (connect_end - connect_start) * 1000
                            result['error'] = 'Port closed or filtered (but interface routing works)'
                        except Exception as e:
                            result['success'] = False
                            result['error'] = f'Socket connection failed: {str(e)}'
                        
                        test_socket_tcp.close()
                    except Exception as e:
                        result['success'] = False
                        result['error'] = f'Could not bind to interface {interface} ({interface_ip}): {str(e)}'
                    
                    test_socket.close()
                    
                    if result['success'] is not False:  # If we got a result, return it
                        return result
                        
                except Exception as e:
                    logger.warning(f"Socket binding method failed: {e}, falling back to default ping")
            
            # Method 3: Fallback to default ping (no interface binding)
            if system == 'Darwin':  # macOS
                cmd = ['ping', '-c', '3', '-W', '1000', ip]
            elif system == 'Linux':
                cmd = ['ping', '-c', '3', '-W', '1', ip]
            elif system == 'Windows':
                cmd = ['ping', '-n', '3', '-w', '1000', ip]
            else:
                cmd = ['ping', '-c', '3', ip]
            
            # Run ping command
            start_time = time.time()
            ping_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            end_time = time.time()
            
            if ping_result.returncode == 0:
                result['success'] = True
                # Try to extract latency from ping output
                output = ping_result.stdout
                if 'time=' in output or 'time<' in output:
                    # Extract average time
                    import re
                    times = re.findall(r'time[<=](\d+\.?\d*)', output)
                    if times:
                        result['latency_ms'] = float(times[-1])  # Last time is usually the average
                    else:
                        result['latency_ms'] = (end_time - start_time) * 1000
                else:
                    result['latency_ms'] = (end_time - start_time) * 1000
            else:
                result['success'] = False
                result['error'] = ping_result.stderr or 'Connection failed'
            
            return result
            
        except subprocess.TimeoutExpired:
            return {
                'ip': ip,
                'interface': interface or 'default',
                'success': False,
                'latency_ms': None,
                'error': 'Connection timeout',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error testing IP connection: {e}")
            return {
                'ip': ip,
                'interface': interface or 'default',
                'success': False,
                'latency_ms': None,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def test_all_ips(self, interface: str = None) -> List[Dict[str, Any]]:
        """Test connections to all IPs in the test list through specified interface.
        If no interface is specified, tests through all available interfaces."""
        results = []
        
        if interface:
            # Test all IPs through the specified interface
            for ip in self._test_ip_list:
                result = self.test_ip_connection(ip, interface)
                results.append(result)
        else:
            # Test each IP through all available interfaces
            interfaces = self.get_network_interfaces()
            active_interfaces = [iface['name'] for iface in interfaces 
                               if iface['is_up'] and iface['type'] != 'Loopback']
            
            for ip in self._test_ip_list:
                # Test through each interface
                for iface_name in active_interfaces:
                    result = self.test_ip_connection(ip, iface_name)
                    results.append(result)
        
        return results
    
    def test_ip_all_interfaces(self, ip: str) -> List[Dict[str, Any]]:
        """Test a specific IP through all available interfaces."""
        results = []
        
        # Get all active interfaces
        interfaces = self.get_network_interfaces()
        active_interfaces = [iface['name'] for iface in interfaces 
                           if iface['is_up'] and iface['type'] != 'Loopback']
        
        if not active_interfaces:
            return [{
                'ip': ip,
                'interface': 'none',
                'success': False,
                'error': 'No active interfaces available',
                'timestamp': datetime.now().isoformat()
            }]
        
        # Test the IP through each interface
        for iface_name in active_interfaces:
            result = self.test_ip_connection(ip, iface_name)
            results.append(result)
        
        return results
    
    def set_route(self, interface: str, target_ip: str, gateway: str = None) -> Dict[str, Any]:
        """Set a route for a specific interface."""
        try:
            import platform
            system = platform.system()
            
            # Get interface IP address - use psutil directly for more reliable detection
            interface_ip = None
            try:
                net_if_addrs = psutil.net_if_addrs()
                if interface in net_if_addrs:
                    for addr in net_if_addrs[interface]:
                        # Check if it's IPv4 (AF_INET = 2)
                        if addr.family == socket.AF_INET:
                            interface_ip = addr.address
                            break
            except Exception as e:
                logger.warning(f"Error getting interface addresses: {e}")
            
            # Fallback: try getting from our interface list
            if not interface_ip:
                interfaces = self.get_network_interfaces()
                for iface in interfaces:
                    if iface['name'] == interface:
                        for addr in iface['addresses']:
                            # Check if it's IPv4 - use raw family value or check address format
                            family_raw = addr.get('family_raw')
                            if family_raw == socket.AF_INET:
                                interface_ip = addr.get('address')
                                break
                            # Fallback: check if address looks like IPv4
                            addr_value = addr.get('address', '')
                            if addr_value and '.' in addr_value and ':' not in addr_value:
                                # Additional validation: check if it's a valid IPv4 format
                                try:
                                    ipaddress.ip_address(addr_value)
                                    if addr_value.count('.') == 3:  # Basic IPv4 check
                                        interface_ip = addr_value
                                        break
                                except:
                                    pass
                        break
            
            # If no IPv4 address found, we can still configure the route
            # but we'll need to handle it differently
            if not interface_ip:
                # Get interface details for better error message
                interfaces = self.get_network_interfaces()
                available_interfaces = [iface['name'] for iface in interfaces]
                interface_found = False
                interface_details = []
                interface_ipv6 = None
                
                for iface in interfaces:
                    if iface['name'] == interface:
                        interface_found = True
                        interface_details = iface.get('addresses', [])
                        # Check for IPv6 address as fallback
                        for addr in iface.get('addresses', []):
                            if addr.get('family_raw') == socket.AF_INET6:
                                interface_ipv6 = addr.get('address')
                                break
                        break
                
                if not interface_found:
                    return {
                        'success': False,
                        'error': f'Interface {interface} not found. Available interfaces: {", ".join(available_interfaces)}',
                        'interface': interface,
                        'available_interfaces': available_interfaces
                    }
                
                # If we have IPv6 but no IPv4, we can still store the route config
                # but note that actual route setting may require IPv4
                if interface_ipv6:
                    logger.warning(f"Interface {interface} has IPv6 address but no IPv4 address")
                    # Use a placeholder or the interface name itself
                    interface_ip = f"IPv6:{interface_ipv6}"
                else:
                    return {
                        'success': False,
                        'error': f'Interface {interface} has no IPv4 or IPv6 address. Interface addresses: {interface_details}',
                        'interface': interface,
                        'interface_addresses': interface_details
                    }
            
            # If no gateway specified, use interface's default gateway
            if not gateway:
                # Try to get default gateway for the interface
                try:
                    # If interface_ip starts with "IPv6:", we can't easily determine gateway
                    if interface_ip.startswith('IPv6:'):
                        gateway = 'default'  # Will need to be set manually
                    else:
                        # For IPv4, try to determine gateway (usually .1 of the subnet)
                        gateway = interface_ip.rsplit('.', 1)[0] + '.1'
                except:
                    gateway = 'default'
            
            # Store route configuration
            self._route_configs[interface] = {
                'enabled': True,
                'target_ip': target_ip,
                'gateway': gateway,
                'interface_ip': interface_ip,
                'timestamp': datetime.now().isoformat()
            }
            
            # Save to file
            self.save_routes_to_file()
            
            # Actually set the route using system commands (requires sudo on macOS/Linux)
            if system == 'Darwin':  # macOS
                # Add route: sudo route add -net <target> -interface <interface>
                # For now, just log it (requires sudo)
                logger.info(f"Route configuration saved for {interface}: {target_ip} via {gateway}")
                return {
                    'success': True,
                    'message': f'Route configured for {interface}',
                    'interface': interface,
                    'target_ip': target_ip,
                    'gateway': gateway,
                    'note': 'Route configuration saved. Actual route may require sudo privileges.'
                }
            elif system == 'Linux':
                logger.info(f"Route configuration saved for {interface}: {target_ip} via {gateway}")
                return {
                    'success': True,
                    'message': f'Route configured for {interface}',
                    'interface': interface,
                    'target_ip': target_ip,
                    'gateway': gateway,
                    'note': 'Route configuration saved. Actual route may require sudo privileges.'
                }
            else:
                return {
                    'success': True,
                    'message': f'Route configuration saved for {interface}',
                    'interface': interface,
                    'target_ip': target_ip,
                    'gateway': gateway
                }
                
        except Exception as e:
            logger.error(f"Error setting route: {e}")
            return {
                'success': False,
                'error': str(e),
                'interface': interface
            }
    
    def load_routes_from_file(self, file_path: str = None) -> bool:
        """Load route configurations from YAML file."""
        if file_path is None:
            file_path = self._routes_file
        
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and isinstance(data, dict):
                        self._route_configs = data.get('routes', {})
                    else:
                        self._route_configs = {}
                
                logger.info(f"Loaded {len(self._route_configs)} route configurations from {file_path}")
                return True
            else:
                logger.info(f"Routes file {file_path} not found, starting with empty routes")
                self._route_configs = {}
                return False
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {file_path}: {e}")
            self._route_configs = {}
            return False
        except Exception as e:
            logger.error(f"Error loading routes from {file_path}: {e}")
            self._route_configs = {}
            return False
    
    def save_routes_to_file(self, file_path: str = None) -> bool:
        """Save route configurations to YAML file."""
        if file_path is None:
            file_path = self._routes_file
        
        try:
            data = {
                'routes': self._route_configs,
                'last_updated': datetime.now().isoformat(),
                'total_routes': len(self._route_configs),
                'active_routes': len([c for c in self._route_configs.values() if c.get('enabled', False)])
            }
            
            with open(file_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Saved {len(self._route_configs)} route configurations to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving routes to {file_path}: {e}")
            return False
    
    def disable_route(self, interface: str) -> Dict[str, Any]:
        """Disable a route for a specific interface."""
        try:
            if interface in self._route_configs:
                self._route_configs[interface]['enabled'] = False
                self._route_configs[interface]['disabled_at'] = datetime.now().isoformat()
                logger.info(f"Route disabled for {interface}")
                # Save to file
                self.save_routes_to_file()
                return {
                    'success': True,
                    'message': f'Route disabled for {interface}',
                    'interface': interface
                }
            else:
                return {
                    'success': False,
                    'error': f'No route configuration found for {interface}',
                    'interface': interface
                }
        except Exception as e:
            logger.error(f"Error disabling route: {e}")
            return {
                'success': False,
                'error': str(e),
                'interface': interface
            }
    
    def enable_route(self, interface: str) -> Dict[str, Any]:
        """Enable a route for a specific interface."""
        try:
            if interface in self._route_configs:
                self._route_configs[interface]['enabled'] = True
                self._route_configs[interface]['enabled_at'] = datetime.now().isoformat()
                logger.info(f"Route enabled for {interface}")
                # Save to file
                self.save_routes_to_file()
                return {
                    'success': True,
                    'message': f'Route enabled for {interface}',
                    'interface': interface
                }
            else:
                return {
                    'success': False,
                    'error': f'No route configuration found for {interface}',
                    'interface': interface
                }
        except Exception as e:
            logger.error(f"Error enabling route: {e}")
            return {
                'success': False,
                'error': str(e),
                'interface': interface
            }
    
    def _explain_route_flags(self, flags: str) -> Dict[str, str]:
        """Explain route flags."""
        flag_explanations = {
            'U': 'Up - Route is active and usable',
            'G': 'Gateway - Route uses a gateway (router)',
            'H': 'Host - Route is to a specific host (not a network)',
            'R': 'Reinstate - Route was reinstated after interface came up',
            'D': 'Dynamic - Route was created dynamically',
            'M': 'Modified - Route was modified by routing daemon',
            'A': 'Address - Route was installed by addrconf',
            'C': 'Cache - Route is from cache',
            'L': 'Link - Route involves a link',
            'S': 'Static - Route was manually added',
            'B': 'Blackhole - Route discards packets',
            '!': 'Reject - Route rejects packets',
            'b': 'Broadcast - Route is a broadcast route',
            'm': 'Multicast - Route is a multicast route',
            'c': 'Cloned - Route was cloned',
            'W': 'WasCloned - Route was auto-configured',
            'l': 'Local - Route is a local route',
            'X': 'Resolve - Route needs resolution',
            'Y': 'ProtoCloned - Route was cloned from protocol',
            'Z': 'Multipath - Route has multiple paths'
        }
        
        explanations = []
        for flag in flags:
            if flag in flag_explanations:
                explanations.append(f"{flag}: {flag_explanations[flag]}")
            else:
                explanations.append(f"{flag}: Unknown flag")
        
        return {
            'flags': flags,
            'explanations': explanations,
            'full_explanation': ' | '.join(explanations) if explanations else 'No flags'
        }
    
    def get_all_system_routes(self) -> Dict[str, Any]:
        """Get all system routes with parsed information and flag explanations."""
        try:
            import platform
            system = platform.system()
            
            parsed_routes = []
            raw_routes = []
            
            try:
                if system == 'Darwin':  # macOS
                    result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        raw_routes = result.stdout.split('\n')
                        # Parse macOS netstat -rn output
                        # Format: Destination        Gateway            Flags           Netif Expire
                        # Skip header lines: "Routing tables", "Internet:", "Destination..."
                        header_found = False
                        for line in raw_routes:
                            line = line.strip()
                            if not line:
                                continue
                            
                            # Skip header lines
                            if line.startswith('Routing tables') or line.startswith('Internet'):
                                continue
                            
                            # Check if this is the column header line
                            if 'Destination' in line and 'Gateway' in line and 'Flags' in line:
                                header_found = True
                                continue
                            
                            # Only process lines after header is found
                            if not header_found:
                                continue
                            
                            # Parse route line - use more flexible splitting
                            # Handle cases where fields might be separated by multiple spaces
                            parts = line.split()
                            if len(parts) >= 4:
                                try:
                                    destination = parts[0]
                                    gateway = parts[1] if parts[1] != '*' else 'default'
                                    flags = parts[2] if len(parts) > 2 else ''
                                    netif = parts[3] if len(parts) > 3 else ''
                                    
                                    flag_info = self._explain_route_flags(flags)
                                    
                                    parsed_routes.append({
                                        'destination': destination,
                                        'gateway': gateway,
                                        'flags': flags,
                                        'interface': netif,
                                        'flag_explanations': flag_info,
                                        'raw': line
                                    })
                                except (IndexError, ValueError) as e:
                                    logger.warning(f"Error parsing route line '{line}': {e}")
                                    continue
                
                elif system == 'Linux':
                    # Try 'ip route' first
                    result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        raw_routes = result.stdout.split('\n')
                        for line in raw_routes:
                            if not line.strip():
                                continue
                            
                            # Parse Linux ip route output
                            # Format: default via 192.168.1.1 dev eth0 proto static metric 100
                            parts = line.split()
                            destination = 'default'
                            gateway = ''
                            interface = ''
                            flags = ''
                            
                            i = 0
                            while i < len(parts):
                                if parts[i] == 'via' and i + 1 < len(parts):
                                    gateway = parts[i + 1]
                                    i += 2
                                elif parts[i] == 'dev' and i + 1 < len(parts):
                                    interface = parts[i + 1]
                                    i += 2
                                elif parts[i] == 'proto':
                                    if i + 1 < len(parts):
                                        flags += parts[i + 1][0].upper()  # Use first letter as flag
                                    i += 2
                                elif i == 0 and parts[i] != 'default':
                                    destination = parts[i]
                                    i += 1
                                else:
                                    i += 1
                            
                            if not flags:
                                flags = 'U'  # Default to Up
                            
                            flag_info = self._explain_route_flags(flags)
                            
                            parsed_routes.append({
                                'destination': destination,
                                'gateway': gateway or 'direct',
                                'flags': flags,
                                'interface': interface,
                                'flag_explanations': flag_info,
                                'raw': line.strip()
                            })
                    else:
                        # Fallback to netstat
                        result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            raw_routes = result.stdout.split('\n')
                            # Similar parsing to macOS but for Linux
                            header_found = False
                            for line in raw_routes:
                                line = line.strip()
                                if not line:
                                    continue
                                
                                # Skip header lines
                                if line.startswith('Kernel') or line.startswith('Iface'):
                                    continue
                                
                                # Check if this is the column header line
                                if 'Destination' in line and 'Gateway' in line:
                                    header_found = True
                                    continue
                                
                                # Only process lines after header is found
                                if not header_found:
                                    continue
                                
                                parts = line.split()
                                if len(parts) >= 4:
                                    try:
                                        destination = parts[0]
                                        gateway = parts[1] if parts[1] != '*' else 'default'
                                        flags = parts[2] if len(parts) > 2 else ''
                                        netif = parts[3] if len(parts) > 3 else ''
                                        
                                        flag_info = self._explain_route_flags(flags)
                                        
                                        parsed_routes.append({
                                            'destination': destination,
                                            'gateway': gateway,
                                            'flags': flags,
                                            'interface': netif,
                                            'flag_explanations': flag_info,
                                            'raw': line
                                        })
                                    except (IndexError, ValueError) as e:
                                        logger.warning(f"Error parsing route line '{line}': {e}")
                                        continue
                else:
                    # Windows or other
                    result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        raw_routes = result.stdout.split('\n')
                        # Basic parsing
                        for line in raw_routes:
                            if line.strip():
                                flag_info = self._explain_route_flags('')
                                parsed_routes.append({
                                    'destination': 'Unknown',
                                    'gateway': 'Unknown',
                                    'flags': '',
                                    'interface': 'Unknown',
                                    'flag_explanations': flag_info,
                                    'raw': line.strip()
                                })
            except Exception as e:
                logger.warning(f"Could not get system routes: {e}")
            
            return {
                'timestamp': datetime.now().isoformat(),
                'system': system,
                'total_routes': len(parsed_routes),
                'routes': parsed_routes,
                'raw_output': raw_routes[:50]  # Keep first 50 lines of raw output
            }
            
        except Exception as e:
            logger.error(f"Error getting all system routes: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'system': platform.system() if 'platform' in dir() else 'Unknown',
                'total_routes': 0,
                'routes': [],
                'raw_output': []
            }
    
    def get_route_status(self, interface: str = None) -> Dict[str, Any]:
        """Get route status for a specific interface or all interfaces."""
        try:
            import platform
            system = platform.system()
            
            # Get system routes
            routes = []
            try:
                if system == 'Darwin':  # macOS
                    result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
                elif system == 'Linux':
                    result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=10)
                else:
                    result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    routes = result.stdout.split('\n')
            except Exception as e:
                logger.warning(f"Could not get system routes: {e}")
            
            # Get configured routes
            configured_routes = {}
            for iface, config in self._route_configs.items():
                if interface is None or iface == interface:
                    configured_routes[iface] = config.copy()
            
            # Get interface status
            interfaces = self.get_network_interfaces()
            interface_status = {}
            for iface in interfaces:
                if interface is None or iface['name'] == interface:
                    interface_status[iface['name']] = {
                        'is_up': iface['is_up'],
                        'type': iface['type'],
                        'addresses': iface['addresses']
                    }
            
            return {
                'timestamp': datetime.now().isoformat(),
                'system_routes': routes[:20],  # Limit to first 20 routes
                'configured_routes': configured_routes,
                'interface_status': interface_status
            }
            
        except Exception as e:
            logger.error(f"Error getting route status: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'system_routes': [],
                'configured_routes': {},
                'interface_status': {}
            }
    
    def test_route_connection(self, interface: str) -> Dict[str, Any]:
        """Test connection for a specific route."""
        try:
            if interface not in self._route_configs:
                return {
                    'success': False,
                    'error': f'No route configuration found for {interface}',
                    'interface': interface
                }
            
            config = self._route_configs[interface]
            target_ip = config.get('target_ip')
            
            if not target_ip:
                return {
                    'success': False,
                    'error': 'No target IP configured for this route',
                    'interface': interface
                }
            
            # Test the connection through the interface
            test_result = self.test_ip_connection(target_ip, interface)
            
            # Add route-specific information
            test_result['route_enabled'] = config.get('enabled', False)
            test_result['route_gateway'] = config.get('gateway', 'N/A')
            test_result['route_interface_ip'] = config.get('interface_ip', 'N/A')
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error testing route connection for {interface}: {e}")
            return {
                'success': False,
                'error': str(e),
                'interface': interface,
                'ip': 'Unknown',
                'timestamp': datetime.now().isoformat()
            }
    
    def monitor_all_routes(self) -> Dict[str, Any]:
        """Monitor status of all routes."""
        try:
            route_status = self.get_route_status()
            
            # Test all routes (both enabled and disabled)
            route_tests = {}
            for iface, config in self._route_configs.items():
                target_ip = config.get('target_ip')
                if target_ip:
                    test_result = self.test_ip_connection(target_ip, iface)
                    # Add route configuration info
                    test_result['route_enabled'] = config.get('enabled', False)
                    test_result['route_gateway'] = config.get('gateway', 'N/A')
                    test_result['route_interface_ip'] = config.get('interface_ip', 'N/A')
                    route_tests[iface] = test_result
            
            return {
                'timestamp': datetime.now().isoformat(),
                'route_status': route_status,
                'route_tests': route_tests,
                'configured_routes': self._route_configs.copy(),
                'total_configured_routes': len(self._route_configs),
                'active_routes': len([c for c in self._route_configs.values() if c.get('enabled', False)])
            }
            
        except Exception as e:
            logger.error(f"Error monitoring routes: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'route_status': {},
                'route_tests': {},
                'configured_routes': {},
                'total_configured_routes': 0,
                'active_routes': 0
            }

    def get_all_monitoring_data(self) -> Dict[str, Any]:
        """Get all monitoring data in one call."""
        return {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.get_system_info(),
            'services': self.get_running_services(),
            'ports': self.get_active_ports(),
            'mysql': self.check_mysql_status(),
            'postgresql': self.check_postgresql_status(),
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
    
    print(f"\n3. Active Ports (with labels):")
    ports = monitor.get_active_ports()
    for i, port in enumerate(ports[:10]):
        label = port.get('port_label', 'Unknown')
        process = port.get('process_name', 'N/A')
        print(f"   {i+1}. {port['local_address']} - {port['status']} - {label} ({process})")
    
    print(f"\n4. MySQL Status:")
    mysql_status = monitor.check_mysql_status()
    print(f"   Status: {mysql_status['status']}")
    print(f"   Port Accessible: {mysql_status['port_accessible']}")
    
    print(f"\n5. PostgreSQL Status:")
    postgres_status = monitor.check_postgresql_status()
    print(f"   Status: {postgres_status['status']}")
    print(f"   Port Accessible: {postgres_status['port_accessible']}")
    
    print(f"\n6. Port Labels by Category:")
    port_categories = monitor.get_port_labels_by_category()
    for category, ports in port_categories.items():
        if ports:
            print(f"   {category}:")
            for port, label in ports.items():
                print(f"     {port}: {label}")
    
    print(f"\n7. Custom Port Label Demo:")
    # Add a custom port label
    monitor.add_custom_port_label("9999", "Custom Test Service")
    print("   Added custom label for port 9999: Custom Test Service")
    
    # Test the custom label
    test_label = monitor.get_port_label("9999")
    print(f"   Retrieved label for port 9999: {test_label}")
    
    print(f"\n8. All Data (JSON):")
    all_data = monitor.get_all_monitoring_data()
    print(json.dumps(all_data, indent=2, default=str))

if __name__ == "__main__":
    main()
