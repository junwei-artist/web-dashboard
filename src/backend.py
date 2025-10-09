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
        self._psutil_access_warned = False  # Track if we've already warned about psutil access
        self._fallback_error_logged = False  # Track if we've already logged fallback errors
        self._port_labels = self._initialize_port_labels()
        # Load custom labels from configuration file
        self.load_custom_labels_from_file()
        
        # Client monitoring
        self._active_clients = {}  # {client_ip: {last_seen, user_agent, request_count, endpoints}}
        self._client_history = []  # List of all client access records
    
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
