#!/usr/bin/env python3
"""
Autossh Manager for handling autossh tunnel operations.
Manages SSH reverse tunnels using autossh for persistent connections.
"""

import subprocess
import threading
import time
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Callable
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class AutosshTunnel:
    """Represents a single autossh tunnel configuration."""
    
    def __init__(self, tunnel_id: str, config: Dict):
        self.tunnel_id = tunnel_id
        self.name = config.get('name', f'Tunnel {tunnel_id}')
        self.local_port = config.get('local_port', '11434')
        self.remote_port = config.get('remote_port', None)  # If None, use same as local_port
        self.vps_ip = config.get('vps_ip', '')
        self.vps_port = config.get('vps_port', '22')
        self.username = config.get('username', 'root')
        self.ssh_key_path = config.get('ssh_key_path', '')  # Path to SSH private key (required)
        self.remote_bind_address = config.get('remote_bind_address', '0.0.0.0')
        self.server_alive_interval = config.get('server_alive_interval', 30)
        self.server_alive_count_max = config.get('server_alive_count_max', 3)
        self.monitor_port = config.get('monitor_port', 0)  # 0 means no monitoring port
        self.is_running = False
        self.process = None
        self.last_started = None
        self.status = 'stopped'  # stopped, running, error
        self.output_log = []
        self.error_log = []
        self.thread = None
        self.stop_event = threading.Event()
        
    def to_dict(self):
        """Convert tunnel to dictionary."""
        return {
            'tunnel_id': self.tunnel_id,
            'name': self.name,
            'local_port': self.local_port,
            'remote_port': self.remote_port or self.local_port,
            'vps_ip': self.vps_ip,
            'vps_port': self.vps_port,
            'username': self.username,
            'ssh_key_path': self.ssh_key_path,
            'remote_bind_address': self.remote_bind_address,
            'server_alive_interval': self.server_alive_interval,
            'server_alive_count_max': self.server_alive_count_max,
            'monitor_port': self.monitor_port,
            'is_running': self.is_running,
            'last_started': self.last_started.isoformat() if self.last_started else None,
            'status': self.status
        }


class AutosshManager:
    """Manages autossh tunnels and operations."""
    
    def __init__(self, config_file: str = 'autossh_config.json'):
        self.config_file = config_file
        self.tunnels: Dict[str, AutosshTunnel] = {}
        self.lock = threading.Lock()
        self.output_callbacks: Dict[str, Callable] = {}  # tunnel_id -> callback
        self.load_config()
        
    def load_config(self):
        """Load autossh configurations from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    for tunnel_id, config in data.get('tunnels', {}).items():
                        tunnel = AutosshTunnel(tunnel_id, config)
                        self.tunnels[tunnel_id] = tunnel
                logger.info(f"Loaded {len(self.tunnels)} autossh tunnels from config")
            except Exception as e:
                logger.error(f"Error loading autossh config: {e}")
    
    def save_config(self):
        """Save autossh configurations to file."""
        try:
            data = {
                'tunnels': {}
            }
            with self.lock:
                for tunnel_id, tunnel in self.tunnels.items():
                    # Save tunnel configuration
                    tunnel_config = tunnel.to_dict()
                    data['tunnels'][tunnel_id] = tunnel_config
            
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Saved autossh config")
        except Exception as e:
            logger.error(f"Error saving autossh config: {e}")
    
    def add_tunnel(self, config: Dict) -> str:
        """Add a new autossh tunnel."""
        tunnel_id = config.get('tunnel_id') or f"tunnel_{int(time.time())}"
        
        with self.lock:
            tunnel = AutosshTunnel(tunnel_id, config)
            self.tunnels[tunnel_id] = tunnel
        
        self.save_config()
        return tunnel_id
    
    def update_tunnel(self, tunnel_id: str, config: Dict) -> bool:
        """Update an existing autossh tunnel."""
        with self.lock:
            if tunnel_id not in self.tunnels:
                logger.warning(f"[Autossh Tunnel {tunnel_id}] Cannot update: Tunnel not found")
                return False
            
            tunnel = self.tunnels[tunnel_id]
            if tunnel.is_running:
                logger.warning(f"[Autossh Tunnel {tunnel_id}] Cannot update: Tunnel is running. Stop it first.")
                return False
            
            logger.info(f"[Autossh Tunnel {tunnel_id}] Updating tunnel: {tunnel.name}")
            # Update fields
            for key, value in config.items():
                if key != 'tunnel_id' and hasattr(tunnel, key):
                    # Handle ssh_key_path - required field
                    if key == 'ssh_key_path':
                        value = value.strip() if value else ''
                        if not value:
                            logger.warning(f"[Autossh Tunnel {tunnel_id}] SSH key path is required")
                            continue
                    old_value = getattr(tunnel, key, None)
                    setattr(tunnel, key, value)
                    if old_value != value:
                        logger.debug(f"[Autossh Tunnel {tunnel_id}] Updated {key}: {old_value} -> {value}")
        
        self.save_config()
        logger.info(f"[Autossh Tunnel {tunnel_id}] Tunnel updated successfully")
        return True
    
    def delete_tunnel(self, tunnel_id: str) -> bool:
        """Delete an autossh tunnel."""
        with self.lock:
            if tunnel_id not in self.tunnels:
                return False
            
            tunnel = self.tunnels[tunnel_id]
            if tunnel.is_running:
                self.stop_tunnel(tunnel_id)
            
            del self.tunnels[tunnel_id]
        
        self.save_config()
        return True
    
    def get_tunnel(self, tunnel_id: str) -> Optional[AutosshTunnel]:
        """Get a tunnel by ID."""
        with self.lock:
            return self.tunnels.get(tunnel_id)
    
    def get_all_tunnels(self) -> List[Dict]:
        """Get all tunnels as dictionaries."""
        with self.lock:
            tunnels_list = []
            for tunnel in self.tunnels.values():
                # Check if process is still running
                if tunnel.is_running and tunnel.process:
                    try:
                        # Check if process is still alive
                        if tunnel.process.poll() is not None:
                            # Process has exited
                            tunnel.is_running = False
                            if tunnel.status == 'running':
                                tunnel.status = 'error'
                                return_code = tunnel.process.returncode
                                tunnel.error_log.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'type': 'error',
                                    'message': f'Process exited unexpectedly with return code: {return_code}'
                                })
                    except:
                        # Process object is invalid
                        tunnel.is_running = False
                        if tunnel.status == 'running':
                            tunnel.status = 'error'
                
                tunnels_list.append(tunnel.to_dict())
            return tunnels_list
    
    def get_tunnel_command(self, tunnel_id: str) -> Optional[str]:
        """Get the autossh command string for a tunnel."""
        with self.lock:
            if tunnel_id not in self.tunnels:
                return None
            
            tunnel = self.tunnels[tunnel_id]
            remote_port = tunnel.remote_port or tunnel.local_port
            
            # Build autossh command
            cmd_parts = ['autossh', '-v']
            cmd_parts.append('-M')
            cmd_parts.append(str(tunnel.monitor_port))
            cmd_parts.append('-o')
            cmd_parts.append(f'"ServerAliveInterval {tunnel.server_alive_interval}"')
            cmd_parts.append('-o')
            cmd_parts.append(f'"ServerAliveCountMax {tunnel.server_alive_count_max}"')
            cmd_parts.append('-o')
            cmd_parts.append('"StrictHostKeyChecking=no"')
            cmd_parts.append('-o')
            cmd_parts.append('"ExitOnForwardFailure=yes"')
            cmd_parts.append('-o')
            cmd_parts.append('"TCPKeepAlive=yes"')
            cmd_parts.append('-N')
            cmd_parts.append('-R')
            cmd_parts.append(f'{tunnel.remote_bind_address}:{remote_port}:127.0.0.1:{tunnel.local_port}')
            
            if tunnel.ssh_key_path:
                key_path = tunnel.ssh_key_path.strip()
                if key_path.startswith('~'):
                    key_path = os.path.expanduser(key_path)
                cmd_parts.append('-i')
                cmd_parts.append(key_path)
            
            if tunnel.vps_port != '22':
                cmd_parts.append('-p')
                cmd_parts.append(str(tunnel.vps_port))
            
            cmd_parts.append(f'{tunnel.username}@{tunnel.vps_ip}')
            
            return ' '.join(cmd_parts)
    
    def set_output_callback(self, tunnel_id: str, callback: Callable):
        """Set callback for real-time output."""
        self.output_callbacks[tunnel_id] = callback
    
    def _run_autossh(self, tunnel: AutosshTunnel):
        """Run autossh command for a tunnel."""
        try:
            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] Starting autossh execution")
            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] Tunnel: {tunnel.name}")
            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] Local port: {tunnel.local_port}")
            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] Remote: {tunnel.remote_bind_address}:{tunnel.remote_port or tunnel.local_port}")
            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] VPS: {tunnel.username}@{tunnel.vps_ip}:{tunnel.vps_port}")
            
            # Build autossh command
            # Add verbose flag to get more output for debugging
            cmd = ['autossh', '-v']
            cmd.append('-M')
            cmd.append(str(tunnel.monitor_port))
            cmd.extend(['-o', f'ServerAliveInterval {tunnel.server_alive_interval}'])
            cmd.extend(['-o', f'ServerAliveCountMax {tunnel.server_alive_count_max}'])
            cmd.extend(['-o', 'StrictHostKeyChecking=no'])  # Avoid host key prompts
            # Avoid host key file issues (use NUL on Windows, /dev/null on Unix)
            if os.name == 'nt':
                cmd.extend(['-o', 'UserKnownHostsFile=NUL'])
            else:
                cmd.extend(['-o', 'UserKnownHostsFile=/dev/null'])
            
            # SSH key is required
            if not tunnel.ssh_key_path or not tunnel.ssh_key_path.strip():
                error_msg = 'SSH key path is required. Please specify a valid SSH private key file path.'
                logger.error(f"[Autossh Tunnel {tunnel.tunnel_id}] {error_msg}")
                tunnel.status = 'error'
                tunnel.error_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'error',
                    'message': error_msg
                })
                with self.lock:
                    tunnel.is_running = False
                return
            
            key_path = tunnel.ssh_key_path.strip()
            # Expand ~ to home directory
            if key_path.startswith('~'):
                key_path = os.path.expanduser(key_path)
            
            # Verify key file exists
            if not os.path.exists(key_path):
                error_msg = f'SSH key file not found: {key_path}. Please check the path and ensure the key file exists.'
                logger.error(f"[Autossh Tunnel {tunnel.tunnel_id}] {error_msg}")
                tunnel.status = 'error'
                tunnel.error_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'error',
                    'message': error_msg
                })
                with self.lock:
                    tunnel.is_running = False
                return
            
            # Check key file permissions (should be 600 or 400)
            try:
                stat_info = os.stat(key_path)
                mode = stat_info.st_mode & 0o777
                if mode not in [0o600, 0o400]:
                    logger.warning(f"[Autossh Tunnel {tunnel.tunnel_id}] SSH key file permissions are {oct(mode)}. Recommended: 600 or 400")
            except:
                pass
            
            cmd.extend(['-i', key_path])
            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] Using SSH key: {key_path}")
            
            # Add options for stability
            cmd.extend(['-o', 'ExitOnForwardFailure=yes'])  # Exit if port forwarding fails
            cmd.extend(['-o', 'TCPKeepAlive=yes'])  # Enable TCP keepalive
            cmd.extend(['-o', 'Compression=no'])  # Disable compression for stability
            cmd.extend(['-o', 'BatchMode=yes'])  # Disable interactive prompts
            cmd.extend(['-o', 'IdentitiesOnly=yes'])  # Only use specified key
            
            cmd.append('-N')
            
            remote_port = tunnel.remote_port or tunnel.local_port
            cmd.extend(['-R', f'{tunnel.remote_bind_address}:{remote_port}:127.0.0.1:{tunnel.local_port}'])
            
            if tunnel.vps_port != '22':
                cmd.extend(['-p', str(tunnel.vps_port)])
            
            cmd.append(f'{tunnel.username}@{tunnel.vps_ip}')
            
            # Log the command
            cmd_str = ' '.join(cmd)
            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] Executing command: {cmd_str}")
            
            tunnel.status = 'running'
            tunnel.last_started = datetime.now()
            logger.info(f"[Autossh Tunnel {tunnel.tunnel_id}] Tunnel started at {tunnel.last_started.isoformat()}")
            
            # Set up environment
            env = os.environ.copy()
            
            # Run autossh
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=env
            )
            tunnel.process = process
            
            # Initialize logs
            tunnel.output_log = []
            tunnel.error_log = []
            
            # Add initial log entry
            initial_log = {
                'timestamp': datetime.now().isoformat(),
                'type': 'output',
                'message': f'Starting autossh tunnel: {" ".join(cmd)}'
            }
            tunnel.output_log.append(initial_log)
            
            # Read output in a separate thread to allow stopping
            def read_output():
                try:
                    # Give process a moment to start and potentially output errors
                    time.sleep(0.5)
                    
                    # Check if process is still running after initial delay
                    if process.poll() is not None:
                        # Process exited quickly, likely an error
                        return_code = process.returncode
                        error_msg = f'Process exited immediately with return code: {return_code}'
                        logger.error(f"[Autossh Tunnel {tunnel.tunnel_id}] {error_msg}")
                        tunnel.error_log.append({
                            'timestamp': datetime.now().isoformat(),
                            'type': 'error',
                            'message': error_msg
                        })
                        # Try to read any error output
                        try:
                            remaining_output = process.stdout.read()
                            if remaining_output:
                                for line in remaining_output.split('\n'):
                                    if line.strip():
                                        log_entry = {
                                            'timestamp': datetime.now().isoformat(),
                                            'type': 'error',
                                            'message': line.strip()
                                        }
                                        tunnel.output_log.append(log_entry)
                                        tunnel.error_log.append(log_entry)
                        except:
                            pass
                        with self.lock:
                            tunnel.is_running = False
                            tunnel.status = 'error'
                        return
                    
                    # Process is running, start reading output
                    while True:
                        # Check if tunnel should be stopped
                        if tunnel.stop_event.is_set():
                            try:
                                process.terminate()
                                process.wait(timeout=5)
                            except:
                                try:
                                    process.kill()
                                except:
                                    pass
                            return
                        
                        # Check if process is still running
                        poll_result = process.poll()
                        if poll_result is not None:
                            # Process exited
                            return_code = poll_result
                            if return_code != 0:
                                error_msg = f'Process exited with return code: {return_code}'
                                logger.error(f"[Autossh Tunnel {tunnel.tunnel_id}] {error_msg}")
                                tunnel.error_log.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'type': 'error',
                                    'message': error_msg
                                })
                                with self.lock:
                                    tunnel.is_running = False
                                    tunnel.status = 'error'
                            else:
                                logger.info(f"[Autossh Tunnel {tunnel.tunnel_id}] Process exited normally")
                                with self.lock:
                                    tunnel.is_running = False
                                    tunnel.status = 'stopped'
                            break
                        
                        # Try to read a line (non-blocking)
                        try:
                            # Try to read with a timeout approach
                            # On Unix systems, we can use select, on Windows we'll just try readline
                            try:
                                import select
                                # Check if there's data available (Unix/Linux/macOS)
                                if select.select([process.stdout], [], [], 0.1)[0]:
                                    output = process.stdout.readline()
                                else:
                                    output = None
                            except (ImportError, OSError):
                                # Windows or select not available - try direct readline
                                # This might block briefly, but with small timeout it should be OK
                                output = process.stdout.readline()
                            
                            if output:
                                line = output.strip()
                                if line:
                                    log_entry = {
                                        'timestamp': datetime.now().isoformat(),
                                        'type': 'output',
                                        'message': line
                                    }
                                    tunnel.output_log.append(log_entry)
                                    
                                    # Keep only last 30 entries
                                    if len(tunnel.output_log) > 30:
                                        tunnel.output_log.pop(0)
                                    
                                    # Log to console as debug
                                    logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] OUTPUT: {line}")
                                    
                                    # Call callback if set
                                    if tunnel.tunnel_id in self.output_callbacks:
                                        try:
                                            self.output_callbacks[tunnel.tunnel_id](log_entry)
                                        except Exception as e:
                                            logger.error(f"[Autossh Tunnel {tunnel.tunnel_id}] Error in output callback: {e}")
                        except Exception as read_error:
                            # If readline fails, just sleep and check process status
                            logger.debug(f"[Autossh Tunnel {tunnel.tunnel_id}] Read error (non-critical): {read_error}")
                            time.sleep(0.5)
                            continue
                        
                        # Small sleep to avoid busy waiting
                        time.sleep(0.1)
                        
                except Exception as e:
                    logger.error(f"[Autossh Tunnel {tunnel.tunnel_id}] Error in output reader: {e}")
                    tunnel.error_log.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'error',
                        'message': f'Error reading output: {str(e)}'
                    })
                    with self.lock:
                        tunnel.is_running = False
                        tunnel.status = 'error'
            
            # Start reading output in separate thread
            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()
            
            # Don't wait for process - it should run continuously
            # Instead, check process status after a short delay
            time.sleep(1)
            if process.poll() is not None:
                # Process exited quickly
                return_code = process.returncode
                logger.error(f"[Autossh Tunnel {tunnel.tunnel_id}] Process exited immediately with return code: {return_code}")
                tunnel.status = 'error'
                tunnel.error_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'error',
                    'message': f'Process exited immediately with return code: {return_code}. Check authentication and network connectivity.'
                })
                with self.lock:
                    tunnel.is_running = False
            else:
                # Process is running
                logger.info(f"[Autossh Tunnel {tunnel.tunnel_id}] Tunnel process started successfully")
                # Add a success message to logs
                success_log = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'output',
                    'message': 'Tunnel process started successfully. Monitoring connection...'
                }
                tunnel.output_log.append(success_log)
            
        except Exception as e:
            logger.error(f"Error running autossh for tunnel {tunnel.tunnel_id}: {e}")
            tunnel.status = 'error'
            tunnel.error_log.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'error',
                'message': str(e)
            })
            if tunnel.tunnel_id in self.output_callbacks:
                try:
                    self.output_callbacks[tunnel.tunnel_id]({
                        'type': 'error',
                        'message': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                except:
                    pass
            with self.lock:
                tunnel.is_running = False
    
    def start_tunnel(self, tunnel_id: str) -> bool:
        """Start an autossh tunnel."""
        with self.lock:
            if tunnel_id not in self.tunnels:
                logger.warning(f"[Autossh Tunnel {tunnel_id}] Cannot start: Tunnel not found")
                return False
            
            tunnel = self.tunnels[tunnel_id]
            if tunnel.is_running:
                logger.warning(f"[Autossh Tunnel {tunnel_id}] Cannot start: Tunnel is already running")
                return False
            
            tunnel.is_running = True
            tunnel.stop_event.clear()
        
        logger.info(f"[Autossh Tunnel {tunnel_id}] Starting tunnel '{tunnel.name}'")
        
        # Run in separate thread
        def run():
            self._run_autossh(tunnel)
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        tunnel.thread = thread
        
        return True
    
    def stop_tunnel(self, tunnel_id: str) -> bool:
        """Stop a running autossh tunnel."""
        with self.lock:
            if tunnel_id not in self.tunnels:
                logger.warning(f"[Autossh Tunnel {tunnel_id}] Cannot stop: Tunnel not found")
                return False
            
            tunnel = self.tunnels[tunnel_id]
            if not tunnel.is_running:
                logger.warning(f"[Autossh Tunnel {tunnel_id}] Cannot stop: Tunnel is not running")
                return False
            
            logger.info(f"[Autossh Tunnel {tunnel_id}] Stopping tunnel '{tunnel.name}'")
            tunnel.stop_event.set()
            
            if tunnel.process:
                logger.debug(f"[Autossh Tunnel {tunnel_id}] Terminating autossh process...")
                try:
                    tunnel.process.terminate()
                    tunnel.process.wait(timeout=5)
                    logger.debug(f"[Autossh Tunnel {tunnel_id}] Process terminated successfully")
                except:
                    try:
                        logger.debug(f"[Autossh Tunnel {tunnel_id}] Process termination timed out, killing process...")
                        tunnel.process.kill()
                    except:
                        pass
            
            tunnel.is_running = False
            tunnel.status = 'stopped'
        
        logger.info(f"[Autossh Tunnel {tunnel_id}] Tunnel stopped successfully")
        return True
    
    def get_tunnel_logs(self, tunnel_id: str, limit: int = 30) -> Dict:
        """Get logs for a tunnel (last 30 entries by default)."""
        with self.lock:
            if tunnel_id not in self.tunnels:
                return {'output': [], 'error': []}
            
            tunnel = self.tunnels[tunnel_id]
            # Return last 30 entries
            output_logs = tunnel.output_log[-limit:] if len(tunnel.output_log) > limit else tunnel.output_log
            error_logs = tunnel.error_log[-limit:] if len(tunnel.error_log) > limit else tunnel.error_log
            return {
                'output': output_logs,
                'error': error_logs
            }

