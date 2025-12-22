"""
Configuration Manager for System Monitor Web Dashboard
Handles loading and validation of configuration settings including IP access control.
"""

import json
import os
import logging
import ipaddress
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages configuration settings for the dashboard."""
    
    def __init__(self, config_file: str = "config.json"):
        """Initialize the configuration manager.
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file
        self.config = self._load_default_config()
        self._load_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration settings."""
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 9100,
                "debug": True
            },
            "security": {
                "enable_ip_restriction": False,
                "allowed_ips": ["127.0.0.1", "::1", "localhost"],
                "blocked_ips": [],
                "log_access_attempts": True
            },
            "monitoring": {
                "refresh_interval": 5,
                "max_processes": 100,
                "enable_database_monitoring": True
            },
            "logging": {
                "level": "INFO",
                "log_file": "dashboard.log",
                "max_log_size": "10MB",
                "backup_count": 5
            }
        }
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                
                # Merge with defaults
                self._merge_config(self.config, file_config)
                logger.info(f"Configuration loaded from {self.config_file}")
                
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in config file {self.config_file}: {e}")
                logger.info("Using default configuration")
            except Exception as e:
                logger.error(f"Error loading config file {self.config_file}: {e}")
                logger.info("Using default configuration")
        else:
            logger.info(f"Config file {self.config_file} not found, using defaults")
            self._save_config()
    
    def _merge_config(self, default: Dict[str, Any], file_config: Dict[str, Any]) -> None:
        """Recursively merge file configuration with defaults."""
        for key, value in file_config.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def _save_config(self) -> None:
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving config file {self.config_file}: {e}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation.
        
        Args:
            key_path: Configuration key path (e.g., 'server.port')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """Set configuration value using dot notation.
        
        Args:
            key_path: Configuration key path (e.g., 'server.port')
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def is_ip_allowed(self, client_ip: str) -> bool:
        """Check if client IP is allowed to access the dashboard.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if IP is allowed, False otherwise
        """
        if not self.get('security.enable_ip_restriction', False):
            return True
        
        # Normalize IPv6-mapped IPv4 addresses (e.g., ::ffff:127.0.0.1 -> 127.0.0.1)
        normalized_ip = self._normalize_ip(client_ip)
        
        # Check blocked IPs first
        blocked_ips = self.get('security.blocked_ips', [])
        if self._is_ip_in_list(normalized_ip, blocked_ips):
            if self.get('security.log_access_attempts', True):
                logger.warning(f"Blocked IP {client_ip} (normalized: {normalized_ip}) attempted to access dashboard")
            return False
        
        # Check allowed IPs
        allowed_ips = self.get('security.allowed_ips', [])
        if self._is_ip_in_list(normalized_ip, allowed_ips):
            if self.get('security.log_access_attempts', True):
                logger.info(f"Allowed IP {client_ip} (normalized: {normalized_ip}) accessed dashboard")
            return True
        
        # IP not in allowed list
        if self.get('security.log_access_attempts', True):
            logger.warning(f"Unauthorized IP {client_ip} (normalized: {normalized_ip}) attempted to access dashboard")
        return False
    
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address, converting IPv6-mapped IPv4 to IPv4.
        
        Args:
            ip: IP address to normalize
            
        Returns:
            Normalized IP address
        """
        try:
            # Handle IPv6-mapped IPv4 addresses (::ffff:x.x.x.x format)
            if ip.startswith('::ffff:'):
                # Extract the IPv4 part
                ipv4_part = ip[7:]  # Remove '::ffff:' prefix
                # Validate it's a valid IPv4 address
                ipaddress.ip_address(ipv4_part)
                return ipv4_part
            
            # Try to parse as IPv6 and check if it's IPv4-mapped
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv6Address):
                # Check if it's an IPv6-mapped IPv4 address
                try:
                    # Try to get IPv4 mapped address (available in Python 3.4+)
                    if hasattr(addr, 'ipv4_mapped') and addr.ipv4_mapped:
                        return str(addr.ipv4_mapped)
                except AttributeError:
                    # Fallback: check if it matches ::ffff: pattern
                    if ip.startswith('::ffff:'):
                        ipv4_part = ip[7:]
                        try:
                            ipaddress.ip_address(ipv4_part)
                            return ipv4_part
                        except ValueError:
                            pass
            
            return ip
        except ValueError:
            return ip
    
    def _is_ip_in_list(self, client_ip: str, ip_list: List[str]) -> bool:
        """Check if IP is in the given list (supports CIDR notation).
        
        Args:
            client_ip: Client IP address
            ip_list: List of IPs or CIDR blocks
            
        Returns:
            True if IP matches any entry in the list
        """
        try:
            client_addr = ipaddress.ip_address(client_ip)
            
            for ip_entry in ip_list:
                # Handle special cases
                if ip_entry.lower() == 'localhost':
                    if client_ip in ['127.0.0.1', '::1', '::ffff:127.0.0.1']:
                        return True
                    continue
                
                # Handle CIDR notation
                if '/' in ip_entry:
                    try:
                        network = ipaddress.ip_network(ip_entry, strict=False)
                        if client_addr in network:
                            return True
                    except ValueError:
                        logger.warning(f"Invalid CIDR notation: {ip_entry}")
                        continue
                
                # Handle single IP
                try:
                    allowed_addr = ipaddress.ip_address(ip_entry)
                    if client_addr == allowed_addr:
                        return True
                except ValueError:
                    logger.warning(f"Invalid IP address: {ip_entry}")
                    continue
            
            return False
            
        except ValueError:
            logger.error(f"Invalid client IP address: {client_ip}")
            return False
    
    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration."""
        return self.get('server', {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration."""
        return self.get('security', {})
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration."""
        return self.get('monitoring', {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration."""
        return self.get('logging', {})
    
    def add_allowed_ip(self, ip: str) -> bool:
        """Add an IP to the allowed list.
        
        Args:
            ip: IP address or CIDR block to add
            
        Returns:
            True if successfully added, False otherwise
        """
        try:
            # Validate IP format
            if '/' in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
            
            allowed_ips = self.get('security.allowed_ips', [])
            if ip not in allowed_ips:
                allowed_ips.append(ip)
                self.set('security.allowed_ips', allowed_ips)
                self._save_config()
                logger.info(f"Added allowed IP: {ip}")
                return True
            else:
                logger.info(f"IP {ip} already in allowed list")
                return True
                
        except ValueError as e:
            logger.error(f"Invalid IP format {ip}: {e}")
            return False
    
    def remove_allowed_ip(self, ip: str) -> bool:
        """Remove an IP from the allowed list.
        
        Args:
            ip: IP address to remove
            
        Returns:
            True if successfully removed, False otherwise
        """
        allowed_ips = self.get('security.allowed_ips', [])
        if ip in allowed_ips:
            allowed_ips.remove(ip)
            self.set('security.allowed_ips', allowed_ips)
            self._save_config()
            logger.info(f"Removed allowed IP: {ip}")
            return True
        else:
            logger.warning(f"IP {ip} not found in allowed list")
            return False
    
    def list_allowed_ips(self) -> List[str]:
        """Get list of allowed IPs."""
        return self.get('security.allowed_ips', [])
    
    def enable_ip_restriction(self) -> None:
        """Enable IP restriction."""
        self.set('security.enable_ip_restriction', True)
        self._save_config()
        logger.info("IP restriction enabled")
    
    def disable_ip_restriction(self) -> None:
        """Disable IP restriction."""
        self.set('security.enable_ip_restriction', False)
        self._save_config()
        logger.info("IP restriction disabled")
    
    def reload_config(self) -> None:
        """Reload configuration from file."""
        self.config = self._load_default_config()
        self._load_config()
        logger.info("Configuration reloaded")
