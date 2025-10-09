#!/usr/bin/env python3
"""
Frontend web application for system monitoring dashboard.
Provides web interface for monitoring services, ports, and databases.
"""

from flask import Flask, render_template, jsonify, request, abort
from .backend import SystemMonitor
from .config_manager import ConfigManager
import json
import threading
import time
from datetime import datetime

app = Flask(__name__)
monitor = SystemMonitor()
config_manager = ConfigManager()

# Global variable to store latest monitoring data
latest_data = {}
data_lock = threading.Lock()

def check_ip_access():
    """Check if client IP is allowed to access the dashboard."""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
    
    # Handle forwarded IPs (take the first one)
    if ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
    
    if not config_manager.is_ip_allowed(client_ip):
        abort(403, description=f"Access denied for IP: {client_ip}")

@app.before_request
def before_request():
    """Check IP access before processing any request."""
    check_ip_access()

def update_monitoring_data():
    """Background thread to continuously update monitoring data."""
    global latest_data
    while True:
        try:
            new_data = monitor.get_all_monitoring_data()
            with data_lock:
                latest_data = new_data
        except Exception as e:
            print(f"Error updating monitoring data: {e}")
        time.sleep(5)  # Update every 5 seconds

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')

@app.route('/api/monitoring-data')
def get_monitoring_data():
    """API endpoint to get current monitoring data."""
    with data_lock:
        return jsonify(latest_data)

@app.route('/api/services')
def get_services():
    """API endpoint to get running services."""
    services = monitor.get_running_services()
    return jsonify(services)

@app.route('/api/ports')
def get_ports():
    """API endpoint to get active ports."""
    ports = monitor.get_active_ports()
    return jsonify(ports)

@app.route('/api/mysql')
def get_mysql_status():
    """API endpoint to get MySQL status."""
    mysql_status = monitor.check_mysql_status()
    return jsonify(mysql_status)

@app.route('/api/postgresql')
def get_postgresql_status():
    """API endpoint to get PostgreSQL status."""
    postgres_status = monitor.check_postgresql_status()
    return jsonify(postgres_status)

@app.route('/api/system-info')
def get_system_info():
    """API endpoint to get system information."""
    system_info = monitor.get_system_info()
    return jsonify(system_info)

@app.route('/services')
def services_page():
    """Services monitoring page."""
    return render_template('services.html')

@app.route('/ports')
def ports_page():
    """Ports monitoring page."""
    return render_template('ports.html')

@app.route('/databases')
def databases_page():
    """Database monitoring page."""
    return render_template('databases.html')

@app.route('/system')
def system_page():
    """System information page."""
    return render_template('system.html')

@app.route('/config')
def config_page():
    """Configuration management page."""
    return render_template('config.html')

@app.route('/api/config')
def get_config():
    """API endpoint to get current configuration."""
    return jsonify({
        'security': config_manager.get_security_config(),
        'server': config_manager.get_server_config(),
        'monitoring': config_manager.get_monitoring_config()
    })

@app.route('/api/config/allowed-ips', methods=['GET', 'POST', 'DELETE'])
def manage_allowed_ips():
    """API endpoint to manage allowed IPs."""
    if request.method == 'GET':
        return jsonify({'allowed_ips': config_manager.list_allowed_ips()})
    
    elif request.method == 'POST':
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        if config_manager.add_allowed_ip(ip):
            return jsonify({'message': f'Added IP: {ip}'})
        else:
            return jsonify({'error': f'Invalid IP format: {ip}'}), 400
    
    elif request.method == 'DELETE':
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        if config_manager.remove_allowed_ip(ip):
            return jsonify({'message': f'Removed IP: {ip}'})
        else:
            return jsonify({'error': f'IP not found: {ip}'}), 404

@app.route('/api/config/ip-restriction', methods=['POST'])
def toggle_ip_restriction():
    """API endpoint to enable/disable IP restriction."""
    data = request.get_json()
    enable = data.get('enable', True)
    
    if enable:
        config_manager.enable_ip_restriction()
        return jsonify({'message': 'IP restriction enabled'})
    else:
        config_manager.disable_ip_restriction()
        return jsonify({'message': 'IP restriction disabled'})

@app.route('/api/config/reload', methods=['POST'])
def reload_config():
    """API endpoint to reload configuration."""
    config_manager.reload_config()
    return jsonify({'message': 'Configuration reloaded'})

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 (Forbidden) errors."""
    return render_template('403.html', 
                         error_message=error.description,
                         client_ip=request.environ.get('REMOTE_ADDR')), 403

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return render_template('500.html'), 500

def start_background_monitoring():
    """Start the background monitoring thread."""
    monitoring_thread = threading.Thread(target=update_monitoring_data, daemon=True)
    monitoring_thread.start()
    print("Background monitoring started")

if __name__ == '__main__':
    # Initialize with some data
    with data_lock:
        latest_data = monitor.get_all_monitoring_data()
    
    # Start background monitoring
    start_background_monitoring()
    
    print("Starting System Monitor Web Dashboard...")
    print("Dashboard will be available at: http://localhost:9100")
    print("Press Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=9100)
