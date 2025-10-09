#!/usr/bin/env python3
"""
Frontend web application for system monitoring dashboard.
Provides web interface for monitoring services, ports, and databases.
"""

from flask import Flask, render_template, jsonify, request
from .backend import SystemMonitor
import json
import threading
import time
from datetime import datetime

app = Flask(__name__)
monitor = SystemMonitor()

# Global variable to store latest monitoring data
latest_data = {}
data_lock = threading.Lock()

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
