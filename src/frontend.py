#!/usr/bin/env python3
"""
Frontend web application for system monitoring dashboard.
Provides web interface for monitoring services, ports, and databases.
"""

from flask import Flask, render_template, jsonify, request, abort, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_cors import CORS
from backend import SystemMonitor
from config_manager import ConfigManager
from rsync_manager import RsyncManager
from postgres_sync_manager import PostgresSyncManager
from autossh_manager import AutosshManager
from ollama_gateway_manager import OllamaGatewayManager
from litellm_manager import LiteLLMManager
from auth import auth_manager, login_manager, can_edit_required
import logging
import json
import threading
import time
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
# Enable CORS for Next.js frontend on port 9200
CORS(app, origins=['http://localhost:9200', 'http://127.0.0.1:9200'], supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize login manager
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

monitor = SystemMonitor()
config_manager = ConfigManager()
rsync_manager = RsyncManager()
postgres_sync_manager = PostgresSyncManager()
autossh_manager = AutosshManager()
ollama_gateway_manager = OllamaGatewayManager()
litellm_manager = LiteLLMManager()

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# Set rsync_manager logger to DEBUG
logging.getLogger('rsync_manager').setLevel(logging.DEBUG)

# Global variable to store latest monitoring data
latest_data = {}
data_lock = threading.Lock()

@app.before_request
def log_client_access():
    """Log client access for monitoring."""
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
    user_agent = request.headers.get('User-Agent')
    referer = request.headers.get('Referer')
    endpoint = request.endpoint
    
    # Log the access
    monitor.log_client_access(
        client_ip=client_ip,
        user_agent=user_agent,
        referer=referer,
        status_code=200,  # Will be updated if there's an error
        endpoint=endpoint
    )

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
    """Check IP access and authentication before processing any request."""
    # Skip IP check and authentication for static files
    if request.path.startswith('/static'):
        return
    
    # Skip authentication for login page and auth check endpoint (but still check IP)
    if request.endpoint == 'login' or request.path == '/api/auth/check':
        check_ip_access()
        return
    
    # Check IP access for all other routes
    check_ip_access()
    
    # Require login for all other routes
    if not current_user.is_authenticated:
        # Check if it's an API route by path (more reliable than endpoint name)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        else:
            # For non-API routes, redirect to login
            # Don't use request.url as it contains backend URL
            # Instead, construct frontend URL from headers if available
            frontend_host = request.headers.get('X-Forwarded-Host')
            if frontend_host:
                # Request came through proxy, use frontend host
                frontend_url = f'http://{frontend_host}{request.path}'
                if request.query_string:
                    frontend_url += f'?{request.query_string.decode()}'
                return redirect(f'http://{frontend_host}/login?next={frontend_url}')
            else:
                # Direct access to backend, use backend URL
                return redirect(url_for('login', next=request.url))

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
        
        # Get refresh interval from config, default to 5 seconds
        refresh_interval = config_manager.get('monitoring.refresh_interval', 5)
        time.sleep(refresh_interval)

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = auth_manager.authenticate(username, password)
        if user:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout route."""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile_page():
    """User profile page."""
    return render_template('profile.html')

@app.route('/api/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """API endpoint to change user password."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not old_password or not new_password or not confirm_password:
            return jsonify({'success': False, 'error': 'All password fields are required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'success': False, 'error': 'New passwords do not match'}), 400
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'New password must be at least 6 characters long'}), 400
        
        success, message = auth_manager.change_password(
            current_user.username,
            old_password,
            new_password
        )
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/')
@login_required
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')

@app.route('/api/auth/check')
def check_auth():
    """API endpoint to check if user is authenticated."""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'username': current_user.username,
            'role': current_user.role if hasattr(current_user, 'role') else 'viewer'
        })
    else:
        return jsonify({'authenticated': False}), 401

@app.route('/api/monitoring-data')
@login_required
def get_monitoring_data():
    """API endpoint to get current monitoring data."""
    with data_lock:
        return jsonify(latest_data)

@app.route('/api/services')
@login_required
def get_services():
    """API endpoint to get running services."""
    services = monitor.get_running_services()
    return jsonify(services)

@app.route('/api/ports')
@login_required
def get_ports():
    """API endpoint to get active ports."""
    ports = monitor.get_active_ports()
    return jsonify(ports)

@app.route('/api/clients')
@login_required
def get_clients():
    """API endpoint to get active clients."""
    clients = monitor.get_active_clients()
    return jsonify(clients)

@app.route('/api/client-stats')
@login_required
def get_client_statistics():
    """API endpoint to get client statistics."""
    stats = monitor.get_client_statistics()
    return jsonify(stats)

@app.route('/api/client-history/<client_ip>')
@login_required
def get_client_history(client_ip):
    """API endpoint to get client access history."""
    history = monitor.get_client_history(client_ip)
    return jsonify(history)

@app.route('/api/mysql')
@login_required
def get_mysql_status():
    """API endpoint to get MySQL status."""
    mysql_status = monitor.check_mysql_status()
    return jsonify(mysql_status)

@app.route('/api/postgresql')
@login_required
def get_postgresql_status():
    """API endpoint to get PostgreSQL status."""
    postgres_status = monitor.check_postgresql_status()
    return jsonify(postgres_status)

@app.route('/api/system-info')
@login_required
def get_system_info():
    """API endpoint to get system information."""
    system_info = monitor.get_system_info()
    return jsonify(system_info)

@app.route('/services')
@login_required
def services_page():
    """Services monitoring page."""
    return render_template('services.html')

@app.route('/ports')
@login_required
def ports_page():
    """Ports monitoring page."""
    return render_template('ports.html')

@app.route('/clients')
@login_required
def clients_page():
    """Client monitoring page."""
    return render_template('clients.html')

@app.route('/databases')
@login_required
def databases_page():
    """Database monitoring page."""
    return render_template('databases.html')

@app.route('/system')
@login_required
def system_page():
    """System information page."""
    return render_template('system.html')

@app.route('/config')
@login_required
def config_page():
    """Configuration management page."""
    return render_template('config.html')

@app.route('/proxy-detection')
@login_required
def proxy_detection_page():
    """Enhanced proxy detection page."""
    return render_template('proxy-detection.html')

@app.route('/api/config')
@login_required
def get_config():
    """API endpoint to get current configuration."""
    return jsonify({
        'security': config_manager.get_security_config(),
        'server': config_manager.get_server_config(),
        'monitoring': config_manager.get_monitoring_config()
    })

@app.route('/api/config/allowed-ips', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_allowed_ips():
    """API endpoint to manage allowed IPs."""
    if request.method == 'GET':
        return jsonify({'allowed_ips': config_manager.list_allowed_ips()})
    
    elif request.method == 'POST':
        if not current_user.can_edit():
            return jsonify({'error': 'Permission denied. Admin access required.'}), 403
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        if config_manager.add_allowed_ip(ip):
            return jsonify({'message': f'Added IP: {ip}'})
        else:
            return jsonify({'error': f'Invalid IP format: {ip}'}), 400
    
    elif request.method == 'DELETE':
        if not current_user.can_edit():
            return jsonify({'error': 'Permission denied. Admin access required.'}), 403
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        if config_manager.remove_allowed_ip(ip):
            return jsonify({'message': f'Removed IP: {ip}'})
        else:
            return jsonify({'error': f'IP not found: {ip}'}), 404

@app.route('/api/config/ip-restriction', methods=['POST'])
@login_required
@can_edit_required
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
@login_required
@can_edit_required
def reload_config():
    """API endpoint to reload configuration."""
    config_manager.reload_config()
    return jsonify({'message': 'Configuration reloaded'})

@app.route('/api/proxy-detection')
@login_required
def get_proxy_detection():
    """API endpoint to get comprehensive proxy detection data."""
    proxy_data = monitor.check_proxy_usage()
    return jsonify(proxy_data)

@app.route('/api/network-connections')
@login_required
def get_network_connections():
    """API endpoint to get all network connections across all ports."""
    connections_data = monitor.monitor_network_connections()
    return jsonify(connections_data)

@app.route('/api/network-client-stats')
@login_required
def get_network_client_statistics():
    """API endpoint to get network client statistics across all ports."""
    stats_data = monitor.get_network_client_statistics()
    return jsonify(stats_data)

@app.route('/api/clients-by-port')
@login_required
def get_clients_by_port():
    """API endpoint to get clients categorized by ports."""
    clients_by_port_data = monitor.get_clients_by_port()
    return jsonify(clients_by_port_data)

@app.route('/api/custom-port-clients')
@login_required
def get_custom_port_clients():
    """API endpoint to get clients for custom ports defined in port_labels.json."""
    custom_port_clients_data = monitor.get_custom_port_clients()
    return jsonify(custom_port_clients_data)

@app.route('/network-interfaces')
@login_required
def network_interfaces_page():
    """Network interfaces management page."""
    return render_template('network-interfaces.html')

@app.route('/api/network-interfaces')
@login_required
def get_network_interfaces():
    """API endpoint to get network interfaces."""
    interfaces = monitor.get_network_interfaces()
    return jsonify(interfaces)

@app.route('/api/test-ips', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_test_ips():
    """API endpoint to manage test IP list."""
    if request.method == 'GET':
        try:
            return jsonify({'ips': monitor.get_test_ip_list()})
        except Exception as e:
            logger.error(f"Error getting test IP list: {e}")
            return jsonify({'error': str(e), 'ips': []}), 500
    
    elif request.method == 'POST':
        if not current_user.can_edit():
            return jsonify({'error': 'Permission denied. Admin access required.'}), 403
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body required'}), 400
            
            ip = data.get('ip')
            if not ip:
                return jsonify({'error': 'IP address required'}), 400
            
            ip = ip.strip()
            if monitor.add_test_ip(ip):
                return jsonify({'message': f'Added IP: {ip}', 'ips': monitor.get_test_ip_list()})
            else:
                # Check if IP is already in list
                current_ips = monitor.get_test_ip_list()
                if ip in current_ips:
                    return jsonify({'error': f'IP {ip} already exists in test list'}), 400
                else:
                    return jsonify({'error': f'Invalid IP address format: {ip}'}), 400
        except Exception as e:
            logger.error(f"Error adding test IP: {e}")
            return jsonify({'error': f'Error adding IP: {str(e)}'}), 500
    
    elif request.method == 'DELETE':
        if not current_user.can_edit():
            return jsonify({'error': 'Permission denied. Admin access required.'}), 403
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body required'}), 400
            
            ip = data.get('ip')
            if not ip:
                return jsonify({'error': 'IP address required'}), 400
            
            ip = ip.strip()
            if monitor.remove_test_ip(ip):
                return jsonify({'message': f'Removed IP: {ip}', 'ips': monitor.get_test_ip_list()})
            else:
                return jsonify({'error': f'IP not found: {ip}'}), 404
        except Exception as e:
            logger.error(f"Error removing test IP: {e}")
            return jsonify({'error': f'Error removing IP: {str(e)}'}), 500

@app.route('/api/test-ip-connection', methods=['POST'])
@login_required
def test_ip_connection():
    """API endpoint to test IP connection through specific interface."""
    data = request.get_json()
    ip = data.get('ip')
    interface = data.get('interface')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    result = monitor.test_ip_connection(ip, interface)
    return jsonify(result)

@app.route('/api/test-all-ips', methods=['POST'])
@login_required
def test_all_ips():
    """API endpoint to test all IPs in the list through specified interface."""
    data = request.get_json() or {}
    interface = data.get('interface')
    
    results = monitor.test_all_ips(interface)
    return jsonify({'results': results})

@app.route('/api/test-ip-all-interfaces', methods=['POST'])
@login_required
def test_ip_all_interfaces():
    """API endpoint to test a specific IP through all available interfaces."""
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    results = monitor.test_ip_all_interfaces(ip)
    return jsonify({'results': results, 'ip': ip})

@app.route('/api/test-urls', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_test_urls():
    """API endpoint to manage test URL list."""
    if request.method == 'GET':
        try:
            return jsonify({'urls': monitor.get_test_url_list()})
        except Exception as e:
            logger.error(f"Error getting test URL list: {e}")
            return jsonify({'error': str(e), 'urls': []}), 500
    
    elif request.method == 'POST':
        if not current_user.can_edit():
            return jsonify({'error': 'Permission denied. Admin access required.'}), 403
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body required'}), 400
            
            url = data.get('url')
            if not url:
                return jsonify({'error': 'URL required'}), 400
            
            url = url.strip()
            if monitor.add_test_url(url):
                return jsonify({'message': f'Added URL: {url}', 'urls': monitor.get_test_url_list()})
            else:
                # Check if URL is already in list
                current_urls = monitor.get_test_url_list()
                if url in current_urls:
                    return jsonify({'error': f'URL {url} already exists in test list'}), 400
                else:
                    return jsonify({'error': f'Invalid URL format: {url}. Must start with http:// or https://'}), 400
        except Exception as e:
            logger.error(f"Error adding test URL: {e}")
            return jsonify({'error': f'Error adding URL: {str(e)}'}), 500
    
    elif request.method == 'DELETE':
        if not current_user.can_edit():
            return jsonify({'error': 'Permission denied. Admin access required.'}), 403
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body required'}), 400
            
            url = data.get('url')
            if not url:
                return jsonify({'error': 'URL required'}), 400
            
            url = url.strip()
            if monitor.remove_test_url(url):
                return jsonify({'message': f'Removed URL: {url}', 'urls': monitor.get_test_url_list()})
            else:
                return jsonify({'error': f'URL not found: {url}'}), 404
        except Exception as e:
            logger.error(f"Error removing test URL: {e}")
            return jsonify({'error': f'Error removing URL: {str(e)}'}), 500

@app.route('/api/test-url-connection', methods=['POST'])
@login_required
def test_url_connection():
    """API endpoint to test URL connection through specific interface."""
    data = request.get_json()
    url = data.get('url')
    interface = data.get('interface')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    result = monitor.test_url_connection(url, interface)
    return jsonify(result)

@app.route('/api/test-all-urls', methods=['POST'])
@login_required
def test_all_urls():
    """API endpoint to test all URLs in the list through specified interface."""
    data = request.get_json() or {}
    interface = data.get('interface')
    
    results = monitor.test_all_urls(interface)
    return jsonify({'results': results})

@app.route('/api/test-url-all-interfaces', methods=['POST'])
@login_required
def test_url_all_interfaces():
    """API endpoint to test a specific URL through all available interfaces."""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    results = monitor.test_url_all_interfaces(url)
    return jsonify({'results': results, 'url': url})

@app.route('/api/traceroute', methods=['POST'])
@login_required
def traceroute_ip():
    """API endpoint to perform traceroute to an IP through specific interface."""
    data = request.get_json()
    ip = data.get('ip')
    interface = data.get('interface')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    result = monitor.traceroute_ip(ip, interface)
    return jsonify(result)

@app.route('/api/set-route', methods=['POST'])
@login_required
@can_edit_required
def set_route():
    """API endpoint to set route for an interface."""
    data = request.get_json()
    interface = data.get('interface')
    target_ip = data.get('target_ip')
    gateway = data.get('gateway')
    
    if not interface or not target_ip:
        return jsonify({'error': 'Interface and target IP required'}), 400
    
    result = monitor.set_route(interface, target_ip, gateway)
    return jsonify(result)

@app.route('/api/disable-route', methods=['POST'])
@login_required
@can_edit_required
def disable_route():
    """API endpoint to disable route for an interface."""
    data = request.get_json()
    interface = data.get('interface')
    
    if not interface:
        return jsonify({'error': 'Interface required'}), 400
    
    result = monitor.disable_route(interface)
    return jsonify(result)

@app.route('/api/enable-route', methods=['POST'])
@login_required
@can_edit_required
def enable_route():
    """API endpoint to enable route for an interface."""
    data = request.get_json()
    interface = data.get('interface')
    
    if not interface:
        return jsonify({'error': 'Interface required'}), 400
    
    result = monitor.enable_route(interface)
    return jsonify(result)

@app.route('/api/route-status')
@login_required
def get_route_status():
    """API endpoint to get route status."""
    interface = request.args.get('interface')
    status = monitor.get_route_status(interface)
    return jsonify(status)

@app.route('/api/monitor-routes')
@login_required
def monitor_routes():
    """API endpoint to monitor all routes."""
    route_data = monitor.monitor_all_routes()
    return jsonify(route_data)

@app.route('/api/test-route', methods=['POST'])
@login_required
def test_route():
    """API endpoint to test a specific route connection."""
    data = request.get_json()
    interface = data.get('interface')
    
    if not interface:
        return jsonify({'error': 'Interface required'}), 400
    
    result = monitor.test_route_connection(interface)
    return jsonify(result)

@app.route('/api/all-system-routes')
@login_required
def get_all_system_routes():
    """API endpoint to get all system routes with flag explanations."""
    routes_data = monitor.get_all_system_routes()
    return jsonify(routes_data)

@app.route('/api/save-configs', methods=['POST'])
@login_required
@can_edit_required
def save_configs():
    """API endpoint to manually save test IPs and routes to YAML files."""
    try:
        test_ips_saved = monitor.save_test_ips_to_file()
        routes_saved = monitor.save_routes_to_file()
        
        return jsonify({
            'success': True,
            'test_ips_saved': test_ips_saved,
            'routes_saved': routes_saved,
            'message': 'Configurations saved successfully'
        })
    except Exception as e:
        logger.error(f"Error saving configurations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/reload-configs', methods=['POST'])
@login_required
@can_edit_required
def reload_configs():
    """API endpoint to reload test IPs, URLs and routes from YAML files."""
    try:
        test_ips_loaded = monitor.load_test_ips_from_file()
        test_urls_loaded = monitor.load_test_urls_from_file()
        routes_loaded = monitor.load_routes_from_file()
        
        return jsonify({
            'success': True,
            'test_ips_loaded': test_ips_loaded,
            'test_urls_loaded': test_urls_loaded,
            'routes_loaded': routes_loaded,
            'message': 'Configurations reloaded successfully',
            'test_ips': monitor.get_test_ip_list(),
            'test_urls': monitor.get_test_url_list(),
            'routes': monitor.get_route_status().get('configured_routes', {})
        })
    except Exception as e:
        logger.error(f"Error reloading configurations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Rsync routes
@app.route('/rsync')
@login_required
def rsync_page():
    """Rsync management page."""
    return render_template('rsync.html')

@app.route('/api/rsync/jobs', methods=['GET'])
@login_required
def get_rsync_jobs():
    """Get all rsync jobs."""
    try:
        jobs = rsync_manager.get_all_jobs()
        return jsonify({'success': True, 'jobs': jobs})
    except Exception as e:
        logger.error(f"Error getting rsync jobs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs', methods=['POST'])
@login_required
@can_edit_required
def create_rsync_job():
    """Create a new rsync job."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        job_id = rsync_manager.add_job(data)
        return jsonify({'success': True, 'job_id': job_id, 'message': 'Job created successfully'})
    except Exception as e:
        logger.error(f"Error creating rsync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs/<job_id>', methods=['PUT'])
@login_required
@can_edit_required
def update_rsync_job(job_id):
    """Update an rsync job."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        if rsync_manager.update_job(job_id, data):
            return jsonify({'success': True, 'message': 'Job updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
    except Exception as e:
        logger.error(f"Error updating rsync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs/<job_id>', methods=['DELETE'])
@login_required
@can_edit_required
def delete_rsync_job(job_id):
    """Delete an rsync job."""
    try:
        if rsync_manager.delete_job(job_id):
            return jsonify({'success': True, 'message': 'Job deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting rsync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs/<job_id>/start', methods=['POST'])
@login_required
@can_edit_required
def start_rsync_job(job_id):
    """Start an rsync job."""
    try:
        data = request.get_json() or {}
        persistent = data.get('persistent', False)
        
        if rsync_manager.start_job(job_id, persistent=persistent):
            return jsonify({'success': True, 'message': 'Job started successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or already running'}), 400
    except Exception as e:
        logger.error(f"Error starting rsync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs/<job_id>/stop', methods=['POST'])
@login_required
@can_edit_required
def stop_rsync_job(job_id):
    """Stop an rsync job."""
    try:
        if rsync_manager.stop_job(job_id):
            return jsonify({'success': True, 'message': 'Job stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or not running'}), 400
    except Exception as e:
        logger.error(f"Error stopping rsync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs/<job_id>/run-once', methods=['POST'])
@login_required
@can_edit_required
def run_rsync_job_once(job_id):
    """Run an rsync job once."""
    try:
        if rsync_manager.run_job_once(job_id):
            return jsonify({'success': True, 'message': 'Job started successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or already running'}), 400
    except Exception as e:
        logger.error(f"Error running rsync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs/<job_id>/logs', methods=['GET'])
@login_required
def get_rsync_job_logs(job_id):
    """Get logs for an rsync job."""
    try:
        limit = request.args.get('limit', 100, type=int)
        logs = rsync_manager.get_job_logs(job_id, limit=limit)
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        logger.error(f"Error getting rsync job logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rsync/jobs/<job_id>/command', methods=['GET'])
@login_required
def get_rsync_job_command(job_id):
    """Get the rsync command string for a job."""
    try:
        command = rsync_manager.get_job_command(job_id)
        if command:
            return jsonify({'success': True, 'command': command})
        else:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
    except Exception as e:
        logger.error(f"Error getting rsync job command: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# WebSocket handlers for real-time monitoring
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logger.info('Client connected')
    emit('connected', {'message': 'Connected to rsync monitor'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.info('Client disconnected')

@socketio.on('subscribe_job')
def handle_subscribe_job(data):
    """Subscribe to a job's real-time output."""
    job_id = data.get('job_id')
    if job_id:
        # Set up callback for this job
        def output_callback(output_data):
            socketio.emit('job_output', {
                'job_id': job_id,
                'data': output_data
            })
        
        rsync_manager.set_output_callback(job_id, output_callback)
        emit('subscribed', {'job_id': job_id, 'message': 'Subscribed to job output'})

@socketio.on('unsubscribe_job')
def handle_unsubscribe_job(data):
    """Unsubscribe from a job's real-time output."""
    job_id = data.get('job_id')
    if job_id and job_id in rsync_manager.output_callbacks:
        del rsync_manager.output_callbacks[job_id]
        emit('unsubscribed', {'job_id': job_id, 'message': 'Unsubscribed from job output'})

# PostgreSQL Sync routes
@app.route('/postgres-sync')
@login_required
def postgres_sync_page():
    """PostgreSQL sync management page."""
    return render_template('postgres-sync.html')

@app.route('/api/postgres-sync/jobs', methods=['GET'])
@login_required
def get_postgres_sync_jobs():
    """Get all PostgreSQL sync jobs."""
    try:
        jobs = postgres_sync_manager.get_all_jobs()
        return jsonify({'success': True, 'jobs': jobs})
    except Exception as e:
        logger.error(f"Error getting PostgreSQL sync jobs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs', methods=['POST'])
@login_required
@can_edit_required
def create_postgres_sync_job():
    """Create a new PostgreSQL sync job."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        job_id = postgres_sync_manager.add_job(data)
        return jsonify({'success': True, 'job_id': job_id, 'message': 'Job created successfully'})
    except Exception as e:
        logger.error(f"Error creating PostgreSQL sync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>', methods=['PUT'])
@login_required
@can_edit_required
def update_postgres_sync_job(job_id):
    """Update a PostgreSQL sync job."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        if postgres_sync_manager.update_job(job_id, data):
            return jsonify({'success': True, 'message': 'Job updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
    except Exception as e:
        logger.error(f"Error updating PostgreSQL sync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>', methods=['DELETE'])
@login_required
@can_edit_required
def delete_postgres_sync_job(job_id):
    """Delete a PostgreSQL sync job."""
    try:
        if postgres_sync_manager.delete_job(job_id):
            return jsonify({'success': True, 'message': 'Job deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting PostgreSQL sync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>/start', methods=['POST'])
@login_required
@can_edit_required
def start_postgres_sync_job(job_id):
    """Start a PostgreSQL sync job."""
    try:
        data = request.get_json() or {}
        persistent = data.get('persistent', False)
        
        if postgres_sync_manager.start_job(job_id, persistent=persistent):
            return jsonify({'success': True, 'message': 'Job started successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or already running'}), 400
    except Exception as e:
        logger.error(f"Error starting PostgreSQL sync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>/stop', methods=['POST'])
@login_required
@can_edit_required
def stop_postgres_sync_job(job_id):
    """Stop a PostgreSQL sync job (stops both task and persistent mode)."""
    try:
        if postgres_sync_manager.stop_job(job_id):
            return jsonify({'success': True, 'message': 'Job stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or not running'}), 400
    except Exception as e:
        logger.error(f"Error stopping PostgreSQL sync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>/stop-task', methods=['POST'])
@login_required
@can_edit_required
def stop_postgres_sync_task(job_id):
    """Stop only the currently running task, keep persistent mode enabled."""
    try:
        if postgres_sync_manager.stop_task(job_id):
            return jsonify({'success': True, 'message': 'Task stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or task not running'}), 400
    except Exception as e:
        logger.error(f"Error stopping PostgreSQL sync task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>/stop-persistent', methods=['POST'])
@login_required
@can_edit_required
def stop_postgres_sync_persistent(job_id):
    """Stop persistent mode, allow current task to finish if running."""
    try:
        if postgres_sync_manager.stop_persistent(job_id):
            return jsonify({'success': True, 'message': 'Persistent mode stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or persistent mode not enabled'}), 400
    except Exception as e:
        logger.error(f"Error stopping PostgreSQL sync persistent mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>/run-once', methods=['POST'])
@login_required
@can_edit_required
def run_postgres_sync_job_once(job_id):
    """Run a PostgreSQL sync job once."""
    try:
        if postgres_sync_manager.run_job_once(job_id):
            return jsonify({'success': True, 'message': 'Job started successfully'})
        else:
            return jsonify({'success': False, 'error': 'Job not found or already running'}), 400
    except Exception as e:
        logger.error(f"Error running PostgreSQL sync job: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/postgres-sync/jobs/<job_id>/logs', methods=['GET'])
@login_required
def get_postgres_sync_job_logs(job_id):
    """Get logs for a PostgreSQL sync job."""
    try:
        logs = postgres_sync_manager.get_job_logs(job_id)
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        logger.error(f"Error getting PostgreSQL sync job logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('subscribe_postgres_job')
def handle_subscribe_postgres_job(data):
    """Subscribe to a PostgreSQL sync job's real-time output."""
    job_id = data.get('job_id')
    if job_id:
        # Set up callback for this job
        def output_callback(output_data):
            socketio.emit('postgres_job_output', {
                'job_id': job_id,
                'data': output_data
            })
        
        postgres_sync_manager.set_output_callback(job_id, output_callback)
        emit('subscribed', {'job_id': job_id, 'message': 'Subscribed to job output'})

@socketio.on('unsubscribe_postgres_job')
def handle_unsubscribe_postgres_job(data):
    """Unsubscribe from a PostgreSQL sync job's real-time output."""
    job_id = data.get('job_id')
    if job_id and job_id in postgres_sync_manager.output_callbacks:
        del postgres_sync_manager.output_callbacks[job_id]
        emit('unsubscribed', {'job_id': job_id, 'message': 'Unsubscribed from job output'})

# Autossh routes
@app.route('/autossh')
@login_required
def autossh_page():
    """Autossh management page."""
    return render_template('autossh.html')

@app.route('/api/autossh/tunnels', methods=['GET'])
@login_required
def get_autossh_tunnels():
    """Get all autossh tunnels."""
    try:
        tunnels = autossh_manager.get_all_tunnels()
        return jsonify({'success': True, 'tunnels': tunnels})
    except Exception as e:
        logger.error(f"Error getting autossh tunnels: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/tunnels', methods=['POST'])
@login_required
@can_edit_required
def create_autossh_tunnel():
    """Create a new autossh tunnel."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        tunnel_id = autossh_manager.add_tunnel(data)
        return jsonify({'success': True, 'tunnel_id': tunnel_id, 'message': 'Tunnel created successfully'})
    except Exception as e:
        logger.error(f"Error creating autossh tunnel: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/tunnels/<tunnel_id>', methods=['PUT'])
@login_required
@can_edit_required
def update_autossh_tunnel(tunnel_id):
    """Update an autossh tunnel."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        if autossh_manager.update_tunnel(tunnel_id, data):
            return jsonify({'success': True, 'message': 'Tunnel updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Tunnel not found or is running'}), 404
    except Exception as e:
        logger.error(f"Error updating autossh tunnel: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/tunnels/<tunnel_id>', methods=['DELETE'])
@login_required
@can_edit_required
def delete_autossh_tunnel(tunnel_id):
    """Delete an autossh tunnel."""
    try:
        if autossh_manager.delete_tunnel(tunnel_id):
            return jsonify({'success': True, 'message': 'Tunnel deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Tunnel not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting autossh tunnel: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/tunnels/<tunnel_id>/start', methods=['POST'])
@login_required
@can_edit_required
def start_autossh_tunnel(tunnel_id):
    """Start an autossh tunnel."""
    try:
        if autossh_manager.start_tunnel(tunnel_id):
            return jsonify({'success': True, 'message': 'Tunnel started successfully'})
        else:
            return jsonify({'success': False, 'error': 'Tunnel not found or already running'}), 400
    except Exception as e:
        logger.error(f"Error starting autossh tunnel: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/tunnels/<tunnel_id>/stop', methods=['POST'])
@login_required
@can_edit_required
def stop_autossh_tunnel(tunnel_id):
    """Stop an autossh tunnel."""
    try:
        if autossh_manager.stop_tunnel(tunnel_id):
            return jsonify({'success': True, 'message': 'Tunnel stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Tunnel not found or not running'}), 400
    except Exception as e:
        logger.error(f"Error stopping autossh tunnel: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/tunnels/<tunnel_id>/logs', methods=['GET'])
@login_required
def get_autossh_tunnel_logs(tunnel_id):
    """Get logs for an autossh tunnel (last 30 entries)."""
    try:
        limit = request.args.get('limit', 30, type=int)
        logs = autossh_manager.get_tunnel_logs(tunnel_id, limit=limit)
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        logger.error(f"Error getting autossh tunnel logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/tunnels/<tunnel_id>/command', methods=['GET'])
@login_required
def get_autossh_tunnel_command(tunnel_id):
    """Get the autossh command string for a tunnel."""
    try:
        command = autossh_manager.get_tunnel_command(tunnel_id)
        if command:
            return jsonify({'success': True, 'command': command})
        else:
            return jsonify({'success': False, 'error': 'Tunnel not found'}), 404
    except Exception as e:
        logger.error(f"Error getting autossh tunnel command: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/ssh-connections', methods=['GET'])
@login_required
def get_ssh_connections():
    """Get all active SSH connections on the system."""
    try:
        connections = monitor.get_ssh_connections()
        return jsonify({'success': True, 'connections': connections})
    except Exception as e:
        logger.error(f"Error getting SSH connections: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/ssh-connections/<int:pid>/kill', methods=['POST'])
@login_required
@can_edit_required
def kill_ssh_connection(pid):
    """Kill an SSH connection by PID."""
    try:
        result = monitor.kill_ssh_connection(pid)
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    except Exception as e:
        logger.error(f"Error killing SSH connection {pid}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/autossh/ssh-connections/kill-log', methods=['GET'])
@login_required
def get_killed_ssh_connections_log():
    """Get the log of killed SSH connections."""
    try:
        log = monitor.get_killed_ssh_connections_log()
        return jsonify({'success': True, 'log': log})
    except Exception as e:
        logger.error(f"Error getting kill log: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('subscribe_autossh_tunnel')
def handle_subscribe_autossh_tunnel(data):
    """Subscribe to an autossh tunnel's real-time output."""
    tunnel_id = data.get('tunnel_id')
    if tunnel_id:
        # Set up callback for this tunnel
        def output_callback(output_data):
            socketio.emit('autossh_tunnel_output', {
                'tunnel_id': tunnel_id,
                'data': output_data
            })
        
        autossh_manager.set_output_callback(tunnel_id, output_callback)
        emit('subscribed', {'tunnel_id': tunnel_id, 'message': 'Subscribed to tunnel output'})

@socketio.on('unsubscribe_autossh_tunnel')
def handle_unsubscribe_autossh_tunnel(data):
    """Unsubscribe from an autossh tunnel's real-time output."""
    tunnel_id = data.get('tunnel_id')
    if tunnel_id and tunnel_id in autossh_manager.output_callbacks:
        del autossh_manager.output_callbacks[tunnel_id]
        emit('unsubscribed', {'tunnel_id': tunnel_id, 'message': 'Unsubscribed from tunnel output'})

# Ollama Gateway routes
@app.route('/ollama-gateway')
@login_required
def ollama_gateway_page():
    """Ollama Gateway management page."""
    return render_template('ollama-gateway.html')


@app.route('/api/ollama-gateway/api-keys', methods=['GET'])
@login_required
def get_ollama_api_keys():
    """Get all API keys."""
    try:
        keys = ollama_gateway_manager.get_all_api_keys()
        return jsonify({'success': True, 'api_keys': keys})
    except Exception as e:
        logger.error(f"Error getting API keys: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/api-keys', methods=['POST'])
@login_required
@can_edit_required
def create_ollama_api_key():
    """Create a new API key."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        result = ollama_gateway_manager.generate_api_key(
            name=data.get('name', ''),
            description=data.get('description', ''),
            rate_limit=data.get('rate_limit'),
            token_limit=data.get('token_limit')
        )
        return jsonify({'success': True, **result})
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/api-keys/<api_key>', methods=['PUT'])
@login_required
@can_edit_required
def update_ollama_api_key(api_key):
    """Update an API key."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        success = ollama_gateway_manager.update_api_key(api_key, data)
        if success:
            return jsonify({'success': True, 'message': 'API key updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'API key not found'}), 404
    except Exception as e:
        logger.error(f"Error updating API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/api-keys/<api_key>/revoke', methods=['POST'])
@login_required
@can_edit_required
def revoke_ollama_api_key(api_key):
    """Revoke an API key."""
    try:
        success = ollama_gateway_manager.revoke_api_key(api_key)
        if success:
            return jsonify({'success': True, 'message': 'API key revoked successfully'})
        else:
            return jsonify({'success': False, 'error': 'API key not found'}), 404
    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/api-keys/<api_key>', methods=['DELETE'])
@login_required
@can_edit_required
def delete_ollama_api_key(api_key):
    """Delete an API key."""
    try:
        success = ollama_gateway_manager.delete_api_key(api_key)
        if success:
            return jsonify({'success': True, 'message': 'API key deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'API key not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/statistics', methods=['GET'])
@login_required
def get_ollama_statistics():
    """Get statistics for API key(s)."""
    try:
        api_key = request.args.get('api_key')
        stats = ollama_gateway_manager.get_statistics(api_key)
        return jsonify({'success': True, 'statistics': stats})
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/queue/status', methods=['GET'])
@login_required
def get_ollama_queue_status():
    """Get queue status for all tasks or a specific task."""
    try:
        task_id = request.args.get('task_id')
        status = ollama_gateway_manager.get_queue_status(task_id)
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logger.error(f"Error getting queue status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks', methods=['GET'])
@login_required
def get_ollama_tasks():
    """Get all tasks."""
    try:
        tasks = ollama_gateway_manager.get_all_tasks()
        return jsonify({'success': True, 'tasks': tasks})
    except Exception as e:
        logger.error(f"Error getting tasks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks', methods=['POST'])
@login_required
@can_edit_required
def create_ollama_task():
    """Create a new task."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        task_id = ollama_gateway_manager.add_task(data)
        return jsonify({'success': True, 'task_id': task_id, 'message': 'Task created successfully'})
    except Exception as e:
        logger.error(f"Error creating task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks/<task_id>', methods=['PUT'])
@login_required
@can_edit_required
def update_ollama_task(task_id):
    """Update a task."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        success = ollama_gateway_manager.update_task(task_id, data)
        if success:
            return jsonify({'success': True, 'message': 'Task updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found or is running'}), 404
    except Exception as e:
        logger.error(f"Error updating task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks/<task_id>', methods=['DELETE'])
@login_required
@can_edit_required
def delete_ollama_task(task_id):
    """Delete a task."""
    try:
        success = ollama_gateway_manager.delete_task(task_id)
        if success:
            return jsonify({'success': True, 'message': 'Task deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks/<task_id>/start', methods=['POST'])
@login_required
@can_edit_required
def start_ollama_task(task_id):
    """Start a task."""
    try:
        success = ollama_gateway_manager.start_task(task_id)
        if success:
            return jsonify({'success': True, 'message': 'Task started successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found or already running'}), 400
    except Exception as e:
        logger.error(f"Error starting task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks/<task_id>/stop', methods=['POST'])
@login_required
@can_edit_required
def stop_ollama_task(task_id):
    """Stop a task."""
    try:
        success = ollama_gateway_manager.stop_task(task_id)
        if success:
            return jsonify({'success': True, 'message': 'Task stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found or not running'}), 400
    except Exception as e:
        logger.error(f"Error stopping task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks/<task_id>/monitor', methods=['GET'])
@login_required
def get_ollama_task_monitor(task_id):
    """Get job history/monitor for a task."""
    try:
        limit = request.args.get('limit', 50, type=int)
        history = ollama_gateway_manager.get_task_job_history(task_id, limit=limit)
        return jsonify({'success': True, 'jobs': history})
    except Exception as e:
        logger.error(f"Error getting task monitor: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks/<task_id>/api-examples', methods=['GET'])
@login_required
def get_ollama_task_api_examples(task_id):
    """Get API usage examples for a task."""
    try:
        examples = ollama_gateway_manager.get_task_api_examples(task_id)
        return jsonify({'success': True, 'examples': examples})
    except Exception as e:
        logger.error(f"Error getting API examples: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ollama-gateway/tasks/<task_id>/models', methods=['GET'])
@login_required
def get_ollama_task_models(task_id):
    """Get available models from Ollama for a task."""
    try:
        models = ollama_gateway_manager.get_task_available_models(task_id)
        return jsonify({'success': models.get('success', True), 'data': models})
    except Exception as e:
        logger.error(f"Error getting models: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# LiteLLM routes
@app.route('/litellm')
@login_required
def litellm_page():
    """LiteLLM management page."""
    return render_template('litellm.html')

@app.route('/api/litellm/tasks', methods=['GET'])
@login_required
def get_litellm_tasks():
    """Get all tasks."""
    try:
        tasks = litellm_manager.get_all_tasks()
        return jsonify({'success': True, 'tasks': tasks})
    except Exception as e:
        logger.error(f"Error getting tasks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks', methods=['POST'])
@login_required
@can_edit_required
def create_litellm_task():
    """Create a new task."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        task_id = litellm_manager.add_task(data)
        return jsonify({'success': True, 'task_id': task_id, 'message': 'Task created successfully'})
    except Exception as e:
        logger.error(f"Error creating task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks/<task_id>', methods=['PUT'])
@login_required
@can_edit_required
def update_litellm_task(task_id):
    """Update a task."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        success = litellm_manager.update_task(task_id, data)
        if success:
            return jsonify({'success': True, 'message': 'Task updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found or is running'}), 404
    except Exception as e:
        logger.error(f"Error updating task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks/<task_id>', methods=['DELETE'])
@login_required
@can_edit_required
def delete_litellm_task(task_id):
    """Delete a task."""
    try:
        success = litellm_manager.delete_task(task_id)
        if success:
            return jsonify({'success': True, 'message': 'Task deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks/<task_id>/start', methods=['POST'])
@login_required
@can_edit_required
def start_litellm_task(task_id):
    """Start a task."""
    try:
        success = litellm_manager.start_task(task_id)
        if success:
            return jsonify({'success': True, 'message': 'Task started successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found or already running'}), 400
    except Exception as e:
        logger.error(f"Error starting task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks/<task_id>/stop', methods=['POST'])
@login_required
@can_edit_required
def stop_litellm_task(task_id):
    """Stop a task."""
    try:
        success = litellm_manager.stop_task(task_id)
        if success:
            return jsonify({'success': True, 'message': 'Task stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Task not found or not running'}), 400
    except Exception as e:
        logger.error(f"Error stopping task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks/<task_id>/api-keys', methods=['GET'])
@login_required
def get_litellm_task_api_keys(task_id):
    """Get all API keys for a task."""
    try:
        keys = litellm_manager.get_task_api_keys(task_id)
        return jsonify({'success': True, 'api_keys': keys})
    except Exception as e:
        logger.error(f"Error getting API keys: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks/<task_id>/api-keys', methods=['POST'])
@login_required
@can_edit_required
def create_litellm_api_key(task_id):
    """Create a new API key for a task."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        result = litellm_manager.generate_api_key(
            task_id=task_id,
            name=data.get('name', ''),
            description=data.get('description', '')
        )
        return jsonify({'success': True, **result})
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/api-keys/<api_key>/revoke', methods=['POST'])
@login_required
@can_edit_required
def revoke_litellm_api_key(api_key):
    """Revoke an API key."""
    try:
        success = litellm_manager.revoke_api_key(api_key)
        if success:
            return jsonify({'success': True, 'message': 'API key revoked successfully'})
        else:
            return jsonify({'success': False, 'error': 'API key not found'}), 404
    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/api-keys/<api_key>', methods=['DELETE'])
@login_required
@can_edit_required
def delete_litellm_api_key(api_key):
    """Delete an API key."""
    try:
        success = litellm_manager.delete_api_key(api_key)
        if success:
            return jsonify({'success': True, 'message': 'API key deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'API key not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/statistics', methods=['GET'])
@login_required
def get_litellm_statistics():
    """Get statistics for task(s) or API key(s)."""
    try:
        task_id = request.args.get('task_id')
        api_key = request.args.get('api_key')
        stats = litellm_manager.get_statistics(task_id=task_id, api_key=api_key)
        return jsonify({'success': True, 'statistics': stats})
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/token-records', methods=['GET'])
@login_required
def get_litellm_token_records():
    """Get token records from database."""
    try:
        task_id = request.args.get('task_id')
        api_key = request.args.get('api_key')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = request.args.get('limit', 100, type=int)
        
        records = litellm_manager.get_token_records(
            task_id=task_id,
            api_key=api_key,
            start_date=start_date,
            end_date=end_date,
            limit=limit
        )
        return jsonify({'success': True, 'records': records, 'count': len(records)})
    except Exception as e:
        logger.error(f"Error getting token records: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/litellm/tasks/<task_id>/api-examples', methods=['GET'])
@login_required
def get_litellm_task_api_examples(task_id):
    """Get API usage examples and instructions for a task."""
    try:
        examples = litellm_manager.get_task_api_examples(task_id)
        return jsonify({'success': True, 'examples': examples})
    except Exception as e:
        logger.error(f"Error getting API examples: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

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
    
    socketio.run(app, debug=True, host='0.0.0.0', port=9100)
