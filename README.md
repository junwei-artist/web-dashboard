# System Monitor Web Dashboard

A comprehensive web application for monitoring system services, active ports, and database status. Built with Python Flask backend and modern HTML/CSS/JavaScript frontend.

## Features

- **Real-time System Monitoring**: CPU usage, memory usage, disk usage, and system uptime
- **Service Monitoring**: View all running processes with CPU and memory usage
- **Port Monitoring**: Track active network connections and listening ports
- **Database Status**: Monitor MySQL and PostgreSQL database status
- **Modern Web Interface**: Responsive design with Bootstrap and Font Awesome icons
- **Auto-refresh**: Real-time updates every 5 seconds
- **RESTful API**: JSON endpoints for programmatic access

## Project Structure

```
web_dashboard/
├── src/                    # Source code directory
│   ├── __init__.py        # Package initialization
│   ├── backend.py         # Core monitoring logic
│   ├── frontend.py        # Flask web application
│   ├── templates/         # HTML templates
│   │   ├── base.html     # Base template with navigation
│   │   ├── dashboard.html # Main dashboard page
│   │   ├── services.html # Services monitoring page
│   │   ├── ports.html    # Ports monitoring page
│   │   ├── databases.html # Database status page
│   │   ├── system.html   # System information page
│   │   ├── 404.html      # 404 error page
│   │   └── 500.html      # 500 error page
│   └── static/           # Static assets (CSS, JS)
│       ├── css/
│       └── js/
├── main.py               # Main entry point
├── test_backend.py       # Backend testing script
├── install.command       # macOS/Linux installation script
├── install.bat           # Windows installation script
├── start_dashboard.command # macOS/Linux launcher script
├── start_dashboard.bat   # Windows launcher script
├── setup.py              # Package setup
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
├── LICENSE               # MIT License
├── .gitignore            # Git ignore rules
├── MANIFEST.in           # Package manifest
└── venv/                 # Virtual environment
```

## Installation

### Prerequisites
- Python 3.13+
- pip (Python package installer)
- Homebrew (macOS/Linux) - for automatic Python installation

### Option 1: Automated Installation (Recommended)

**macOS/Linux:**
```bash
# From anywhere on your system
/path/to/web_dashboard/install.command

# Or from the project directory
./install.command
```

**Windows:**
```cmd
REM From anywhere on your system
C:\path\to\web_dashboard\install.bat

REM Or from the project directory
install.bat
```

The installation scripts will:
- ✅ **Check for Python 3.13** and install it if needed (macOS/Linux)
- ✅ **Create virtual environment** automatically
- ✅ **Install all dependencies** from requirements.txt
- ✅ **Run setup.py** for package installation
- ✅ **Verify installation** and show next steps

### Option 2: Manual Installation

1. **Create and activate virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
   ```

3. **Install the package**:
   ```bash
   pip install -e .
   ```

## Usage

### Running the Application

#### Option 1: Using the Launcher Scripts (Recommended)

**macOS/Linux:**
```bash
# From anywhere on your system
/path/to/web_dashboard/start_dashboard.command

# Or from the project directory
./start_dashboard.command
```

**Windows:**
```cmd
REM From anywhere on your system
C:\path\to\web_dashboard\start_dashboard.bat

REM Or from the project directory
start_dashboard.bat
```

The launcher scripts will:
- ✅ **Auto-navigate** to the correct project directory
- ✅ **Automatically activate** the virtual environment
- ✅ **Check if required packages** are installed
- ✅ **Check for port conflicts** and provide options to resolve them
- ✅ **Start the application** with proper configuration

#### Option 2: Manual Start

1. **Start the web server**:
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   python main.py
   ```

2. **Access the dashboard**:
   - Open your browser and go to: `http://localhost:9100`
   - The dashboard will automatically refresh every 5 seconds

#### Command Line Options

You can also start the application with custom parameters:
```bash
python main.py --port 9101 --host 127.0.0.1 --debug
```

Available options:
- `--port`: Port to run the server on (default: 9100)
- `--host`: Host to bind the server to (default: 0.0.0.0)
- `--debug`: Enable debug mode (default: True)

### Testing the Backend

You can test the backend monitoring functionality independently:

```bash
source venv/bin/activate
python test_backend.py
```

## API Endpoints

The application provides several REST API endpoints:

- `GET /api/monitoring-data` - Get all monitoring data
- `GET /api/services` - Get running services
- `GET /api/ports` - Get active ports
- `GET /api/mysql` - Get MySQL status
- `GET /api/postgresql` - Get PostgreSQL status
- `GET /api/system-info` - Get system information

## Web Pages

- **Dashboard** (`/`) - Overview with system metrics and database status
- **Services** (`/services`) - Detailed view of running processes
- **Ports** (`/ports`) - Network connections and listening ports
- **Databases** (`/databases`) - MySQL and PostgreSQL status
- **System** (`/system`) - Detailed system information

## Features in Detail

### System Monitoring
- CPU usage percentage and core count
- Memory usage (total, available, percentage)
- Disk usage percentage
- System boot time and uptime

### Service Monitoring
- Process list with PID, name, status
- CPU and memory usage per process
- Sortable and searchable interface
- Real-time updates

### Port Monitoring
- Active network connections
- Listening ports with PID information
- Port service identification (SSH, HTTP, MySQL, etc.)
- IPv4/IPv6 family information

### Database Monitoring
- MySQL status and process information
- PostgreSQL status and process information
- Port accessibility testing
- Process count and details

## Dependencies

- **Flask** (2.3.3) - Web framework
- **psutil** (5.9.6) - System and process utilities
- **Werkzeug** (2.3.7) - WSGI toolkit
- **Jinja2** (3.1.2) - Template engine
- **MarkupSafe** (2.1.3) - Safe string handling
- **itsdangerous** (2.1.2) - Secure data handling
- **click** (8.1.7) - Command line interface
- **blinker** (1.6.3) - Signal handling

## Browser Compatibility

- Modern browsers with JavaScript support
- Bootstrap 5.1.3 for responsive design
- Font Awesome 6.0.0 for icons
- Auto-refresh functionality

## Security Notes

- The application runs on `0.0.0.0:9100` by default
- No authentication is implemented (suitable for local monitoring)
- Process information may require appropriate system permissions

## Troubleshooting

### Installation Issues

#### Python 3.13 Not Found (macOS/Linux)
If the installation script can't find Python 3.13:
1. **Install Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
2. **Run the installation script again**:
   ```bash
   ./install.command
   ```

#### Python 3.13 Not Found (Windows)
If the installation script can't find Python 3.13:
1. **Download Python 3.13** from https://www.python.org/downloads/
2. **During installation**, make sure to check "Add Python to PATH"
3. **Restart your command prompt** and run the installation script again:
   ```cmd
   install.bat
   ```

#### Virtual Environment Creation Failed
If virtual environment creation fails:
1. **Check Python installation**:
   ```bash
   python --version
   python3 --version
   ```
2. **Try creating venv manually**:
   ```bash
   python -m venv venv
   ```
3. **If still failing**, try with different Python executable:
   ```bash
   python3.13 -m venv venv
   ```

#### Dependency Installation Failed
If pip installation fails:
1. **Upgrade pip first**:
   ```bash
   python -m pip install --upgrade pip
   ```
2. **Try with trusted hosts**:
   ```bash
   pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
   ```
3. **Check internet connection** and firewall settings

### Port Already in Use
The launcher scripts automatically handle port conflicts by:
1. **Detecting** the process using the port
2. **Showing** process information (PID, name, memory usage)
3. **Providing options** to terminate the process or find an alternative port

If you prefer manual control, modify the port in `main.py`:
```python
app.run(debug=True, host='0.0.0.0', port=YOUR_PORT)
```

Or use command line arguments:
```bash
python main.py --port 9101
```

### Launcher Script Issues
- **macOS/Linux**: Ensure the script is executable: `chmod +x start_dashboard.command`
- **Windows**: Run as Administrator if you need to terminate processes
- **Permission denied**: The script may need elevated privileges to terminate processes

### SSL Certificate Issues
If you encounter SSL certificate issues during installation, use:
```bash
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
```

### Permission Issues
Some system information may require elevated permissions. Run with appropriate system access if needed.

## Development

The application is designed for easy extension:

1. **Add new monitoring features** in `src/backend.py`
2. **Create new API endpoints** in `src/frontend.py`
3. **Add new pages** by creating templates in `src/templates/`
4. **Customize styling** by modifying the base template

## License

This project is open source and available under the MIT License.
