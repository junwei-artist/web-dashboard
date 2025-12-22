# Next.js Frontend Setup

A Next.js frontend has been added to the System Monitor Dashboard, running on port 9200.

## Structure

The Next.js frontend is located in the `frontend-nextjs/` directory with the following structure:

```
frontend-nextjs/
├── app/                    # Next.js App Router pages
│   ├── page.tsx           # Main dashboard page
│   ├── login/             # Login page
│   ├── services/          # Services page
│   ├── ports/             # Ports page
│   └── clients/           # Clients page
├── lib/                   # Utility libraries
│   └── api.ts            # API client for backend communication
├── package.json           # Node.js dependencies
├── next.config.js         # Next.js configuration
└── tsconfig.json          # TypeScript configuration
```

## Setup Instructions

### 1. Install Backend Dependencies

First, install the new Flask-CORS dependency for the backend:

```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Install Frontend Dependencies

Navigate to the frontend directory and install Node.js dependencies:

```bash
cd frontend-nextjs
npm install
```

### 3. Start the Services

**Start the Backend (Port 9100):**
```bash
# From project root
python main.py
# Or use the launcher scripts:
./start_dashboard.command  # macOS/Linux
start_dashboard.bat         # Windows
```

**Start the Next.js Frontend (Port 9200):**
```bash
# From project root
./start_frontend.command    # macOS/Linux
start_frontend.bat          # Windows

# Or manually:
cd frontend-nextjs
npm run dev
```

### 4. Access the Application

- **Next.js Frontend:** http://localhost:9200
- **Original Flask Frontend:** http://localhost:9100

## Features

The Next.js frontend includes:

- **Dashboard Page** (`/`) - Overview with system metrics, database status, services, and ports
- **Services Page** (`/services`) - Detailed list of running services
- **Ports Page** (`/ports`) - Active ports monitoring
- **Clients Page** (`/clients`) - Active client connections
- **Login Page** (`/login`) - User authentication

## Configuration

### Backend URL

The frontend connects to the backend API at `http://localhost:9100` by default. To change this:

1. Create a `.env.local` file in `frontend-nextjs/`:
```
NEXT_PUBLIC_BACKEND_URL=http://your-backend-url:9100
```

2. Or set the environment variable:
```bash
export NEXT_PUBLIC_BACKEND_URL=http://your-backend-url:9100
```

## CORS Configuration

CORS has been enabled on the Flask backend to allow requests from the Next.js frontend. The backend now accepts requests from:
- `http://localhost:9200`
- `http://127.0.0.1:9200`

## Development

### Running in Development Mode

```bash
cd frontend-nextjs
npm run dev
```

### Building for Production

```bash
cd frontend-nextjs
npm run build
npm start
```

## Notes

- The frontend uses the same authentication system as the Flask backend (Flask-Login)
- Session cookies are used for authentication (withCredentials: true)
- Data refreshes automatically every 10 seconds
- The frontend makes direct API calls to the backend on port 9100

