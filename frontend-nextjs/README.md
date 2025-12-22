# System Monitor Dashboard - Next.js Frontend

This is the Next.js frontend for the System Monitor Dashboard, running on port 9200.

## Architecture

The Next.js frontend acts as a **proxy** to the Flask backend. All API requests from the client go through Next.js API routes, which then forward them to the backend. This provides:

- **Security**: Clients never directly access the backend
- **Control**: All requests can be logged, validated, or modified server-side
- **CORS**: No CORS issues since requests are server-to-server
- **Cookie Management**: Session cookies are properly forwarded through the proxy

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set the backend URL (optional, defaults to http://localhost:9100):
```bash
export BACKEND_URL=http://localhost:9100
```

Or create a `.env.local` file:
```
BACKEND_URL=http://localhost:9100
```

## Development

Run the development server:
```bash
npm run dev
```

The frontend will be available at http://localhost:9200

## Production

Build the application:
```bash
npm run build
```

Start the production server:
```bash
npm start
```

## API Proxy

All API requests are proxied through Next.js:

- Client requests: `/api/proxy/...` → Next.js API route → Backend
- Login: `/api/login` → Next.js API route → Backend `/login`
- Logout: `/api/logout` → Next.js API route → Backend `/logout`

The proxy automatically:
- Forwards request headers and cookies
- Forwards response headers and cookies (especially `Set-Cookie`)
- Preserves query parameters
- Handles all HTTP methods (GET, POST, PUT, DELETE, PATCH)

## Features

- Real-time monitoring dashboard
- Service status monitoring
- Port monitoring
- Database status (MySQL, PostgreSQL)
- Client monitoring
- System information display
- Autossh tunnel management
- Authentication with session management

## API Integration

The frontend connects to the Flask backend API through Next.js proxy routes. Make sure the backend is running on port 9100 before starting the frontend.

## Authentication

The frontend uses session-based authentication:
- Login credentials are sent through the Next.js proxy
- Session cookies are forwarded from backend to client
- All protected routes require authentication
- Authentication state is managed via React Context
