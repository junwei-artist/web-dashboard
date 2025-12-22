'use client';

import { useEffect, useState } from 'react';
import { api, Port } from '@/lib/api';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { useAuth } from '@/contexts/AuthContext';
import Link from 'next/link';
import '../globals.css';

function PortsPageContent() {
  const { user, logout } = useAuth();
  const [ports, setPorts] = useState<Port[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  const fetchPorts = async () => {
    try {
      setError(null);
      const data = await api.getPorts();
      setPorts(data);
      setLastUpdate(new Date());
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch ports');
      console.error('Error fetching ports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPorts();
    // Refresh every 10 seconds
    const interval = setInterval(fetchPorts, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading ports...</div>
      </div>
    );
  }

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  return (
    <div className="container">
      <header style={{ marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '2rem', marginBottom: '10px' }}>Active Ports</h1>
          <p style={{ color: '#666' }}>
            Last updated: {lastUpdate.toLocaleTimeString()}
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          {user && (
            <span style={{ color: '#666' }}>
              Logged in as: <strong>{user.username}</strong> ({user.role})
            </span>
          )}
          <button onClick={handleLogout} className="btn btn-secondary">
            Logout
          </button>
        </div>
      </header>

      <nav style={{ marginBottom: '30px' }}>
        <div style={{ display: 'flex', gap: '15px', flexWrap: 'wrap' }}>
          <Link href="/" className="btn btn-primary">
            Dashboard
          </Link>
          <Link href="/services" className="btn btn-secondary">
            Services
          </Link>
          <Link href="/ports" className="btn btn-secondary">
            Ports
          </Link>
          <Link href="/clients" className="btn btn-secondary">
            Clients
          </Link>
          <Link href="/network-interfaces" className="btn btn-secondary">
            Network Interfaces
          </Link>
          <Link href="/autossh" className="btn btn-secondary">
            Autossh
          </Link>
        </div>
      </nav>

      {error && <div className="error">{error}</div>}

      <div className="card">
        <h2>Active Ports ({ports.length})</h2>
        {ports.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Status</th>
                <th>Process</th>
              </tr>
            </thead>
            <tbody>
              {ports.map((port, index) => (
                <tr key={index}>
                  <td>{port.port || 'N/A'}</td>
                  <td>{port.protocol || 'N/A'}</td>
                  <td>
                    <span
                      className={`status-badge ${
                        port.status === 'LISTEN'
                          ? 'status-running'
                          : 'status-unknown'
                      }`}
                    >
                      {port.status || 'Unknown'}
                    </span>
                  </td>
                  <td>{port.process || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No ports found</p>
        )}
      </div>
    </div>
  );
}

export default function PortsPage() {
  return (
    <ProtectedRoute>
      <PortsPageContent />
    </ProtectedRoute>
  );
}

