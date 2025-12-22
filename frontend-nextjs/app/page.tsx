'use client';

import { useEffect, useState } from 'react';
import { api, MonitoringData } from '@/lib/api';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { useAuth } from '@/contexts/AuthContext';
import Link from 'next/link';
import './globals.css';

function DashboardContent() {
  const { user, logout } = useAuth();
  const [data, setData] = useState<MonitoringData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  const fetchData = async () => {
    try {
      setError(null);
      const monitoringData = await api.getMonitoringData();
      setData(monitoringData);
      setLastUpdate(new Date());
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch monitoring data');
      console.error('Error fetching data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Refresh every 10 seconds
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading dashboard data...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container">
        <div className="error">
          <h2>Error</h2>
          <p>{error}</p>
          <button className="btn btn-primary" onClick={fetchData}>
            Retry
          </button>
        </div>
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
          <h1 style={{ fontSize: '2rem', marginBottom: '10px' }}>
            System Monitor Dashboard
          </h1>
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

      <div className="grid">
        <div className="card">
          <h2>System Information</h2>
          {data?.system_info && (
            <div>
              <p>
                <strong>Hostname:</strong> {data.system_info.hostname || 'N/A'}
              </p>
              <p>
                <strong>Platform:</strong> {data.system_info.platform || 'N/A'}
              </p>
              <p>
                <strong>CPU Count:</strong> {data.system_info.cpu_count || 'N/A'}
              </p>
              <p>
                <strong>Memory Total:</strong>{' '}
                {data.system_info.memory_total
                  ? `${(data.system_info.memory_total / 1024 / 1024 / 1024).toFixed(2)} GB`
                  : 'N/A'}
              </p>
            </div>
          )}
        </div>

        <div className="card">
          <h2>MySQL Status</h2>
          {data?.mysql ? (
            <div>
              <span
                className={`status-badge ${
                  data.mysql.status === 'running'
                    ? 'status-running'
                    : 'status-stopped'
                }`}
              >
                {data.mysql.status || 'Unknown'}
              </span>
              {data.mysql.version && (
                <p style={{ marginTop: '10px' }}>
                  <strong>Version:</strong> {data.mysql.version}
                </p>
              )}
            </div>
          ) : (
            <p>No MySQL data available</p>
          )}
        </div>

        <div className="card">
          <h2>PostgreSQL Status</h2>
          {data?.postgresql ? (
            <div>
              <span
                className={`status-badge ${
                  data.postgresql.status === 'running'
                    ? 'status-running'
                    : 'status-stopped'
                }`}
              >
                {data.postgresql.status || 'Unknown'}
              </span>
              {data.postgresql.version && (
                <p style={{ marginTop: '10px' }}>
                  <strong>Version:</strong> {data.postgresql.version}
                </p>
              )}
            </div>
          ) : (
            <p>No PostgreSQL data available</p>
          )}
        </div>
      </div>

      <div className="card">
        <h2>Running Services ({data?.services?.length || 0})</h2>
        {data?.services && data.services.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Service Name</th>
                <th>Status</th>
                <th>PID</th>
              </tr>
            </thead>
            <tbody>
              {data.services.slice(0, 10).map((service: any, index: number) => (
                <tr key={index}>
                  <td>{service.name || 'N/A'}</td>
                  <td>
                    <span
                      className={`status-badge ${
                        service.status === 'running'
                          ? 'status-running'
                          : 'status-stopped'
                      }`}
                    >
                      {service.status || 'Unknown'}
                    </span>
                  </td>
                  <td>{service.pid || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No services data available</p>
        )}
      </div>

      <div className="card">
        <h2>Active Ports ({data?.ports?.length || 0})</h2>
        {data?.ports && data.ports.length > 0 ? (
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
              {data.ports.slice(0, 10).map((port: any, index: number) => (
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
          <p>No ports data available</p>
        )}
      </div>
    </div>
  );
}

export default function Dashboard() {
  return (
    <ProtectedRoute>
      <DashboardContent />
    </ProtectedRoute>
  );
}

