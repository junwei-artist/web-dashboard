'use client';

import { useEffect, useState } from 'react';
import { api, Service } from '@/lib/api';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { useAuth } from '@/contexts/AuthContext';
import Link from 'next/link';
import '../globals.css';

function ServicesPageContent() {
  const { user, logout } = useAuth();
  const [services, setServices] = useState<Service[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  const fetchServices = async () => {
    try {
      setError(null);
      const data = await api.getServices();
      setServices(data);
      setLastUpdate(new Date());
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch services');
      console.error('Error fetching services:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
    // Refresh every 10 seconds
    const interval = setInterval(fetchServices, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading services...</div>
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
          <h1 style={{ fontSize: '2rem', marginBottom: '10px' }}>Services</h1>
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
        <h2>Running Services ({services.length})</h2>
        {services.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Service Name</th>
                <th>Status</th>
                <th>PID</th>
              </tr>
            </thead>
            <tbody>
              {services.map((service, index) => (
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
          <p>No services found</p>
        )}
      </div>
    </div>
  );
}

export default function ServicesPage() {
  return (
    <ProtectedRoute>
      <ServicesPageContent />
    </ProtectedRoute>
  );
}

