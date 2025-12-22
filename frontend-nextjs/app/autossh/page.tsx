'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { useAuth } from '@/contexts/AuthContext';
import Link from 'next/link';
import '../globals.css';

interface AutosshTunnel {
  tunnel_id: string;
  name: string;
  local_port: string;
  remote_port: string;
  vps_ip: string;
  vps_port: string;
  username: string;
  ssh_key_path?: string;
  remote_bind_address: string;
  server_alive_interval: number;
  server_alive_count_max: number;
  monitor_port: number;
  is_running: boolean;
  last_started: string | null;
  status: string;
}

interface TunnelLog {
  timestamp: string;
  type: string;
  message: string;
}

function AutosshPageContent() {
  const { user, logout } = useAuth();
  const [tunnels, setTunnels] = useState<AutosshTunnel[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [showForm, setShowForm] = useState(false);
  const [editingTunnel, setEditingTunnel] = useState<AutosshTunnel | null>(null);
  const [viewingLogs, setViewingLogs] = useState<string | null>(null);
  const [logs, setLogs] = useState<TunnelLog[]>([]);
  const [sshConnections, setSshConnections] = useState<any[]>([]);
  const [loadingSshConnections, setLoadingSshConnections] = useState(true);
  const [killLog, setKillLog] = useState<any[]>([]);
  
  // Form state
  const [formData, setFormData] = useState({
    name: '',
    local_port: '11434',
    remote_port: '',
    vps_ip: '',
    vps_port: '22',
    username: 'root',
    ssh_key_path: '~/.ssh/id_rsa',
    remote_bind_address: '0.0.0.0',
    server_alive_interval: 30,
    server_alive_count_max: 3,
    monitor_port: 0,
  });

  const fetchTunnels = async () => {
    try {
      setError(null);
      const response = await api.getAutosshTunnels();
      if (response.success) {
        setTunnels(response.tunnels);
        setLastUpdate(new Date());
      } else {
        setError(response.error || 'Failed to fetch tunnels');
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch tunnels');
      console.error('Error fetching tunnels:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchLogs = async (tunnelId: string) => {
    try {
      const response = await api.getAutosshTunnelLogs(tunnelId);
      if (response.success) {
        // Combine output and error logs, sort by timestamp
        const allLogs = [
          ...(response.logs.output || []),
          ...(response.logs.error || [])
        ].sort((a, b) => 
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
        );
        setLogs(allLogs);
      }
    } catch (err: any) {
      console.error('Error fetching logs:', err);
    }
  };

  const fetchSshConnections = async () => {
    try {
      setLoadingSshConnections(true);
      const response = await api.getSshConnections();
      if (response.success) {
        setSshConnections(response.connections);
      }
    } catch (err: any) {
      console.error('Error fetching SSH connections:', err);
    } finally {
      setLoadingSshConnections(false);
    }
  };

  const fetchKillLog = async () => {
    try {
      const response = await api.getKilledSshConnectionsLog();
      if (response.success) {
        setKillLog(response.log);
      }
    } catch (err: any) {
      console.error('Error fetching kill log:', err);
    }
  };

  const handleKillConnection = async (pid: number) => {
    if (!confirm(`Are you sure you want to kill process ${pid}? This action cannot be undone.`)) {
      return;
    }
    
    try {
      const response = await api.killSshConnection(pid);
      if (response.success) {
        alert(`Process ${pid} killed successfully.`);
        fetchSshConnections();
        fetchKillLog();
      } else {
        alert(`Error killing process: ${response.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      alert(`Error killing process: ${err.response?.data?.error || err.message}`);
    }
  };

  useEffect(() => {
    fetchTunnels();
    fetchSshConnections();
    fetchKillLog();
    // Refresh every 5 seconds
    const interval = setInterval(() => {
      fetchTunnels();
      fetchSshConnections();
      fetchKillLog();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (viewingLogs) {
      fetchLogs(viewingLogs);
      const interval = setInterval(() => fetchLogs(viewingLogs), 2000);
      return () => clearInterval(interval);
    }
  }, [viewingLogs]);

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (editingTunnel) {
        await api.updateAutosshTunnel(editingTunnel.tunnel_id, formData);
      } else {
        await api.createAutosshTunnel(formData);
      }
      setShowForm(false);
      setEditingTunnel(null);
      setFormData({
        name: '',
        local_port: '11434',
        remote_port: '',
        vps_ip: '',
        vps_port: '22',
        username: 'root',
        ssh_key_path: '~/.ssh/id_rsa',
        remote_bind_address: '0.0.0.0',
        server_alive_interval: 30,
        server_alive_count_max: 3,
        monitor_port: 0,
      });
      fetchTunnels();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to save tunnel');
    }
  };

  const handleEdit = (tunnel: AutosshTunnel) => {
    setEditingTunnel(tunnel);
    setFormData({
      name: tunnel.name,
      local_port: tunnel.local_port,
      remote_port: tunnel.remote_port || '',
      vps_ip: tunnel.vps_ip,
      vps_port: tunnel.vps_port,
      username: tunnel.username,
      ssh_key_path: (tunnel as any).ssh_key_path || '~/.ssh/id_rsa',
      remote_bind_address: tunnel.remote_bind_address,
      server_alive_interval: tunnel.server_alive_interval,
      server_alive_count_max: tunnel.server_alive_count_max,
      monitor_port: tunnel.monitor_port,
    });
    setShowForm(true);
  };

  const handleDelete = async (tunnelId: string) => {
    if (!confirm('Are you sure you want to delete this tunnel?')) return;
    try {
      await api.deleteAutosshTunnel(tunnelId);
      fetchTunnels();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to delete tunnel');
    }
  };

  const handleStart = async (tunnelId: string) => {
    try {
      await api.startAutosshTunnel(tunnelId);
      fetchTunnels();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to start tunnel');
    }
  };

  const handleStop = async (tunnelId: string) => {
    try {
      await api.stopAutosshTunnel(tunnelId);
      fetchTunnels();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to stop tunnel');
    }
  };

  const handleViewLogs = (tunnelId: string) => {
    setViewingLogs(tunnelId);
    fetchLogs(tunnelId);
  };

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading autossh tunnels...</div>
      </div>
    );
  }

  return (
    <div className="container">
      <header style={{ marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '2rem', marginBottom: '10px' }}>Autossh Tunnel Management</h1>
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
          <Link href="/autossh" className="btn btn-secondary">
            Autossh
          </Link>
        </div>
      </nav>

      {error && <div className="error">{error}</div>}

      {/* SSH Connections Monitor */}
      <div className="card" style={{ marginBottom: '30px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>All SSH Connections Monitor</h2>
          <button onClick={fetchSshConnections} className="btn btn-secondary" style={{ fontSize: '14px', padding: '5px 15px' }}>
            Refresh
          </button>
        </div>
        {loadingSshConnections ? (
          <div className="text-center text-muted">Loading SSH connections...</div>
        ) : sshConnections.length === 0 ? (
          <div className="alert alert-info">No active SSH connections found.</div>
        ) : (
          <div>
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Process</th>
                  <th>PID</th>
                  <th>Local Address</th>
                  <th>Remote Address</th>
                  <th>Status</th>
                  <th>Command</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sshConnections.map((conn, index) => {
                  const statusClass = conn.status === 'ESTABLISHED' ? 'status-running' : 
                                    conn.status === 'LISTEN' ? 'status-unknown' : 
                                    conn.status === 'TIME_WAIT' ? 'status-unknown' : 'status-stopped';
                  const cmdline = conn.cmdline && conn.cmdline.length > 100 
                    ? conn.cmdline.substring(0, 100) + '...' 
                    : conn.cmdline || 'N/A';
                  
                  const pid = conn.pid;
                  const canKill = pid && pid !== 'N/A' && typeof pid === 'number';
                  
                  return (
                    <tr key={index}>
                      <td>
                        <span className="status-badge status-running" style={{ fontSize: '12px' }}>
                          {conn.connection_type}
                        </span>
                      </td>
                      <td>{conn.process_name}</td>
                      <td>{pid}</td>
                      <td><code>{conn.local_address}</code></td>
                      <td><code>{conn.remote_address}</code></td>
                      <td>
                        <span className={`status-badge ${statusClass}`}>
                          {conn.status}
                        </span>
                      </td>
                      <td>
                        <small style={{ color: '#666' }} title={conn.cmdline}>
                          {cmdline}
                        </small>
                      </td>
                      <td>
                        {canKill ? (
                          <button
                            onClick={() => handleKillConnection(pid)}
                            className="btn btn-danger"
                            style={{ fontSize: '12px', padding: '5px 10px' }}
                            title="Kill this process"
                          >
                            Kill
                          </button>
                        ) : (
                          <span style={{ color: '#999' }}>N/A</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <div style={{ marginTop: '10px' }}>
              <small style={{ color: '#666' }}>Total: {sshConnections.length} SSH connection(s)</small>
            </div>
          </div>
        )}
      </div>

      {/* Kill Log */}
      <div className="card" style={{ marginBottom: '30px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>Killed SSH Connections Log</h2>
          <button onClick={fetchKillLog} className="btn btn-secondary" style={{ fontSize: '14px', padding: '5px 15px' }}>
            Refresh
          </button>
        </div>
        {killLog.length === 0 ? (
          <div className="alert alert-info">No killed connections logged yet.</div>
        ) : (
          <div>
            <table className="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>PID</th>
                  <th>Process Name</th>
                  <th>Command</th>
                  <th>Username</th>
                  <th>Killed Gracefully</th>
                </tr>
              </thead>
              <tbody>
                {killLog.map((entry, index) => {
                  const cmdline = entry.cmdline && entry.cmdline.length > 80 
                    ? entry.cmdline.substring(0, 80) + '...' 
                    : entry.cmdline || 'N/A';
                  
                  return (
                    <tr key={index}>
                      <td>{new Date(entry.timestamp).toLocaleString()}</td>
                      <td>{entry.pid}</td>
                      <td>{entry.process_name}</td>
                      <td>
                        <small style={{ color: '#666' }} title={entry.cmdline}>
                          {cmdline}
                        </small>
                      </td>
                      <td>{entry.username}</td>
                      <td>
                        {entry.killed_gracefully ? (
                          <span className="status-badge status-running">Yes</span>
                        ) : (
                          <span className="status-badge status-error">Force Killed</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div style={{ marginBottom: '20px' }}>
        <button 
          onClick={() => {
            setShowForm(!showForm);
            setEditingTunnel(null);
            setFormData({
              name: '',
              local_port: '11434',
              remote_port: '',
              vps_ip: '',
              vps_port: '22',
              username: 'root',
              remote_bind_address: '0.0.0.0',
              server_alive_interval: 30,
              server_alive_count_max: 3,
              monitor_port: 0,
            });
          }}
          className="btn btn-primary"
        >
          {showForm ? 'Cancel' : 'Add New Tunnel'}
        </button>
      </div>

      {showForm && (
        <div className="card" style={{ marginBottom: '30px' }}>
          <h2>{editingTunnel ? 'Edit Tunnel' : 'Create New Tunnel'}</h2>
          <form onSubmit={handleSubmit}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '15px' }}>
              <div>
                <label>Name:</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>Local Port:</label>
                <input
                  type="number"
                  value={formData.local_port}
                  onChange={(e) => setFormData({ ...formData, local_port: e.target.value })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>Remote Port (leave empty to use local port):</label>
                <input
                  type="number"
                  value={formData.remote_port}
                  onChange={(e) => setFormData({ ...formData, remote_port: e.target.value })}
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>VPS Server IP:</label>
                <input
                  type="text"
                  value={formData.vps_ip}
                  onChange={(e) => setFormData({ ...formData, vps_ip: e.target.value })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>VPS SSH Port:</label>
                <input
                  type="number"
                  value={formData.vps_port}
                  onChange={(e) => setFormData({ ...formData, vps_port: e.target.value })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>Username:</label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>SSH Private Key Path <span style={{ color: 'red' }}>*</span>:</label>
                <input
                  type="text"
                  value={formData.ssh_key_path}
                  onChange={(e) => setFormData({ ...formData, ssh_key_path: e.target.value })}
                  placeholder="~/.ssh/id_rsa"
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
                <small style={{ color: '#666', display: 'block', marginTop: '5px' }}>
                  Path to your SSH private key file (e.g., ~/.ssh/id_rsa). Required for authentication.
                </small>
              </div>
              <div style={{ gridColumn: '1 / -1', marginTop: '10px' }}>
                <div style={{ 
                  backgroundColor: '#e7f3ff', 
                  border: '1px solid #b3d9ff', 
                  borderRadius: '4px', 
                  padding: '15px',
                  marginBottom: '15px'
                }}>
                  <h4 style={{ marginTop: '0', marginBottom: '10px', fontSize: '16px' }}>
                    SSH Key Setup Instructions
                  </h4>
                  <div style={{ fontSize: '13px', lineHeight: '1.6' }}>
                    <p style={{ marginBottom: '10px' }}>
                      <strong>This tunnel requires SSH public key authentication. Follow these steps:</strong>
                    </p>
                    <p style={{ marginBottom: '8px' }}>
                      <strong>1. Generate SSH Key Pair (if you don't have one):</strong><br />
                      <code style={{ backgroundColor: '#f5f5f5', padding: '2px 6px', borderRadius: '3px' }}>
                        ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
                      </code><br />
                      Press Enter to accept default location (~/.ssh/id_rsa) or specify a custom path.
                    </p>
                    <p style={{ marginBottom: '8px' }}>
                      <strong>2. Copy Public Key to VPS Server:</strong><br />
                      <code style={{ backgroundColor: '#f5f5f5', padding: '2px 6px', borderRadius: '3px' }}>
                        ssh-copy-id -i ~/.ssh/id_rsa.pub root@47.112.191.42
                      </code><br />
                      Or manually copy the public key from <code>~/.ssh/id_rsa.pub</code> and add it to <code>~/.ssh/authorized_keys</code> on the VPS.
                    </p>
                    <p style={{ marginBottom: '8px' }}>
                      <strong>3. Test the Connection:</strong><br />
                      <code style={{ backgroundColor: '#f5f5f5', padding: '2px 6px', borderRadius: '3px' }}>
                        ssh -i ~/.ssh/id_rsa root@47.112.191.42
                      </code><br />
                      If this works without asking for a password, your key is set up correctly.
                    </p>
                    <p style={{ marginBottom: '0' }}>
                      <strong>4. Set Proper Permissions (Important!):</strong><br />
                      <code style={{ backgroundColor: '#f5f5f5', padding: '2px 6px', borderRadius: '3px' }}>
                        chmod 600 ~/.ssh/id_rsa
                      </code> (private key)<br />
                      <code style={{ backgroundColor: '#f5f5f5', padding: '2px 6px', borderRadius: '3px' }}>
                        chmod 644 ~/.ssh/id_rsa.pub
                      </code> (public key)<br />
                      <code style={{ backgroundColor: '#f5f5f5', padding: '2px 6px', borderRadius: '3px' }}>
                        chmod 700 ~/.ssh
                      </code> (SSH directory)
                    </p>
                    <p style={{ marginTop: '10px', marginBottom: '0', fontStyle: 'italic', color: '#666' }}>
                      <strong>Note:</strong> The private key file must exist on this machine. Only the public key needs to be on the VPS server.
                    </p>
                  </div>
                </div>
              </div>
              <div>
                <label>Remote Bind Address:</label>
                <input
                  type="text"
                  value={formData.remote_bind_address}
                  onChange={(e) => setFormData({ ...formData, remote_bind_address: e.target.value })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>Server Alive Interval (seconds):</label>
                <input
                  type="number"
                  value={formData.server_alive_interval}
                  onChange={(e) => setFormData({ ...formData, server_alive_interval: parseInt(e.target.value) })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>Server Alive Count Max:</label>
                <input
                  type="number"
                  value={formData.server_alive_count_max}
                  onChange={(e) => setFormData({ ...formData, server_alive_count_max: parseInt(e.target.value) })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
              <div>
                <label>Monitor Port (0 for no monitoring):</label>
                <input
                  type="number"
                  value={formData.monitor_port}
                  onChange={(e) => setFormData({ ...formData, monitor_port: parseInt(e.target.value) })}
                  required
                  style={{ width: '100%', padding: '8px' }}
                />
              </div>
            </div>
            <button type="submit" className="btn btn-primary">
              {editingTunnel ? 'Update Tunnel' : 'Create Tunnel'}
            </button>
          </form>
        </div>
      )}

      {viewingLogs && (
        <div className="card" style={{ marginBottom: '30px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h2>Logs - {tunnels.find(t => t.tunnel_id === viewingLogs)?.name}</h2>
            <button onClick={() => setViewingLogs(null)} className="btn btn-secondary">
              Close
            </button>
          </div>
          <div style={{ 
            backgroundColor: '#1e1e1e', 
            color: '#d4d4d4', 
            padding: '15px', 
            borderRadius: '4px',
            fontFamily: 'monospace',
            fontSize: '12px',
            maxHeight: '400px',
            overflowY: 'auto'
          }}>
            {logs.length === 0 ? (
              <p>No logs available</p>
            ) : (
              logs.map((log, index) => (
                <div key={index} style={{ marginBottom: '5px' }}>
                  <span style={{ color: '#888' }}>
                    [{new Date(log.timestamp).toLocaleString()}]
                  </span>
                  <span style={{ 
                    color: log.type === 'error' ? '#f48771' : '#4ec9b0',
                    marginLeft: '10px'
                  }}>
                    {log.message}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      <div className="card">
        <h2>Autossh Tunnels ({tunnels.length})</h2>
        {tunnels.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Local Port</th>
                <th>Remote Port</th>
                <th>VPS Server</th>
                <th>Username</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tunnels.map((tunnel) => (
                <tr key={tunnel.tunnel_id}>
                  <td>{tunnel.name}</td>
                  <td>{tunnel.local_port}</td>
                  <td>{tunnel.remote_port || tunnel.local_port}</td>
                  <td>{tunnel.vps_ip}:{tunnel.vps_port}</td>
                  <td>{tunnel.username}</td>
                  <td>
                    <span
                      className={`status-badge ${
                        tunnel.status === 'running'
                          ? 'status-running'
                          : tunnel.status === 'error'
                          ? 'status-error'
                          : 'status-stopped'
                      }`}
                    >
                      {tunnel.status}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                      {tunnel.is_running ? (
                        <button
                          onClick={() => handleStop(tunnel.tunnel_id)}
                          className="btn btn-danger"
                          style={{ fontSize: '12px', padding: '5px 10px' }}
                        >
                          Stop
                        </button>
                      ) : (
                        <button
                          onClick={() => handleStart(tunnel.tunnel_id)}
                          className="btn btn-success"
                          style={{ fontSize: '12px', padding: '5px 10px' }}
                        >
                          Start
                        </button>
                      )}
                      <button
                        onClick={() => handleViewLogs(tunnel.tunnel_id)}
                        className="btn btn-info"
                        style={{ fontSize: '12px', padding: '5px 10px' }}
                      >
                        Logs
                      </button>
                      <button
                        onClick={() => handleEdit(tunnel)}
                        className="btn btn-warning"
                        style={{ fontSize: '12px', padding: '5px 10px' }}
                        disabled={tunnel.is_running}
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(tunnel.tunnel_id)}
                        className="btn btn-danger"
                        style={{ fontSize: '12px', padding: '5px 10px' }}
                        disabled={tunnel.is_running}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No tunnels configured. Click "Add New Tunnel" to create one.</p>
        )}
      </div>
    </div>
  );
}

export default function AutosshPage() {
  return (
    <ProtectedRoute>
      <AutosshPageContent />
    </ProtectedRoute>
  );
}

