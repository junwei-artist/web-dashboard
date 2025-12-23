'use client';

import { useEffect, useState } from 'react';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import Link from 'next/link';
import '../globals.css';

interface NetworkInterface {
  name: string;
  type: string;
  is_up: boolean;
  addresses: Array<{ address: string }>;
  speed: number;
  mtu: number;
}

interface TestResult {
  interface: string;
  success: boolean;
  latency_ms?: number;
  error?: string;
  timestamp?: string;
}

interface TracerouteHop {
  hop_number: number;
  hostname: string;
  ip: string;
  times_ms: number[];
  avg_time_ms: number;
  reached: boolean;
  explanation: string;
}

interface TracerouteResult {
  ip: string;
  interface?: string;
  hops: TracerouteHop[];
  total_hops: number;
  success: boolean;
  failed_at_hop?: number;
  failed_layer?: string;
  error?: string;
}

function NetworkInterfacesContent() {
  const { user, logout } = useAuth();
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [testIPs, setTestIPs] = useState<string[]>([]);
  const [testURLs, setTestURLs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [selectedTracerouteInterface, setSelectedTracerouteInterface] = useState('');
  const [selectedURLInterface, setSelectedURLInterface] = useState('');
  const [routeInterface, setRouteInterface] = useState('');
  const [routeTargetIP, setRouteTargetIP] = useState('');
  const [routeGateway, setRouteGateway] = useState('');
  const [newIP, setNewIP] = useState('');
  const [newURL, setNewURL] = useState('');
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [urlTestResults, setUrlTestResults] = useState<any[]>([]);
  const [tracerouteResults, setTracerouteResults] = useState<TracerouteResult | null>(null);
  const [systemRoutes, setSystemRoutes] = useState<any>(null);
  const [routeMonitor, setRouteMonitor] = useState<any>(null);
  const [routeStatus, setRouteStatus] = useState<any>(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(refreshRouteMonitor, 10000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      await Promise.all([
        refreshInterfaces(),
        loadTestIPList(),
        loadTestURLList(),
        refreshSystemRoutes(),
        refreshRouteMonitor(),
      ]);
    } catch (error) {
      console.error('Error loading data:', error);
    } finally {
      setLoading(false);
    }
  };

  const refreshInterfaces = async () => {
    try {
      const data = await api.getNetworkInterfaces();
      setInterfaces(data);
    } catch (error) {
      console.error('Error loading interfaces:', error);
    }
  };

  const loadTestIPList = async () => {
    try {
      const data = await api.getTestIPs();
      setTestIPs(data.ips || []);
    } catch (error) {
      console.error('Error loading test IPs:', error);
    }
  };

  const loadTestURLList = async () => {
    try {
      const data = await api.getTestURLs();
      setTestURLs(data.urls || []);
    } catch (error) {
      console.error('Error loading test URLs:', error);
    }
  };

  const addTestIP = async () => {
    if (!newIP.trim()) {
      alert('Please enter an IP address');
      return;
    }
    try {
      await api.addTestIP(newIP.trim());
      setNewIP('');
      await loadTestIPList();
    } catch (error: any) {
      alert('Error adding IP: ' + (error.response?.data?.error || error.message));
    }
  };

  const removeTestIP = async (ip: string) => {
    if (!confirm(`Remove ${ip} from test list?`)) return;
    try {
      await api.removeTestIP(ip);
      await loadTestIPList();
    } catch (error) {
      console.error('Error removing IP:', error);
    }
  };

  const addTestURL = async () => {
    if (!newURL.trim()) {
      alert('Please enter a URL');
      return;
    }
    if (!newURL.startsWith('http://') && !newURL.startsWith('https://')) {
      alert('URL must start with http:// or https://');
      return;
    }
    try {
      await api.addTestURL(newURL.trim());
      setNewURL('');
      await loadTestURLList();
    } catch (error: any) {
      alert('Error adding URL: ' + (error.response?.data?.error || error.message));
    }
  };

  const removeTestURL = async (url: string) => {
    if (!confirm(`Remove ${url} from test list?`)) return;
    try {
      await api.removeTestURL(url);
      await loadTestURLList();
    } catch (error) {
      console.error('Error removing URL:', error);
    }
  };

  const testIPAllInterfaces = async (ip: string) => {
    try {
      const data = await api.testIPAllInterfaces(ip);
      setTestResults(data.results || []);
    } catch (error) {
      console.error('Error testing IP:', error);
    }
  };

  const testAllIPs = async () => {
    try {
      const data = await api.testAllIPs(selectedInterface || undefined);
      setTestResults(data.results || []);
    } catch (error) {
      console.error('Error testing IPs:', error);
    }
  };

  const testURLAllInterfaces = async (url: string) => {
    try {
      const data = await api.testURLAllInterfaces(url);
      setUrlTestResults(data.results || []);
    } catch (error) {
      console.error('Error testing URL:', error);
    }
  };

  const testAllURLs = async () => {
    try {
      const data = await api.testAllURLs(selectedURLInterface || undefined);
      setUrlTestResults(data.results || []);
    } catch (error) {
      console.error('Error testing URLs:', error);
    }
  };

  const tracerouteIP = async (ip: string) => {
    try {
      const data = await api.traceroute(ip, selectedTracerouteInterface || undefined);
      setTracerouteResults(data);
    } catch (error) {
      console.error('Error performing traceroute:', error);
    }
  };

  const tracerouteSelectedIP = async () => {
    if (testIPs.length === 0) {
      alert('No IPs in test list. Please add an IP first.');
      return;
    }
    const ip = testIPs[0];
    await tracerouteIP(ip);
  };

  const refreshSystemRoutes = async () => {
    try {
      const data = await api.getAllSystemRoutes();
      setSystemRoutes(data);
    } catch (error) {
      console.error('Error loading system routes:', error);
    }
  };

  const setRoute = async () => {
    if (!routeInterface || !routeTargetIP) {
      alert('Please select an interface and enter a target IP');
      return;
    }
    try {
      await api.setRoute(routeInterface, routeTargetIP, routeGateway || undefined);
      setRouteTargetIP('');
      setRouteGateway('');
      await refreshRouteStatus();
    } catch (error: any) {
      alert('Error setting route: ' + (error.response?.data?.error || error.message));
    }
  };

  const refreshRouteStatus = async () => {
    try {
      const data = await api.getRouteStatus();
      setRouteStatus(data);
    } catch (error) {
      console.error('Error loading route status:', error);
    }
  };

  const refreshRouteMonitor = async () => {
    try {
      const data = await api.monitorRoutes();
      setRouteMonitor(data);
    } catch (error) {
      console.error('Error loading route monitor:', error);
    }
  };

  const testRoute = async (interfaceName: string) => {
    try {
      await api.testRoute(interfaceName);
      await refreshRouteMonitor();
    } catch (error) {
      console.error('Error testing route:', error);
    }
  };

  const saveConfigs = async () => {
    try {
      const data = await api.saveConfigs();
      if (data.success) {
        alert('Configurations saved successfully to YAML files');
      } else {
        alert('Error saving configurations: ' + (data.error || 'Unknown error'));
      }
    } catch (error: any) {
      alert('Error saving configurations: ' + error.message);
    }
  };

  const reloadConfigs = async () => {
    if (!confirm('Reload configurations from YAML files? This will overwrite current settings.')) {
      return;
    }
    try {
      const data = await api.reloadConfigs();
      if (data.success) {
        alert('Configurations reloaded successfully from YAML files');
        await loadTestIPList();
        await refreshRouteStatus();
        await refreshRouteMonitor();
      } else {
        alert('Error reloading configurations: ' + (data.error || 'Unknown error'));
      }
    } catch (error: any) {
      alert('Error reloading configurations: ' + error.message);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const availableInterfaces = interfaces.filter(i => i.is_up && i.type !== 'Loopback');

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading network interfaces...</div>
      </div>
    );
  }

  return (
    <div className="container">
      <header style={{ marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '2rem', marginBottom: '10px' }}>Network Interfaces & Routing</h1>
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
          <Link href="/litellm" className="btn btn-secondary">
            LiteLLM
          </Link>
        </div>
      </nav>

      {/* Network Interfaces Section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>Network Interfaces</h2>
          <button onClick={refreshInterfaces} className="btn btn-primary">
            Refresh
          </button>
        </div>
        <div className="table-responsive">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th>Addresses</th>
                <th>Speed</th>
                <th>MTU</th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map((iface, idx) => (
                <tr key={idx}>
                  <td><code>{iface.name}</code></td>
                  <td>{iface.type}</td>
                  <td>
                    <span className={`status-badge ${iface.is_up ? 'status-running' : 'status-stopped'}`}>
                      {iface.is_up ? 'UP' : 'DOWN'}
                    </span>
                  </td>
                  <td>
                    {iface.addresses.map((addr, i) => (
                      <span key={i} className="badge bg-secondary" style={{ marginRight: '5px' }}>
                        {addr.address}
                      </span>
                    ))}
                  </td>
                  <td>{iface.speed > 0 ? `${iface.speed} Mbps` : 'N/A'}</td>
                  <td>{iface.mtu || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Test IP List Section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>Test IP List</h2>
          <div>
            <button onClick={reloadConfigs} className="btn btn-secondary" style={{ marginRight: '10px' }}>
              Reload
            </button>
            <button onClick={saveConfigs} className="btn btn-secondary">
              Save
            </button>
          </div>
        </div>
        <div style={{ marginBottom: '15px' }}>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input
              type="text"
              className="form-control"
              placeholder="Enter IP address (e.g., 8.8.8.8)"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && addTestIP()}
              style={{ flex: 1, padding: '10px', border: '1px solid #ddd', borderRadius: '4px' }}
            />
            <button onClick={addTestIP} className="btn btn-primary">
              Add IP
            </button>
          </div>
        </div>
        <div style={{ marginBottom: '15px' }}>
          <label style={{ display: 'block', marginBottom: '5px' }}>Select Interface for Traceroute:</label>
          <select
            value={selectedTracerouteInterface}
            onChange={(e) => setSelectedTracerouteInterface(e.target.value)}
            style={{ width: '100%', padding: '10px', border: '1px solid #ddd', borderRadius: '4px' }}
          >
            <option value="">Default (All Interfaces)</option>
            {availableInterfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.name} ({iface.type})
              </option>
            ))}
          </select>
        </div>
        <button onClick={tracerouteSelectedIP} className="btn btn-info" style={{ marginBottom: '15px' }}>
          Traceroute Selected IP
        </button>
        <div>
          {testIPs.length === 0 ? (
            <p>No IPs in test list. Add IPs above.</p>
          ) : (
            <ul className="list-group">
              {testIPs.map((ip, idx) => (
                <li key={idx} className="list-group-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <code style={{ marginRight: '10px' }}>{ip}</code>
                    <button onClick={() => testIPAllInterfaces(ip)} className="btn btn-sm btn-primary" style={{ marginRight: '5px' }}>
                      Test All Interfaces
                    </button>
                    <button onClick={() => tracerouteIP(ip)} className="btn btn-sm btn-info">
                      Traceroute
                    </button>
                  </div>
                  <button onClick={() => removeTestIP(ip)} className="btn btn-sm btn-danger">
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        {tracerouteResults && (
          <div style={{ marginTop: '20px' }}>
            <h3>Traceroute Results for {tracerouteResults.ip}</h3>
            {tracerouteResults.error && !tracerouteResults.hops && (
              <div className="error">Error: {tracerouteResults.error}</div>
            )}
            {tracerouteResults.hops && tracerouteResults.hops.length > 0 && (
              <div className="table-responsive">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Hop</th>
                      <th>Hostname</th>
                      <th>IP Address</th>
                      <th>Response Times</th>
                      <th>Avg Time</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tracerouteResults.hops.map((hop, idx) => (
                      <tr key={idx}>
                        <td>{hop.hop_number}</td>
                        <td><code>{hop.hostname}</code></td>
                        <td><code>{hop.ip}</code></td>
                        <td>{hop.times_ms.map(t => `${t.toFixed(2)}ms`).join(', ')}</td>
                        <td>{hop.avg_time_ms ? `${hop.avg_time_ms.toFixed(2)} ms` : 'N/A'}</td>
                        <td>
                          <span className={`status-badge ${hop.reached ? 'status-running' : 'status-stopped'}`}>
                            {hop.reached ? 'Reached' : 'Timeout'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Connection Testing Section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <h2 style={{ marginBottom: '15px' }}>Connection Testing</h2>
        <div style={{ marginBottom: '15px' }}>
          <label style={{ display: 'block', marginBottom: '5px' }}>Select Interface:</label>
          <select
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            style={{ width: '100%', padding: '10px', border: '1px solid #ddd', borderRadius: '4px', marginBottom: '10px' }}
          >
            <option value="">All Interfaces (Test through each)</option>
            {availableInterfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.name} ({iface.type})
              </option>
            ))}
          </select>
        </div>
        <button onClick={testAllIPs} className="btn btn-success">
          Test All IPs
        </button>
        {testResults.length > 0 && (
          <div style={{ marginTop: '20px' }}>
            <h3>Test Results</h3>
            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Interface</th>
                    <th>Status</th>
                    <th>Latency</th>
                    <th>Error</th>
                  </tr>
                </thead>
                <tbody>
                  {testResults.map((result, idx) => (
                    <tr key={idx}>
                      <td><code>{result.ip || 'N/A'}</code></td>
                      <td><code>{result.interface || 'default'}</code></td>
                      <td>
                        <span className={`status-badge ${result.success ? 'status-running' : 'status-stopped'}`}>
                          {result.success ? 'Success' : 'Failed'}
                        </span>
                      </td>
                      <td>{result.latency_ms ? `${result.latency_ms.toFixed(2)} ms` : 'N/A'}</td>
                      <td>{result.error || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* URL Test List Section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>URL Test List (Curl)</h2>
          <div>
            <button onClick={reloadConfigs} className="btn btn-secondary" style={{ marginRight: '10px' }}>
              Reload
            </button>
            <button onClick={saveConfigs} className="btn btn-secondary">
              Save
            </button>
          </div>
        </div>
        <div style={{ marginBottom: '15px' }}>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input
              type="text"
              className="form-control"
              placeholder="Enter URL (e.g., http://10.3.20.26:4899/)"
              value={newURL}
              onChange={(e) => setNewURL(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && addTestURL()}
              style={{ flex: 1, padding: '10px', border: '1px solid #ddd', borderRadius: '4px' }}
            />
            <button onClick={addTestURL} className="btn btn-warning">
              Add URL
            </button>
          </div>
        </div>
        <div>
          {testURLs.length === 0 ? (
            <p>No URLs in test list. Add URLs above.</p>
          ) : (
            <ul className="list-group">
              {testURLs.map((url, idx) => (
                <li key={idx} className="list-group-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <code style={{ marginRight: '10px' }}>{url}</code>
                    <button onClick={() => testURLAllInterfaces(url)} className="btn btn-sm btn-warning">
                      Test All Interfaces
                    </button>
                  </div>
                  <button onClick={() => removeTestURL(url)} className="btn btn-sm btn-danger">
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* URL Connection Testing Section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <h2 style={{ marginBottom: '15px' }}>URL Connection Testing (Curl)</h2>
        <div style={{ marginBottom: '15px' }}>
          <label style={{ display: 'block', marginBottom: '5px' }}>Select Interface:</label>
          <select
            value={selectedURLInterface}
            onChange={(e) => setSelectedURLInterface(e.target.value)}
            style={{ width: '100%', padding: '10px', border: '1px solid #ddd', borderRadius: '4px', marginBottom: '10px' }}
          >
            <option value="">All Interfaces (Test through each)</option>
            {availableInterfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.name} ({iface.type})
              </option>
            ))}
          </select>
        </div>
        <button onClick={testAllURLs} className="btn btn-warning">
          Test All URLs
        </button>
        {urlTestResults.length > 0 && (
          <div style={{ marginTop: '20px' }}>
            <h3>URL Test Results</h3>
            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Interface</th>
                    <th>Status</th>
                    <th>HTTP Code</th>
                    <th>Response Time</th>
                    <th>Error</th>
                  </tr>
                </thead>
                <tbody>
                  {urlTestResults.map((result, idx) => (
                    <tr key={idx}>
                      <td><code>{result.url || 'N/A'}</code></td>
                      <td><code>{result.interface || 'default'}</code></td>
                      <td>
                        <span className={`status-badge ${result.success ? 'status-running' : 'status-stopped'}`}>
                          {result.success ? 'Success' : 'Failed'}
                        </span>
                      </td>
                      <td>{result.status_code || 'N/A'}</td>
                      <td>{result.response_time_ms ? `${result.response_time_ms.toFixed(2)} ms` : 'N/A'}</td>
                      <td>{result.error || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* System Routes Section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>All System Routes</h2>
          <button onClick={refreshSystemRoutes} className="btn btn-primary">
            Refresh
          </button>
        </div>
        {systemRoutes && (
          <div>
            {systemRoutes.error ? (
              <div className="error">Error: {systemRoutes.error}</div>
            ) : (
              <div className="table-responsive">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Destination</th>
                      <th>Gateway</th>
                      <th>Interface</th>
                      <th>Flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(systemRoutes.routes || []).map((route: any, idx: number) => (
                      <tr key={idx}>
                        <td><code>{route.destination || 'Unknown'}</code></td>
                        <td><code>{route.gateway || 'default'}</code></td>
                        <td><code>{route.interface || 'N/A'}</code></td>
                        <td>{route.flags || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Route Management Section */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>Route Management</h2>
          <div>
            <button onClick={reloadConfigs} className="btn btn-secondary" style={{ marginRight: '10px' }}>
              Reload
            </button>
            <button onClick={saveConfigs} className="btn btn-secondary">
              Save
            </button>
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', marginBottom: '15px' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '5px' }}>Interface:</label>
            <select
              value={routeInterface}
              onChange={(e) => setRouteInterface(e.target.value)}
              style={{ width: '100%', padding: '10px', border: '1px solid #ddd', borderRadius: '4px' }}
            >
              <option value="">Select Interface</option>
              {availableInterfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} ({iface.type})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '5px' }}>Target IP/Network:</label>
            <input
              type="text"
              value={routeTargetIP}
              onChange={(e) => setRouteTargetIP(e.target.value)}
              placeholder="e.g., 8.8.8.8 or 0.0.0.0/0"
              style={{ width: '100%', padding: '10px', border: '1px solid #ddd', borderRadius: '4px' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '5px' }}>Gateway (Optional):</label>
            <input
              type="text"
              value={routeGateway}
              onChange={(e) => setRouteGateway(e.target.value)}
              placeholder="e.g., 192.168.1.1"
              style={{ width: '100%', padding: '10px', border: '1px solid #ddd', borderRadius: '4px' }}
            />
          </div>
        </div>
        <button onClick={setRoute} className="btn btn-warning">
          Set Route
        </button>
      </div>

      {/* Route Monitor Section */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
          <h2>Route Monitor</h2>
          <button onClick={refreshRouteMonitor} className="btn btn-primary">
            Refresh
          </button>
        </div>
        {routeMonitor && (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '20px' }}>
              <div className="card" style={{ textAlign: 'center', padding: '15px' }}>
                <h3>{routeMonitor.total_configured_routes || 0}</h3>
                <small>Total Routes</small>
              </div>
              <div className="card" style={{ textAlign: 'center', padding: '15px' }}>
                <h3>{routeMonitor.active_routes || 0}</h3>
                <small>Active Routes</small>
              </div>
              <div className="card" style={{ textAlign: 'center', padding: '15px' }}>
                <h3>{Object.keys(routeMonitor.route_tests || {}).length}</h3>
                <small>Routes Tested</small>
              </div>
              <div className="card" style={{ textAlign: 'center', padding: '15px' }}>
                <button onClick={refreshRouteMonitor} className="btn btn-primary">
                  Test All Routes
                </button>
              </div>
            </div>
            {routeMonitor.configured_routes && Object.keys(routeMonitor.configured_routes).length > 0 && (
              <div className="table-responsive">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Interface</th>
                      <th>Target IP</th>
                      <th>Gateway</th>
                      <th>Route Status</th>
                      <th>Connection Test</th>
                      <th>Latency</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(routeMonitor.configured_routes).map(([iface, config]: [string, any]) => {
                      const testResult = routeMonitor.route_tests?.[iface];
                      return (
                        <tr key={iface}>
                          <td><code>{iface}</code></td>
                          <td><code>{config.target_ip || 'N/A'}</code></td>
                          <td><code>{config.gateway || 'Auto'}</code></td>
                          <td>
                            <span className={`status-badge ${config.enabled !== false ? 'status-running' : 'status-stopped'}`}>
                              {config.enabled !== false ? 'Enabled' : 'Disabled'}
                            </span>
                          </td>
                          <td>
                            {testResult ? (
                              <span className={`status-badge ${testResult.success ? 'status-running' : 'status-stopped'}`}>
                                {testResult.success ? 'Connected' : 'Failed'}
                              </span>
                            ) : (
                              <span className="status-badge status-unknown">Not Tested</span>
                            )}
                          </td>
                          <td>{testResult?.latency_ms ? `${testResult.latency_ms.toFixed(2)} ms` : 'N/A'}</td>
                          <td>
                            <button onClick={() => testRoute(iface)} className="btn btn-sm btn-primary">
                              Test
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function NetworkInterfacesPage() {
  return (
    <ProtectedRoute>
      <NetworkInterfacesContent />
    </ProtectedRoute>
  );
}

