'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { useAuth } from '@/contexts/AuthContext';
import Link from 'next/link';
import '../globals.css';

interface LiteLLMTask {
  task_id: string;
  name: string;
  description: string;
  api_base: string;
  model: string;
  master_key: string;
  port: number;
  is_running: boolean;
  status: string;
  created_at: string;
  last_activity: string | null;
  api_keys: string[];
  total_requests: number;
  total_tokens: number;
  failed_requests: number;
}

interface ApiKey {
  api_key: string;
  full_key: string;
  name: string;
  description: string;
  created_at: string;
  tokens_used_today: number;
  tokens_used_total: number;
  requests_today: number;
  requests_total: number;
  last_used: string | null;
  is_active: boolean;
}

interface TokenRecord {
  record_id: string;
  api_key: string;
  task_id: string;
  tokens: number;
  model: string;
  success: boolean;
  error: string;
  timestamp: string;
  date: string;
}

function LiteLLMPageContent() {
  const { user, logout } = useAuth();
  const [tasks, setTasks] = useState<LiteLLMTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [showForm, setShowForm] = useState(false);
  const [editingTask, setEditingTask] = useState<LiteLLMTask | null>(null);
  const [selectedTask, setSelectedTask] = useState<string | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [showApiKeyForm, setShowApiKeyForm] = useState(false);
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [tokenRecords, setTokenRecords] = useState<TokenRecord[]>([]);
  const [showTokenRecords, setShowTokenRecords] = useState(false);
  const [statistics, setStatistics] = useState<any>(null);
  const [apiExamples, setApiExamples] = useState<any>(null);
  const [showApiExamples, setShowApiExamples] = useState(false);
  const [selectedExample, setSelectedExample] = useState<string>('chat_completions');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('curl');
  
  // Form state
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    api_base: '',
    model: '',
    master_key: '',
    port: 4000,
  });

  const [apiKeyFormData, setApiKeyFormData] = useState({
    name: '',
    description: '',
  });

  const fetchTasks = async () => {
    try {
      setError(null);
      const response = await api.getLiteLLMTasks();
      if (response.success) {
        setTasks(response.tasks);
        setLastUpdate(new Date());
      } else {
        setError(response.error || 'Failed to fetch tasks');
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch tasks');
      console.error('Error fetching tasks:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchApiKeys = async (taskId: string) => {
    try {
      const response = await api.getLiteLLMTaskApiKeys(taskId);
      if (response.success) {
        setApiKeys(response.api_keys);
      }
    } catch (err: any) {
      console.error('Error fetching API keys:', err);
    }
  };

  const fetchTokenRecords = async (taskId?: string, apiKey?: string) => {
    try {
      const response = await api.getLiteLLMTokenRecords(taskId, apiKey, undefined, undefined, 100);
      if (response.success) {
        setTokenRecords(response.records);
      }
    } catch (err: any) {
      console.error('Error fetching token records:', err);
    }
  };

  const fetchStatistics = async (taskId?: string) => {
    try {
      const response = await api.getLiteLLMStatistics(taskId);
      if (response.success) {
        setStatistics(response.statistics);
      }
    } catch (err: any) {
      console.error('Error fetching statistics:', err);
    }
  };

  useEffect(() => {
    fetchTasks();
    const interval = setInterval(fetchTasks, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (editingTask) {
        await api.updateLiteLLMTask(editingTask.task_id, formData);
      } else {
        await api.createLiteLLMTask(formData);
      }
      setShowForm(false);
      setEditingTask(null);
      setFormData({
        name: '',
        description: '',
        api_base: '',
        model: '',
        master_key: '',
        port: 4000,
      });
      fetchTasks();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to save task');
    }
  };

  const handleEdit = (task: LiteLLMTask) => {
    setEditingTask(task);
    setFormData({
      name: task.name,
      description: task.description,
      api_base: task.api_base,
      model: task.model,
      master_key: '',
      port: task.port,
    });
    setShowForm(true);
  };

  const handleDelete = async (taskId: string) => {
    if (!confirm('Are you sure you want to delete this task?')) return;
    try {
      await api.deleteLiteLLMTask(taskId);
      fetchTasks();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to delete task');
    }
  };

  const handleStart = async (taskId: string) => {
    try {
      await api.startLiteLLMTask(taskId);
      fetchTasks();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to start task');
    }
  };

  const handleStop = async (taskId: string) => {
    try {
      await api.stopLiteLLMTask(taskId);
      fetchTasks();
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to stop task');
    }
  };

  const handleViewApiKeys = async (taskId: string) => {
    setSelectedTask(taskId);
    setShowApiKeyForm(false);
    setNewApiKey(null);
    await fetchApiKeys(taskId);
  };

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTask) return;
    try {
      const response = await api.createLiteLLMApiKey(selectedTask, apiKeyFormData);
      if (response.success) {
        setNewApiKey(response.api_key);
        setApiKeyFormData({ name: '', description: '' });
        await fetchApiKeys(selectedTask);
        alert(`API Key created! Save this key: ${response.api_key}`);
      }
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to create API key');
    }
  };

  const handleDeleteApiKey = async (apiKey: string) => {
    if (!confirm('Are you sure you want to delete this API key?')) return;
    try {
      await api.deleteLiteLLMApiKey(apiKey);
      if (selectedTask) {
        await fetchApiKeys(selectedTask);
      }
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to delete API key');
    }
  };

  const handleViewTokenRecords = async (taskId?: string, apiKey?: string) => {
    setShowTokenRecords(true);
    await fetchTokenRecords(taskId, apiKey);
    if (taskId) {
      await fetchStatistics(taskId);
    }
  };

  const handleViewApiExamples = async (taskId: string) => {
    try {
      const response = await api.getLiteLLMTaskApiExamples(taskId);
      if (response.success) {
        setApiExamples(response.examples);
        setShowApiExamples(true);
        setSelectedExample('chat_completions');
        setSelectedLanguage('curl');
      }
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to fetch API examples');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading LiteLLM tasks...</div>
      </div>
    );
  }

  return (
    <div className="container">
      <header style={{ marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '2rem', marginBottom: '10px' }}>LiteLLM Management</h1>
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
          <Link href="/litellm" className="btn btn-secondary">
            LiteLLM
          </Link>
        </div>
      </nav>

      {error && <div className="error">{error}</div>}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>LiteLLM Tasks ({tasks.length})</h2>
        <button onClick={() => { setShowForm(true); setEditingTask(null); setFormData({ name: '', description: '', api_base: '', model: '', master_key: '', port: 4000 }); }} className="btn btn-primary">
          Create Task
        </button>
      </div>

      {showForm && (
        <div className="card" style={{ marginBottom: '30px' }}>
          <h3>{editingTask ? 'Edit Task' : 'Create New Task'}</h3>
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '15px' }}>
              <label>Name:</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                required
                style={{ width: '100%', padding: '8px', marginTop: '5px' }}
              />
            </div>
            <div style={{ marginBottom: '15px' }}>
              <label>Description:</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                style={{ width: '100%', padding: '8px', marginTop: '5px', minHeight: '60px' }}
              />
            </div>
            <div style={{ marginBottom: '15px' }}>
              <label>API Base URL:</label>
              <input
                type="text"
                value={formData.api_base}
                onChange={(e) => setFormData({ ...formData, api_base: e.target.value })}
                required
                placeholder="https://api.openai.com/v1"
                style={{ width: '100%', padding: '8px', marginTop: '5px' }}
              />
            </div>
            <div style={{ marginBottom: '15px' }}>
              <label>Model:</label>
              <input
                type="text"
                value={formData.model}
                onChange={(e) => setFormData({ ...formData, model: e.target.value })}
                required
                placeholder="gpt-4"
                style={{ width: '100%', padding: '8px', marginTop: '5px' }}
              />
            </div>
            <div style={{ marginBottom: '15px' }}>
              <label>Master Key:</label>
              <input
                type="password"
                value={formData.master_key}
                onChange={(e) => setFormData({ ...formData, master_key: e.target.value })}
                placeholder="Leave empty if not needed"
                style={{ width: '100%', padding: '8px', marginTop: '5px' }}
              />
            </div>
            <div style={{ marginBottom: '15px' }}>
              <label>Port:</label>
              <input
                type="number"
                value={formData.port}
                onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) || 4000 })}
                required
                style={{ width: '100%', padding: '8px', marginTop: '5px' }}
              />
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button type="submit" className="btn btn-primary">Save</button>
              <button type="button" onClick={() => { setShowForm(false); setEditingTask(null); }} className="btn btn-secondary">Cancel</button>
            </div>
          </form>
        </div>
      )}

      {tasks.length === 0 ? (
        <div className="card">
          <p>No tasks created yet. Create your first task to get started.</p>
        </div>
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>API Base</th>
                <th>Model</th>
                <th>Port</th>
                <th>Status</th>
                <th>API Keys</th>
                <th>Requests</th>
                <th>Tokens</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task) => (
                <tr key={task.task_id}>
                  <td>
                    <strong>{task.name}</strong>
                    {task.description && <div style={{ fontSize: '12px', color: '#666' }}>{task.description}</div>}
                  </td>
                  <td><code style={{ fontSize: '12px' }}>{task.api_base}</code></td>
                  <td>{task.model}</td>
                  <td>{task.port}</td>
                  <td>
                    <span className={`status-badge ${task.is_running ? 'status-running' : 'status-stopped'}`}>
                      {task.status}
                    </span>
                  </td>
                  <td>{task.api_keys.length}</td>
                  <td>{task.total_requests}</td>
                  <td>{task.total_tokens.toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                      {task.is_running ? (
                        <button onClick={() => handleStop(task.task_id)} className="btn btn-danger" style={{ fontSize: '12px', padding: '5px 10px' }}>
                          Stop
                        </button>
                      ) : (
                        <button onClick={() => handleStart(task.task_id)} className="btn btn-success" style={{ fontSize: '12px', padding: '5px 10px' }}>
                          Start
                        </button>
                      )}
                      <button onClick={() => handleViewApiKeys(task.task_id)} className="btn btn-secondary" style={{ fontSize: '12px', padding: '5px 10px' }}>
                        Keys
                      </button>
                      <button onClick={() => handleViewApiExamples(task.task_id)} className="btn btn-secondary" style={{ fontSize: '12px', padding: '5px 10px' }}>
                        API Docs
                      </button>
                      <button onClick={() => handleViewTokenRecords(task.task_id)} className="btn btn-secondary" style={{ fontSize: '12px', padding: '5px 10px' }}>
                        Records
                      </button>
                      <button onClick={() => handleEdit(task)} className="btn btn-secondary" style={{ fontSize: '12px', padding: '5px 10px' }}>
                        Edit
                      </button>
                      <button onClick={() => handleDelete(task.task_id)} className="btn btn-danger" style={{ fontSize: '12px', padding: '5px 10px' }}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedTask && (
        <div className="card" style={{ marginTop: '30px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h3>API Keys for Task: {tasks.find(t => t.task_id === selectedTask)?.name}</h3>
            <button onClick={() => { setSelectedTask(null); setApiKeys([]); }} className="btn btn-secondary" style={{ fontSize: '14px', padding: '5px 15px' }}>
              Close
            </button>
          </div>

          {newApiKey && (
            <div className="alert alert-success" style={{ marginBottom: '15px' }}>
              <strong>New API Key Created!</strong>
              <div style={{ marginTop: '10px' }}>
                <code style={{ background: '#f5f5f5', padding: '10px', display: 'block', wordBreak: 'break-all' }}>
                  {newApiKey}
                </code>
                <small style={{ color: '#666' }}>Save this key now - it won't be shown again!</small>
              </div>
            </div>
          )}

          <div style={{ marginBottom: '15px' }}>
            <button onClick={() => setShowApiKeyForm(!showApiKeyForm)} className="btn btn-primary" style={{ fontSize: '14px', padding: '5px 15px' }}>
              {showApiKeyForm ? 'Cancel' : 'Create API Key'}
            </button>
          </div>

          {showApiKeyForm && (
            <form onSubmit={handleCreateApiKey} style={{ marginBottom: '20px', padding: '15px', background: '#f5f5f5', borderRadius: '5px' }}>
              <div style={{ marginBottom: '10px' }}>
                <label>Name:</label>
                <input
                  type="text"
                  value={apiKeyFormData.name}
                  onChange={(e) => setApiKeyFormData({ ...apiKeyFormData, name: e.target.value })}
                  required
                  style={{ width: '100%', padding: '8px', marginTop: '5px' }}
                />
              </div>
              <div style={{ marginBottom: '10px' }}>
                <label>Description:</label>
                <textarea
                  value={apiKeyFormData.description}
                  onChange={(e) => setApiKeyFormData({ ...apiKeyFormData, description: e.target.value })}
                  style={{ width: '100%', padding: '8px', marginTop: '5px', minHeight: '60px' }}
                />
              </div>
              <button type="submit" className="btn btn-primary">Create</button>
            </form>
          )}

          {apiKeys.length === 0 ? (
            <p>No API keys for this task yet.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>API Key</th>
                  <th>Created</th>
                  <th>Requests</th>
                  <th>Tokens</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map((key) => (
                  <tr key={key.full_key}>
                    <td>
                      <strong>{key.name}</strong>
                      {key.description && <div style={{ fontSize: '12px', color: '#666' }}>{key.description}</div>}
                    </td>
                    <td><code style={{ fontSize: '11px' }}>{key.api_key}</code></td>
                    <td>{new Date(key.created_at).toLocaleDateString()}</td>
                    <td>{key.requests_total}</td>
                    <td>{key.tokens_used_total.toLocaleString()}</td>
                    <td>
                      <span className={`status-badge ${key.is_active ? 'status-running' : 'status-stopped'}`}>
                        {key.is_active ? 'Active' : 'Revoked'}
                      </span>
                    </td>
                    <td>
                      <button onClick={() => handleDeleteApiKey(key.full_key)} className="btn btn-danger" style={{ fontSize: '12px', padding: '5px 10px' }}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {showTokenRecords && (
        <div className="card" style={{ marginTop: '30px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h3>Token Records & Statistics</h3>
            <button onClick={() => { setShowTokenRecords(false); setTokenRecords([]); setStatistics(null); }} className="btn btn-secondary" style={{ fontSize: '14px', padding: '5px 15px' }}>
              Close
            </button>
          </div>

          {statistics && (
            <div style={{ marginBottom: '20px', padding: '15px', background: '#f5f5f5', borderRadius: '5px' }}>
              <h4>Statistics</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
                <div>
                  <strong>Total Requests:</strong> {statistics.total_requests || 0}
                </div>
                <div>
                  <strong>Total Tokens:</strong> {(statistics.total_tokens || 0).toLocaleString()}
                </div>
                <div>
                  <strong>Failed Requests:</strong> {statistics.failed_requests || 0}
                </div>
                <div>
                  <strong>API Keys:</strong> {statistics.api_keys_count || 0}
                </div>
              </div>
            </div>
          )}

          {tokenRecords.length === 0 ? (
            <p>No token records found.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>API Key</th>
                  <th>Model</th>
                  <th>Tokens</th>
                  <th>Status</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {tokenRecords.map((record) => (
                  <tr key={record.record_id}>
                    <td>{new Date(record.timestamp).toLocaleString()}</td>
                    <td><code style={{ fontSize: '11px' }}>{record.api_key}</code></td>
                    <td>{record.model || 'N/A'}</td>
                    <td>{record.tokens.toLocaleString()}</td>
                    <td>
                      <span className={`status-badge ${record.success ? 'status-running' : 'status-stopped'}`}>
                        {record.success ? 'Success' : 'Failed'}
                      </span>
                    </td>
                    <td>{record.error || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {showApiExamples && apiExamples && (
        <div className="card" style={{ marginTop: '30px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h3>API Instructions & Examples - {apiExamples.task_name}</h3>
            <button onClick={() => { setShowApiExamples(false); setApiExamples(null); }} className="btn btn-secondary" style={{ fontSize: '14px', padding: '5px 15px' }}>
              Close
            </button>
          </div>

          {/* Instructions */}
          <div style={{ marginBottom: '30px', padding: '15px', background: '#f5f5f5', borderRadius: '5px' }}>
            <h4>Overview</h4>
            <p style={{ marginBottom: '15px' }}>{apiExamples.instructions.overview}</p>
            
            <h4 style={{ marginTop: '20px' }}>Authentication</h4>
            <pre style={{ background: '#fff', padding: '10px', borderRadius: '3px', overflow: 'auto', marginBottom: '15px' }}>
              {apiExamples.instructions.authentication}
            </pre>
            
            <h4 style={{ marginTop: '20px' }}>Base URL</h4>
            <p><code style={{ background: '#fff', padding: '5px 10px', borderRadius: '3px' }}>{apiExamples.instructions.base_url}</code></p>
          </div>

          {/* Example Endpoints */}
          <div style={{ marginBottom: '20px' }}>
            <h4>API Endpoints</h4>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '15px', flexWrap: 'wrap' }}>
              {Object.keys(apiExamples.examples).map((endpoint) => (
                <button
                  key={endpoint}
                  onClick={() => { setSelectedExample(endpoint); setSelectedLanguage('curl'); }}
                  className={selectedExample === endpoint ? 'btn btn-primary' : 'btn btn-secondary'}
                  style={{ fontSize: '14px', padding: '5px 15px' }}
                >
                  {endpoint.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </button>
              ))}
            </div>
          </div>

          {/* Selected Example */}
          {apiExamples.examples[selectedExample] && (
            <div>
              <div style={{ marginBottom: '15px' }}>
                <h4>{apiExamples.examples[selectedExample].description}</h4>
                <p><strong>Endpoint:</strong> <code>{apiExamples.examples[selectedExample].endpoint}</code></p>
              </div>

              {/* Language Tabs */}
              <div style={{ marginBottom: '15px' }}>
                <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
                  {['curl', 'python', 'javascript', 'json'].map((lang) => {
                    if (lang === 'json' && !apiExamples.examples[selectedExample].json) return null;
                    return (
                      <button
                        key={lang}
                        onClick={() => setSelectedLanguage(lang)}
                        className={selectedLanguage === lang ? 'btn btn-primary' : 'btn btn-secondary'}
                        style={{ fontSize: '14px', padding: '5px 15px' }}
                      >
                        {lang.charAt(0).toUpperCase() + lang.slice(1)}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Code Display */}
              <div style={{ position: 'relative', marginBottom: '20px' }}>
                <button
                  onClick={() => {
                    const code = selectedLanguage === 'json' 
                      ? JSON.stringify(apiExamples.examples[selectedExample].json, null, 2)
                      : apiExamples.examples[selectedExample][selectedLanguage];
                    copyToClipboard(code);
                  }}
                  className="btn btn-secondary"
                  style={{ position: 'absolute', top: '10px', right: '10px', fontSize: '12px', padding: '5px 10px', zIndex: 10 }}
                >
                  Copy
                </button>
                <pre style={{ 
                  background: '#2d2d2d', 
                  color: '#f8f8f2', 
                  padding: '20px', 
                  borderRadius: '5px', 
                  overflow: 'auto',
                  maxHeight: '500px',
                  fontSize: '13px',
                  lineHeight: '1.5'
                }}>
                  {selectedLanguage === 'json' 
                    ? JSON.stringify(apiExamples.examples[selectedExample].json, null, 2)
                    : apiExamples.examples[selectedExample][selectedLanguage]}
                </pre>
              </div>
            </div>
          )}

          {/* Notes */}
          {apiExamples.notes && apiExamples.notes.length > 0 && (
            <div style={{ marginTop: '30px', padding: '15px', background: '#e7f3ff', borderRadius: '5px' }}>
              <h4>Important Notes</h4>
              <ul style={{ marginTop: '10px', paddingLeft: '20px' }}>
                {apiExamples.notes.map((note: string, index: number) => (
                  <li key={index} style={{ marginBottom: '8px' }}>{note}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function LiteLLMPage() {
  return (
    <ProtectedRoute>
      <LiteLLMPageContent />
    </ProtectedRoute>
  );
}

