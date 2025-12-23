#!/usr/bin/env python3
"""
LiteLLM Manager for handling LiteLLM proxy operations.
Manages tasks/services with API base, model, master key, running port, API keys, and token statistics.
"""

import json
import os
import time
import threading
import logging
import hashlib
import secrets
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("Requests not available. Install with: pip install requests")

try:
    from fastapi import FastAPI, Request, HTTPException, Header
    from fastapi.responses import JSONResponse, StreamingResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logging.warning("FastAPI not available. Install with: pip install fastapi uvicorn")

logger = logging.getLogger(__name__)


class LiteLLMTask:
    """Represents a single LiteLLM service/task configuration."""
    
    def __init__(self, task_id: str, config: Dict):
        self.task_id = task_id
        self.name = config.get('name', f'Task {task_id}')
        self.description = config.get('description', '')
        
        # LiteLLM configuration
        self.api_base = config.get('api_base', '')
        self.model = config.get('model', '')
        self.master_key = config.get('master_key', '')
        self.port = config.get('port', 4000)
        
        # Task status
        self.is_running = False
        self.status = 'stopped'  # stopped, running, error
        self.process = None
        self.thread = None
        self.stop_event = threading.Event()
        self.created_at = config.get('created_at', datetime.now().isoformat())
        self.last_activity = None
        
        # API keys for this task
        self.api_keys: List[str] = config.get('api_keys', [])
        
        # Statistics
        self.total_requests = 0
        self.total_tokens = 0
        self.failed_requests = 0
        
    def to_dict(self):
        """Convert task to dictionary."""
        return {
            'task_id': self.task_id,
            'name': self.name,
            'description': self.description,
            'api_base': self.api_base,
            'model': self.model,
            'master_key': '***' if self.master_key else '',
            'port': self.port,
            'is_running': self.is_running,
            'status': self.status,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'api_keys': self.api_keys,
            'total_requests': self.total_requests,
            'total_tokens': self.total_tokens,
            'failed_requests': self.failed_requests
        }
    
    def get_config_dict(self) -> Dict:
        """Get configuration dictionary."""
        return {
            'api_base': self.api_base,
            'model': self.model,
            'master_key': self.master_key,
            'port': self.port
        }


class LiteLLMManager:
    """Manages LiteLLM services with API keys and token statistics."""
    
    def __init__(self, config_file: str = 'litellm_config.json'):
        self.config_file = config_file
        self.lock = threading.Lock()
        self.tasks: Dict[str, LiteLLMTask] = {}  # task_id -> task
        self.api_keys: Dict[str, Dict] = {}  # api_key -> key_info (includes task_id)
        self.token_records: List[Dict] = []  # Database of token records/statistics
        self.load_config()
    
    def load_config(self):
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.api_keys = data.get('api_keys', {})
                    self.token_records = data.get('token_records', [])
                    
                    # Load tasks
                    tasks_data = data.get('tasks', {})
                    for task_id, task_config in tasks_data.items():
                        task = LiteLLMTask(task_id, task_config)
                        self.tasks[task_id] = task
                    
                logger.info(f"Loaded LiteLLM config with {len(self.api_keys)} API keys and {len(self.tasks)} tasks")
            except Exception as e:
                logger.error(f"Error loading LiteLLM config: {e}")
        else:
            logger.info("No existing config file, starting with defaults")
    
    def save_config(self):
        """Save configuration to file."""
        try:
            data = {
                'api_keys': {},
                'tasks': {},
                'token_records': self.token_records[-1000:]  # Keep last 1000 records
            }
            
            # Save API keys (without sensitive data)
            for key, info in self.api_keys.items():
                key_data = info.copy()
                if 'key_hash' in key_data:
                    del key_data['key_hash']
                data['api_keys'][key] = key_data
            
            # Save tasks
            with self.lock:
                for task_id, task in self.tasks.items():
                    task_dict = task.to_dict()
                    # Include master key in saved config
                    if task.master_key:
                        task_dict['master_key'] = task.master_key
                    data['tasks'][task_id] = task_dict
            
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Saved LiteLLM config")
        except Exception as e:
            logger.error(f"Error saving LiteLLM config: {e}")
    
    def add_task(self, config: Dict) -> str:
        """Add a new LiteLLM task/service."""
        task_id = config.get('task_id') or f"litellm_{int(time.time())}"
        
        with self.lock:
            task = LiteLLMTask(task_id, config)
            self.tasks[task_id] = task
        
        self.save_config()
        logger.info(f"Added new LiteLLM task: {task_id}")
        return task_id
    
    def get_task(self, task_id: str) -> Optional[LiteLLMTask]:
        """Get a task by ID."""
        with self.lock:
            return self.tasks.get(task_id)
    
    def get_all_tasks(self) -> List[Dict]:
        """Get all tasks as dictionaries."""
        with self.lock:
            return [task.to_dict() for task in self.tasks.values()]
    
    def update_task(self, task_id: str, updates: Dict) -> bool:
        """Update a task."""
        with self.lock:
            if task_id not in self.tasks:
                return False
            
            task = self.tasks[task_id]
            if task.is_running:
                return False  # Cannot update running task
            
            # Update fields
            for key, value in updates.items():
                if key not in ['task_id', 'is_running', 'status', 'process', 'thread', 'created_at']:
                    if hasattr(task, key):
                        setattr(task, key, value)
            
            self.save_config()
            return True
    
    def delete_task(self, task_id: str) -> bool:
        """Delete a task."""
        with self.lock:
            if task_id not in self.tasks:
                return False
            
            task = self.tasks[task_id]
            if task.is_running:
                self.stop_task(task_id)
            
            # Remove API keys associated with this task
            keys_to_remove = [key for key, info in self.api_keys.items() if info.get('task_id') == task_id]
            for key in keys_to_remove:
                del self.api_keys[key]
            
            del self.tasks[task_id]
        
        self.save_config()
        logger.info(f"Deleted task: {task_id}")
        return True
    
    def generate_api_key(self, task_id: str, name: str, description: str = '') -> Dict[str, Any]:
        """Generate a new API key for a task."""
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")
        
        # Generate a secure random API key
        api_key = f"sk-litellm_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        key_info = {
            'task_id': task_id,
            'name': name,
            'description': description,
            'key_hash': key_hash,
            'created_at': datetime.now().isoformat(),
            'tokens_used_today': 0,
            'tokens_used_total': 0,
            'requests_today': 0,
            'requests_total': 0,
            'last_used': None,
            'is_active': True,
            'statistics': {
                'daily_tokens': defaultdict(int),
                'daily_requests': defaultdict(int),
                'model_usage': defaultdict(int),
                'error_count': 0,
                'success_count': 0
            }
        }
        
        with self.lock:
            self.api_keys[api_key] = key_info
            # Add to task's API keys list
            if api_key not in self.tasks[task_id].api_keys:
                self.tasks[task_id].api_keys.append(api_key)
        
        self.save_config()
        logger.info(f"Generated new API key for task {task_id}: {name}")
        
        return {
            'api_key': api_key,
            'key_info': {k: v for k, v in key_info.items() if k != 'key_hash'}
        }
    
    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """Validate an API key and return its info."""
        if api_key in self.api_keys:
            key_info = self.api_keys[api_key]
            if key_info.get('is_active', True):
                return key_info
        return None
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        with self.lock:
            if api_key in self.api_keys:
                self.api_keys[api_key]['is_active'] = False
                self.save_config()
                logger.info(f"Revoked API key: {api_key[:20]}...")
                return True
        return False
    
    def delete_api_key(self, api_key: str) -> bool:
        """Delete an API key permanently."""
        with self.lock:
            if api_key in self.api_keys:
                task_id = self.api_keys[api_key].get('task_id')
                if task_id and task_id in self.tasks:
                    if api_key in self.tasks[task_id].api_keys:
                        self.tasks[task_id].api_keys.remove(api_key)
                del self.api_keys[api_key]
                self.save_config()
                logger.info(f"Deleted API key: {api_key[:20]}...")
                return True
        return False
    
    def get_task_api_keys(self, task_id: str) -> List[Dict]:
        """Get all API keys for a task."""
        keys = []
        with self.lock:
            if task_id not in self.tasks:
                return keys
            
            for api_key in self.tasks[task_id].api_keys:
                if api_key in self.api_keys:
                    key_info = self.api_keys[api_key].copy()
                    key_data = {
                        'api_key': api_key[:20] + '...' + api_key[-10:],
                        'full_key': api_key,
                        **{k: v for k, v in key_info.items() if k != 'key_hash'}
                    }
                    keys.append(key_data)
        return keys
    
    def record_token_usage(self, api_key: str, tokens: int, model: str = '', 
                         success: bool = True, error: str = ''):
        """Record token usage and update statistics."""
        if api_key not in self.api_keys:
            return
        
        key_info = self.api_keys[api_key]
        task_id = key_info.get('task_id')
        today = datetime.now().date().isoformat()
        
        # Update counters
        key_info['tokens_used_today'] = key_info.get('tokens_used_today', 0) + tokens
        key_info['tokens_used_total'] = key_info.get('tokens_used_total', 0) + tokens
        key_info['requests_today'] = key_info.get('requests_today', 0) + 1
        key_info['requests_total'] = key_info.get('requests_total', 0) + 1
        key_info['last_used'] = datetime.now().isoformat()
        
        # Update statistics
        stats = key_info.get('statistics', {})
        if 'daily_tokens' not in stats:
            stats['daily_tokens'] = defaultdict(int)
        if 'daily_requests' not in stats:
            stats['daily_requests'] = defaultdict(int)
        if 'model_usage' not in stats:
            stats['model_usage'] = defaultdict(int)
        
        if isinstance(stats['daily_tokens'], dict) and not isinstance(stats['daily_tokens'], defaultdict):
            stats['daily_tokens'] = defaultdict(int, stats['daily_tokens'])
        if isinstance(stats['daily_requests'], dict) and not isinstance(stats['daily_requests'], defaultdict):
            stats['daily_requests'] = defaultdict(int, stats['daily_requests'])
        if isinstance(stats['model_usage'], dict) and not isinstance(stats['model_usage'], defaultdict):
            stats['model_usage'] = defaultdict(int, stats['model_usage'])
        
        stats['daily_tokens'][today] += tokens
        stats['daily_requests'][today] += 1
        if model:
            stats['model_usage'][model] += 1
        if success:
            stats['success_count'] = stats.get('success_count', 0) + 1
        else:
            stats['error_count'] = stats.get('error_count', 0) + 1
        
        # Add to token records database
        record = {
            'record_id': f"record_{int(time.time() * 1000)}_{secrets.token_hex(8)}",
            'api_key': api_key[:20] + '...',
            'task_id': task_id,
            'tokens': tokens,
            'model': model,
            'success': success,
            'error': error[:200] if error else '',
            'timestamp': datetime.now().isoformat(),
            'date': today
        }
        
        with self.lock:
            self.token_records.append(record)
            # Keep only last 10000 records
            if len(self.token_records) > 10000:
                self.token_records = self.token_records[-10000:]
            
            # Update task statistics
            if task_id and task_id in self.tasks:
                task = self.tasks[task_id]
                task.total_requests += 1
                task.total_tokens += tokens
                if not success:
                    task.failed_requests += 1
                task.last_activity = datetime.now().isoformat()
        
        self.save_config()
    
    def get_token_records(self, task_id: Optional[str] = None, 
                          api_key: Optional[str] = None,
                          start_date: Optional[str] = None,
                          end_date: Optional[str] = None,
                          limit: int = 100) -> List[Dict]:
        """Retrieve token records from database."""
        records = self.token_records.copy()
        
        # Filter by task_id
        if task_id:
            records = [r for r in records if r.get('task_id') == task_id]
        
        # Filter by api_key
        if api_key:
            records = [r for r in records if r.get('api_key', '').startswith(api_key[:20])]
        
        # Filter by date range
        if start_date:
            records = [r for r in records if r.get('date', '') >= start_date]
        if end_date:
            records = [r for r in records if r.get('date', '') <= end_date]
        
        # Sort by timestamp (newest first) and limit
        records.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return records[:limit]
    
    def get_statistics(self, task_id: Optional[str] = None, 
                      api_key: Optional[str] = None) -> Dict:
        """Get statistics for task(s) or API key(s)."""
        if api_key:
            if api_key in self.api_keys:
                key_info = self.api_keys[api_key]
                return {
                    'api_key': api_key[:20] + '...',
                    'statistics': key_info.get('statistics', {}),
                    'usage': {
                        'tokens_used_today': key_info.get('tokens_used_today', 0),
                        'tokens_used_total': key_info.get('tokens_used_total', 0),
                        'requests_today': key_info.get('requests_today', 0),
                        'requests_total': key_info.get('requests_total', 0),
                        'last_used': key_info.get('last_used')
                    }
                }
            return {}
        elif task_id:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                # Aggregate statistics from all API keys for this task
                task_keys = [k for k, v in self.api_keys.items() if v.get('task_id') == task_id]
                total_tokens = sum(self.api_keys[k].get('tokens_used_total', 0) for k in task_keys)
                total_requests = sum(self.api_keys[k].get('requests_total', 0) for k in task_keys)
                
                return {
                    'task_id': task_id,
                    'task_name': task.name,
                    'total_requests': task.total_requests,
                    'total_tokens': task.total_tokens,
                    'failed_requests': task.failed_requests,
                    'api_keys_count': len(task.api_keys),
                    'aggregated': {
                        'total_tokens': total_tokens,
                        'total_requests': total_requests
                    }
                }
            return {}
        else:
            # Aggregate statistics for all tasks
            total_stats = {
                'total_tasks': len(self.tasks),
                'total_api_keys': len(self.api_keys),
                'active_api_keys': sum(1 for k in self.api_keys.values() if k.get('is_active', True)),
                'total_requests': sum(k.get('requests_total', 0) for k in self.api_keys.values()),
                'total_tokens': sum(k.get('tokens_used_total', 0) for k in self.api_keys.values()),
                'requests_today': sum(k.get('requests_today', 0) for k in self.api_keys.values()),
                'tokens_today': sum(k.get('tokens_used_today', 0) for k in self.api_keys.values())
            }
            return total_stats
    
    def _create_fastapi_app(self, task: LiteLLMTask):
        """Create FastAPI app for LiteLLM proxy."""
        if not FASTAPI_AVAILABLE:
            logger.error(f"[Task {task.task_id}] FastAPI not available. Cannot create proxy server.")
            return None
        
        logger.info(f"[Task {task.task_id}] Creating FastAPI app for LiteLLM proxy on port {task.port}")
        
        app = FastAPI(title=f"LiteLLM Proxy - {task.name}")
        
        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
        async def litellm_proxy(request: Request, path: str):
            """Proxy requests to LiteLLM with API key validation."""
            logger.info(f"[Task {task.task_id}] Received {request.method} request to /{path}")
            
            # Get API key from header
            auth_header = request.headers.get("Authorization", "")
            api_key = auth_header.replace("Bearer ", "") if auth_header else ""
            if not api_key:
                api_key = request.headers.get("X-API-Key", "")
            
            if not api_key:
                raise HTTPException(status_code=401, detail="API key required")
            
            # Validate API key
            key_info = self.validate_api_key(api_key)
            if not key_info:
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            # Check if API key belongs to this task
            if key_info.get('task_id') != task.task_id:
                raise HTTPException(status_code=403, detail="API key does not belong to this task")
            
            # Get request body
            try:
                body = await request.body()
                data = json.loads(body) if body else {}
            except Exception as e:
                logger.warning(f"[Task {task.task_id}] Error parsing request body: {e}")
                data = {}
            
            # Forward request to LiteLLM API base
            try:
                if not REQUESTS_AVAILABLE:
                    raise HTTPException(status_code=500, detail="Requests library not available")
                
                # Prepare headers
                forward_headers = {
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {task.master_key}' if task.master_key else ''
                }
                
                # Build URL
                api_url = f"{task.api_base.rstrip('/')}/{path.lstrip('/')}"
                
                # Make request
                response = requests.request(
                    method=request.method,
                    url=api_url,
                    json=data if body else None,
                    headers=forward_headers,
                    timeout=300
                )
                
                # Estimate tokens (rough estimate)
                tokens = 0
                if body:
                    # Rough estimate: ~4 characters per token
                    tokens = len(body) // 4
                
                # Record usage
                model = data.get('model', task.model) if isinstance(data, dict) else task.model
                self.record_token_usage(
                    api_key, 
                    tokens, 
                    model,
                    success=response.status_code == 200,
                    error=response.text[:200] if response.status_code != 200 else ''
                )
                
                # Update task activity
                task.last_activity = datetime.now().isoformat()
                
                return JSONResponse(
                    content=response.json() if response.headers.get('content-type', '').startswith('application/json') else {'response': response.text},
                    status_code=response.status_code
                )
                
            except Exception as e:
                logger.error(f"[Task {task.task_id}] Error forwarding request: {e}")
                tokens = len(body) // 4 if body else 0
                model = data.get('model', task.model) if isinstance(data, dict) else task.model
                self.record_token_usage(api_key, tokens, model, success=False, error=str(e))
                raise HTTPException(status_code=500, detail=f"Error forwarding to LiteLLM: {str(e)}")
        
        logger.info(f"[Task {task.task_id}] FastAPI app created successfully")
        return app
    
    def _run_fastapi_server(self, task: LiteLLMTask):
        """Run FastAPI server in a separate thread."""
        try:
            logger.info(f"[Task {task.task_id}] Starting FastAPI server setup...")
            
            app = self._create_fastapi_app(task)
            if not app:
                logger.error(f"[Task {task.task_id}] Failed to create FastAPI app")
                task.status = 'error'
                task.is_running = False
                return
            
            task.fastapi_app = app
            
            config = uvicorn.Config(
                app=app,
                host="0.0.0.0",
                port=task.port,
                log_level="info"
            )
            server = uvicorn.Server(config)
            task.fastapi_server = server
            
            logger.info(f"[Task {task.task_id}] Starting FastAPI server on 0.0.0.0:{task.port}")
            server.run()
            
        except OSError as e:
            if "Address already in use" in str(e):
                logger.error(f"[Task {task.task_id}] Port {task.port} is already in use!")
            task.status = 'error'
            task.is_running = False
        except Exception as e:
            logger.error(f"[Task {task.task_id}] Error running FastAPI server: {e}", exc_info=True)
            task.status = 'error'
            task.is_running = False
    
    def start_task(self, task_id: str) -> bool:
        """Start a LiteLLM proxy task."""
        with self.lock:
            if task_id not in self.tasks:
                logger.warning(f"[Task {task_id}] Cannot start: Task not found")
                return False
            
            task = self.tasks[task_id]
            if task.is_running:
                logger.warning(f"[Task {task_id}] Cannot start: Task is already running")
                return False
            
            task.is_running = True
            task.status = 'running'
            task.stop_event.clear()
        
        logger.info(f"[Task {task_id}] Starting task '{task.name}' on port {task.port}")
        
        # Start FastAPI server in separate thread
        if FASTAPI_AVAILABLE:
            def run_server():
                try:
                    self._run_fastapi_server(task)
                except Exception as e:
                    logger.error(f"Error in FastAPI server thread for {task_id}: {e}", exc_info=True)
                    task.status = 'error'
                    task.is_running = False
            
            server_thread = threading.Thread(target=run_server, daemon=True, name=f"LiteLLM-{task_id}")
            server_thread.start()
            time.sleep(1)  # Give server time to start
        else:
            logger.error(f"[Task {task_id}] FastAPI not available! Install with: pip install fastapi uvicorn")
            task.status = 'error'
            task.is_running = False
            return False
        
        return True
    
    def stop_task(self, task_id: str) -> bool:
        """Stop a running task."""
        with self.lock:
            if task_id not in self.tasks:
                logger.warning(f"[Task {task_id}] Cannot stop: Task not found")
                return False
            
            task = self.tasks[task_id]
            if not task.is_running:
                logger.warning(f"[Task {task_id}] Cannot stop: Task is not running")
                return False
            
            task.stop_event.set()
            task.is_running = False
            task.status = 'stopped'
            
            # Stop FastAPI server if running
            if task.fastapi_server:
                try:
                    task.fastapi_server.should_exit = True
                    logger.info(f"[Task {task_id}] Stopping FastAPI server")
                except:
                    pass
        
        logger.info(f"[Task {task_id}] Stopping task")
        return True
    
    def get_task_api_examples(self, task_id: str) -> Dict:
        """Get API usage examples and instructions for a task."""
        with self.lock:
            if task_id not in self.tasks:
                return {}
            
            task = self.tasks[task_id]
            
            # Get a sample API key for demonstration
            sample_api_key = "YOUR_API_KEY_HERE"
            if task.api_keys:
                # Use first active key as example
                for key in task.api_keys:
                    if key in self.api_keys and self.api_keys[key].get('is_active', True):
                        sample_api_key = key
                        break
            
            proxy_url = f"http://localhost:{task.port}"
            
            examples = {
                'task_id': task_id,
                'task_name': task.name,
                'description': task.description,
                'proxy_url': proxy_url,
                'api_base': task.api_base,
                'model': task.model,
                'sample_api_key': sample_api_key[:30] + '...' if len(sample_api_key) > 30 else sample_api_key,
                'instructions': {
                    'overview': f'''This LiteLLM proxy provides OpenAI-compatible APIs for {task.name}.
The proxy runs on port {task.port} and forwards requests to {task.api_base}.
All requests must include a valid API key in the Authorization header.''',
                    'authentication': f'''Use one of these methods to authenticate:

1. Authorization Bearer Token:
   Authorization: Bearer {sample_api_key}

2. X-API-Key Header:
   X-API-Key: {sample_api_key}''',
                    'base_url': f'''Base URL: {proxy_url}
All OpenAI-compatible endpoints are available at this base URL.'''
                },
                'examples': {
                    'chat_completions': {
                        'description': 'Chat completions endpoint - for conversational AI',
                        'endpoint': '/v1/chat/completions',
                        'curl': f'''curl -X POST {proxy_url}/v1/chat/completions \\
  -H "Authorization: Bearer {sample_api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "{task.model}",
    "messages": [
      {{"role": "system", "content": "You are a helpful assistant."}},
      {{"role": "user", "content": "Hello! How are you?"}}
    ],
    "temperature": 0.7,
    "max_tokens": 150
  }}' ''',
                        'python': f'''import requests

url = "{proxy_url}/v1/chat/completions"
headers = {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
}}
data = {{
    "model": "{task.model}",
    "messages": [
        {{"role": "system", "content": "You are a helpful assistant."}},
        {{"role": "user", "content": "Hello! How are you?"}}
    ],
    "temperature": 0.7,
    "max_tokens": 150
}}

response = requests.post(url, json=data, headers=headers)
print(response.json())''',
                        'javascript': f'''const response = await fetch("{proxy_url}/v1/chat/completions", {{
  method: "POST",
  headers: {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
  }},
  body: JSON.stringify({{
    model: "{task.model}",
    messages: [
      {{role: "system", content: "You are a helpful assistant."}},
      {{role: "user", content: "Hello! How are you?"}}
    ],
    temperature: 0.7,
    max_tokens: 150
  }})
}});

const data = await response.json();
console.log(data);''',
                        'json': {
                            "model": task.model,
                            "messages": [
                                {"role": "system", "content": "You are a helpful assistant."},
                                {"role": "user", "content": "Hello! How are you?"}
                            ],
                            "temperature": 0.7,
                            "max_tokens": 150
                        }
                    },
                    'completions': {
                        'description': 'Text completions endpoint - for text generation',
                        'endpoint': '/v1/completions',
                        'curl': f'''curl -X POST {proxy_url}/v1/completions \\
  -H "Authorization: Bearer {sample_api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "{task.model}",
    "prompt": "The capital of France is",
    "max_tokens": 50,
    "temperature": 0.7
  }}' ''',
                        'python': f'''import requests

url = "{proxy_url}/v1/completions"
headers = {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
}}
data = {{
    "model": "{task.model}",
    "prompt": "The capital of France is",
    "max_tokens": 50,
    "temperature": 0.7
}}

response = requests.post(url, json=data, headers=headers)
print(response.json())''',
                        'javascript': f'''const response = await fetch("{proxy_url}/v1/completions", {{
  method: "POST",
  headers: {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
  }},
  body: JSON.stringify({{
    model: "{task.model}",
    prompt: "The capital of France is",
    max_tokens: 50,
    temperature: 0.7
  }})
}});

const data = await response.json();
console.log(data);''',
                        'json': {
                            "model": task.model,
                            "prompt": "The capital of France is",
                            "max_tokens": 50,
                            "temperature": 0.7
                        }
                    },
                    'embeddings': {
                        'description': 'Embeddings endpoint - for text embeddings',
                        'endpoint': '/v1/embeddings',
                        'curl': f'''curl -X POST {proxy_url}/v1/embeddings \\
  -H "Authorization: Bearer {sample_api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "{task.model}",
    "input": "The food was delicious and the waiter was very attentive."
  }}' ''',
                        'python': f'''import requests

url = "{proxy_url}/v1/embeddings"
headers = {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
}}
data = {{
    "model": "{task.model}",
    "input": "The food was delicious and the waiter was very attentive."
}}

response = requests.post(url, json=data, headers=headers)
print(response.json())''',
                        'javascript': f'''const response = await fetch("{proxy_url}/v1/embeddings", {{
  method: "POST",
  headers: {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
  }},
  body: JSON.stringify({{
    model: "{task.model}",
    input: "The food was delicious and the waiter was very attentive."
  }})
}});

const data = await response.json();
console.log(data);''',
                        'json': {
                            "model": task.model,
                            "input": "The food was delicious and the waiter was very attentive."
                        }
                    },
                    'models': {
                        'description': 'List available models',
                        'endpoint': '/v1/models',
                        'curl': f'''curl -X GET {proxy_url}/v1/models \\
  -H "Authorization: Bearer {sample_api_key}"''',
                        'python': f'''import requests

url = "{proxy_url}/v1/models"
headers = {{
    "Authorization": "Bearer {sample_api_key}"
}}

response = requests.get(url, headers=headers)
print(response.json())''',
                        'javascript': f'''const response = await fetch("{proxy_url}/v1/models", {{
  method: "GET",
  headers: {{
    "Authorization": "Bearer {sample_api_key}"
  }}
}});

const data = await response.json();
console.log(data);''',
                        'json': None
                    }
                },
                'notes': [
                    'All endpoints are OpenAI-compatible and follow the OpenAI API specification.',
                    f'The proxy forwards requests to {task.api_base} with the master key configured for this task.',
                    'Token usage is automatically tracked for each API key.',
                    'Rate limiting and token limits can be configured per API key.',
                    'Check the token records section to view usage statistics.'
                ]
            }
            
            return examples

