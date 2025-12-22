#!/usr/bin/env python3
"""
Ollama Gateway Manager for handling Ollama API gateway operations.
Manages API keys, token counting, rate limiting, request queuing, and statistics.
"""

import json
import os
import time
import threading
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import requests
from urllib.parse import urljoin

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available. Install with: pip install redis")

try:
    from fastapi import FastAPI, Request, HTTPException, Header, WebSocket, WebSocketDisconnect
    from fastapi.responses import StreamingResponse, JSONResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logging.warning("FastAPI not available. Install with: pip install fastapi uvicorn")

logger = logging.getLogger(__name__)


class OllamaTask:
    """Represents a single Ollama gateway configuration and its worker task."""
    
    def __init__(self, task_id: str, config: Dict):
        self.task_id = task_id
        self.name = config.get('name', f'Gateway {task_id}')
        self.description = config.get('description', '')
        
        # Gateway configuration
        self.ollama_url = config.get('ollama_url', 'http://localhost:11434')
        self.gateway_port = config.get('gateway_port', 11435)
        self.mode = config.get('mode', 'redis')  # 'redis' for queued, 'direct' for direct forwarding
        self.redis_host = config.get('redis_host', 'localhost')
        self.redis_port = config.get('redis_port', 6379)
        self.redis_db = config.get('redis_db', 0)
        self.redis_password = config.get('redis_password', None)
        self.max_queue_size = config.get('max_queue_size', 1000)
        self.default_rate_limit = config.get('default_rate_limit', 100)
        self.default_token_limit = config.get('default_token_limit', 1000000)
        
        # Task status
        self.is_running = False
        self.status = 'stopped'  # stopped, running, error
        self.thread = None
        self.stop_event = threading.Event()
        self.processed_jobs = 0
        self.failed_jobs = 0
        self.last_activity = None
        self.created_at = config.get('created_at', datetime.now().isoformat())
        self.redis_client = None
        self.job_history = []  # Latest 50 jobs for monitoring
        self.fastapi_app = None
        self.fastapi_server = None
        
    def to_dict(self):
        """Convert task to dictionary."""
        return {
            'task_id': self.task_id,
            'name': self.name,
            'description': self.description,
            'ollama_url': self.ollama_url,
            'gateway_port': self.gateway_port,
            'mode': self.mode,
            'redis_host': self.redis_host,
            'redis_port': self.redis_port,
            'redis_db': self.redis_db,
            'redis_password': '***' if self.redis_password else None,
            'max_queue_size': self.max_queue_size,
            'default_rate_limit': self.default_rate_limit,
            'default_token_limit': self.default_token_limit,
            'is_running': self.is_running,
            'status': self.status,
            'processed_jobs': self.processed_jobs,
            'failed_jobs': self.failed_jobs,
            'last_activity': self.last_activity,
            'created_at': self.created_at,
            'job_history': self.job_history[-50:]  # Keep latest 50 in saved data
        }
    
    def get_config_dict(self) -> Dict:
        """Get configuration dictionary."""
        return {
            'ollama_url': self.ollama_url,
            'gateway_port': self.gateway_port,
            'mode': self.mode,
            'redis_host': self.redis_host,
            'redis_port': self.redis_port,
            'redis_db': self.redis_db,
            'redis_password': self.redis_password,
            'max_queue_size': self.max_queue_size,
            'default_rate_limit': self.default_rate_limit,
            'default_token_limit': self.default_token_limit
        }
    
    def _init_redis(self):
        """Initialize Redis connection for this task."""
        if not REDIS_AVAILABLE:
            print(f"[WARN] [Task {self.task_id}] Redis library not available")
            return None
            
        try:
            print(f"[DEBUG] [Task {self.task_id}] Connecting to Redis at {self.redis_host}:{self.redis_port} DB:{self.redis_db}")
            client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                decode_responses=True,
                socket_connect_timeout=5
            )
            print(f"[DEBUG] [Task {self.task_id}] Testing Redis connection...")
            client.ping()
            print(f"[DEBUG] [Task {self.task_id}] Redis connection successful!")
            return client
        except Exception as e:
            logger.error(f"[Task {self.task_id}] Failed to connect to Redis: {e}", exc_info=True)
            print(f"[ERROR] [Task {self.task_id}] Failed to connect to Redis: {e}")
            print(f"[ERROR] [Task {self.task_id}] Redis config: {self.redis_host}:{self.redis_port} DB:{self.redis_db}")
            import traceback
            traceback.print_exc()
            return None


class OllamaGatewayManager:
    """Manages Ollama Gateway Service with Redis queue, API keys, and statistics."""
    
    def __init__(self, config_file: str = 'ollama_gateway_config.json'):
        self.config_file = config_file
        self.lock = threading.Lock()
        self.api_keys: Dict[str, Dict] = {}  # api_key -> key_info
        self.tasks: Dict[str, OllamaTask] = {}  # task_id -> task (each task is a gateway configuration)
        # Default configuration values (used when creating API keys without specific limits)
        self.config = {
            'default_rate_limit': 100,
            'default_token_limit': 1000000
        }
        self.load_config()
    
    def load_config(self):
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.api_keys = data.get('api_keys', {})
                    # Load tasks (each task is a gateway configuration)
                    tasks_data = data.get('tasks', {})
                    for task_id, task_config in tasks_data.items():
                        task = OllamaTask(task_id, task_config)
                        # Restore job history if saved
                        if 'job_history' in task_config:
                            task.job_history = task_config['job_history']
                        self.tasks[task_id] = task
                    
                    # Ensure statistics are properly initialized for all API keys
                    for api_key, key_info in self.api_keys.items():
                        if 'statistics' not in key_info:
                            key_info['statistics'] = {
                                'daily_tokens': {},
                                'daily_requests': {},
                                'model_usage': {},
                                'error_count': 0,
                                'success_count': 0
                            }
                        # Convert saved dicts to defaultdicts if needed
                        stats = key_info['statistics']
                        daily_tokens = stats.get('daily_tokens')
                        if daily_tokens is None:
                            stats['daily_tokens'] = defaultdict(int)
                        elif isinstance(daily_tokens, dict) and not isinstance(daily_tokens, defaultdict):
                            stats['daily_tokens'] = defaultdict(int, daily_tokens)
                        
                        daily_requests = stats.get('daily_requests')
                        if daily_requests is None:
                            stats['daily_requests'] = defaultdict(int)
                        elif isinstance(daily_requests, dict) and not isinstance(daily_requests, defaultdict):
                            stats['daily_requests'] = defaultdict(int, daily_requests)
                        
                        model_usage = stats.get('model_usage')
                        if model_usage is None:
                            stats['model_usage'] = defaultdict(int)
                        elif isinstance(model_usage, dict) and not isinstance(model_usage, defaultdict):
                            stats['model_usage'] = defaultdict(int, model_usage)
                logger.info(f"Loaded Ollama Gateway config with {len(self.api_keys)} API keys and {len(self.tasks)} gateway configurations")
            except Exception as e:
                logger.error(f"Error loading Ollama Gateway config: {e}")
        else:
            logger.info("No existing config file, starting with defaults")
    
    def save_config(self):
        """Save configuration to file."""
        try:
            data = {
                'api_keys': {},
                'tasks': {}
            }
            # Save API keys without sensitive data
            for key, info in self.api_keys.items():
                key_data = info.copy()
                # Don't save full key hash, just metadata
                if 'key_hash' in key_data:
                    del key_data['key_hash']
                data['api_keys'][key] = key_data
            
            # Save tasks (each task contains its gateway configuration)
            with self.lock:
                for task_id, task in self.tasks.items():
                    task_dict = task.to_dict()
                    # Include password in saved config (for Redis connection)
                    if task.redis_password:
                        task_dict['redis_password'] = task.redis_password
                    data['tasks'][task_id] = task_dict
            
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Saved Ollama Gateway config")
        except Exception as e:
            logger.error(f"Error saving Ollama Gateway config: {e}")
    
    def generate_api_key(self, name: str, description: str = '', 
                        rate_limit: Optional[int] = None,
                        token_limit: Optional[int] = None) -> Dict[str, Any]:
        """Generate a new API key."""
        # Generate a secure random API key
        api_key = f"ollama_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        key_info = {
            'name': name,
            'description': description,
            'key_hash': key_hash,
            'created_at': datetime.now().isoformat(),
            'rate_limit': rate_limit if rate_limit is not None else self.config.get('default_rate_limit', 100),
            'token_limit': token_limit if token_limit is not None else self.config.get('default_token_limit', 1000000),
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
        
        self.save_config()
        logger.info(f"Generated new API key: {name}")
        
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
                del self.api_keys[api_key]
                self.save_config()
                logger.info(f"Deleted API key: {api_key[:20]}...")
                return True
        return False
    
    def update_api_key(self, api_key: str, updates: Dict) -> bool:
        """Update API key settings."""
        with self.lock:
            if api_key in self.api_keys:
                for key, value in updates.items():
                    if key not in ['key_hash', 'created_at', 'statistics']:
                        self.api_keys[api_key][key] = value
                self.save_config()
                return True
        return False
    
    def get_all_api_keys(self) -> List[Dict]:
        """Get all API keys (without sensitive data)."""
        keys = []
        with self.lock:
            for api_key, info in self.api_keys.items():
                key_data = {
                    'api_key': api_key[:20] + '...' + api_key[-10:],  # Partial key for display
                    'full_key': api_key,  # Include full key for management
                    **{k: v for k, v in info.items() if k != 'key_hash'}
                }
                keys.append(key_data)
        return keys
    
    def _get_redis_client(self):
        """Get a Redis client from any available task."""
        with self.lock:
            for task in self.tasks.values():
                if task.redis_client:
                    return task.redis_client
                # Try to initialize if not already done
                redis_client = task._init_redis()
                if redis_client:
                    task.redis_client = redis_client
                    return redis_client
        return None
    
    def check_rate_limit(self, api_key: str, redis_client: Optional[Any] = None) -> Tuple[bool, Optional[str]]:
        """Check if API key is within rate limit."""
        key_info = self.api_keys.get(api_key)
        if not key_info or not key_info.get('is_active', True):
            return False, "API key not found or inactive"
        
        # Use provided Redis client or get one from tasks
        if not redis_client:
            redis_client = self._get_redis_client()
        
        # Check rate limit using Redis if available
        if redis_client:
            try:
                rate_key = f"rate_limit:{api_key}"
                current = redis_client.get(rate_key)
                if current and int(current) >= key_info['rate_limit']:
                    return False, "Rate limit exceeded"
                # Increment counter
                pipe = redis_client.pipeline()
                pipe.incr(rate_key)
                pipe.expire(rate_key, 60)  # Reset every minute
                pipe.execute()
            except Exception as e:
                logger.error(f"Redis rate limit check error: {e}")
                print(f"[ERROR] Redis rate limit check error: {e}")
        else:
            # Fallback: simple in-memory rate limiting (not ideal for production)
            logger.warning("Redis not available for rate limiting, using fallback")
            print(f"[WARN] Redis not available for rate limiting")
        
        return True, None
    
    def check_token_limit(self, api_key: str, tokens: int) -> Tuple[bool, Optional[str]]:
        """Check if API key has enough token quota."""
        key_info = self.api_keys.get(api_key)
        if not key_info:
            return False, "API key not found"
        
        # Reset daily tokens if it's a new day
        today = datetime.now().date().isoformat()
        last_reset = key_info.get('last_reset_date')
        if last_reset != today:
            key_info['tokens_used_today'] = 0
            key_info['requests_today'] = 0
            key_info['last_reset_date'] = today
        
        if key_info['tokens_used_today'] + tokens > key_info['token_limit']:
            return False, "Token limit exceeded for today"
        
        return True, None
    
    def record_request(self, api_key: str, tokens_used: int, model: str = '', 
                     success: bool = True, error: str = ''):
        """Record a request and update statistics."""
        if api_key not in self.api_keys:
            return
        
        key_info = self.api_keys[api_key]
        today = datetime.now().date().isoformat()
        
        # Update counters
        key_info['tokens_used_today'] = key_info.get('tokens_used_today', 0) + tokens_used
        key_info['tokens_used_total'] = key_info.get('tokens_used_total', 0) + tokens_used
        key_info['requests_today'] = key_info.get('requests_today', 0) + 1
        key_info['requests_total'] = key_info.get('requests_total', 0) + 1
        key_info['last_used'] = datetime.now().isoformat()
        
        # Ensure statistics dict exists and has defaultdicts
        if 'statistics' not in key_info:
            key_info['statistics'] = {
                'daily_tokens': defaultdict(int),
                'daily_requests': defaultdict(int),
                'model_usage': defaultdict(int),
                'error_count': 0,
                'success_count': 0
            }
        
        stats = key_info['statistics']
        
        # Ensure defaultdicts are properly initialized
        daily_tokens = stats.get('daily_tokens')
        if daily_tokens is None:
            stats['daily_tokens'] = defaultdict(int)
        elif not isinstance(daily_tokens, defaultdict):
            stats['daily_tokens'] = defaultdict(int, daily_tokens if isinstance(daily_tokens, dict) else {})
        
        daily_requests = stats.get('daily_requests')
        if daily_requests is None:
            stats['daily_requests'] = defaultdict(int)
        elif not isinstance(daily_requests, defaultdict):
            stats['daily_requests'] = defaultdict(int, daily_requests if isinstance(daily_requests, dict) else {})
        
        model_usage = stats.get('model_usage')
        if model_usage is None:
            stats['model_usage'] = defaultdict(int)
        elif not isinstance(model_usage, defaultdict):
            stats['model_usage'] = defaultdict(int, model_usage if isinstance(model_usage, dict) else {})
        
        # Update statistics (now safe - using defaultdict)
        stats['daily_tokens'][today] += tokens_used
        stats['daily_requests'][today] += 1
        if model:
            stats['model_usage'][model] += 1
        if success:
            stats['success_count'] = stats.get('success_count', 0) + 1
        else:
            stats['error_count'] = stats.get('error_count', 0) + 1
        
        self.save_config()
    
    def queue_request(self, task_id: str, api_key: str, endpoint: str, method: str = 'POST', 
                     data: Dict = None, headers: Dict = None) -> str:
        """Queue a request to be processed by a specific gateway task."""
        logger.debug(f"Queueing request for task {task_id}, endpoint: {endpoint}, method: {method}")
        print(f"[DEBUG] Queueing request for task {task_id}, endpoint: {endpoint}, method: {method}")
        
        if task_id not in self.tasks:
            error_msg = f"Task {task_id} not found"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}")
            raise ValueError(error_msg)
        
        task = self.tasks[task_id]
        job_id = f"job_{int(time.time() * 1000)}_{secrets.token_hex(8)}"
        print(f"[DEBUG] Generated job_id: {job_id}")
        
        job_data = {
            'job_id': job_id,
            'task_id': task_id,
            'api_key': api_key,
            'endpoint': endpoint,
            'method': method,
            'data': data or {},
            'headers': headers or {},
            'created_at': datetime.now().isoformat(),
            'status': 'queued'
        }
        
        # Use task's Redis connection
        print(f"[DEBUG] Initializing Redis connection for task {task_id}...")
        redis_client = task._init_redis()
        if redis_client:
            try:
                queue_name = f"ollama_queue:{task_id}"
                print(f"[DEBUG] Queue name: {queue_name}")
                print(f"[DEBUG] Adding job to Redis queue...")
                # Add to task-specific queue
                redis_client.lpush(queue_name, json.dumps(job_data))
                print(f"[DEBUG] Job added to queue successfully")
                # Store job data
                redis_client.setex(
                    f"job:{job_id}",
                    3600,  # 1 hour TTL
                    json.dumps(job_data)
                )
                print(f"[DEBUG] Job data stored in Redis with key: job:{job_id}")
                logger.info(f"Queued job {job_id} to task {task_id} for API key {api_key[:20]}...")
                print(f"[INFO] Queued job {job_id} to task {task_id}")
                return job_id
            except Exception as e:
                logger.error(f"Error queueing job to Redis: {e}", exc_info=True)
                print(f"[ERROR] Error queueing job to Redis: {e}")
                import traceback
                traceback.print_exc()
                return job_id
        else:
            logger.warning(f"Redis not available for task {task_id}")
            print(f"[WARN] Redis not available for task {task_id}")
            return job_id
    
    def get_queue_status(self, task_id: Optional[str] = None) -> Dict:
        """Get current queue status for a specific task or all tasks."""
        if task_id:
            # Get status for specific task
            if task_id not in self.tasks:
                return {'error': 'Task not found'}
            
            task = self.tasks[task_id]
            redis_client = task._init_redis()
            if not redis_client:
                return {
                    'queue_length': 0,
                    'redis_connected': False,
                    'error': 'Redis not available'
                }
            
            try:
                queue_name = f"ollama_queue:{task_id}"
                queue_length = redis_client.llen(queue_name)
                return {
                    'task_id': task_id,
                    'queue_length': queue_length,
                    'redis_connected': True,
                    'max_queue_size': task.max_queue_size
                }
            except Exception as e:
                logger.error(f"Error getting queue status for task {task_id}: {e}")
                return {
                    'queue_length': 0,
                    'redis_connected': False,
                    'error': str(e)
                }
        else:
            # Aggregate status for all tasks
            total_queue = 0
            tasks_status = []
            for tid, task in self.tasks.items():
                redis_client = task._init_redis()
                if redis_client:
                    try:
                        queue_name = f"ollama_queue:{tid}"
                        queue_length = redis_client.llen(queue_name)
                        total_queue += queue_length
                        tasks_status.append({
                            'task_id': tid,
                            'task_name': task.name,
                            'queue_length': queue_length,
                            'max_queue_size': task.max_queue_size
                        })
                    except:
                        pass
            
            return {
                'total_queue_length': total_queue,
                'tasks': tasks_status,
                'redis_connected': len(tasks_status) > 0
            }
    
    def get_job_status(self, job_id: str, task_id: Optional[str] = None) -> Optional[Dict]:
        """Get status of a queued job."""
        redis_client = None
        
        # If task_id provided, use that task's Redis
        if task_id and task_id in self.tasks:
            task = self.tasks[task_id]
            redis_client = task.redis_client or task._init_redis()
        else:
            # Try to get Redis from any task
            redis_client = self._get_redis_client()
        
        if not redis_client:
            return None
        
        try:
            job_data = redis_client.get(f"job:{job_id}")
            if job_data:
                return json.loads(job_data)
        except Exception as e:
            logger.error(f"Error getting job status: {e}")
        return None
    
    def get_statistics(self, api_key: Optional[str] = None) -> Dict:
        """Get statistics for API key(s)."""
        if api_key:
            if api_key in self.api_keys:
                return {
                    'api_key': api_key[:20] + '...',
                    'statistics': self.api_keys[api_key].get('statistics', {}),
                    'usage': {
                        'tokens_used_today': self.api_keys[api_key].get('tokens_used_today', 0),
                        'tokens_used_total': self.api_keys[api_key].get('tokens_used_total', 0),
                        'requests_today': self.api_keys[api_key].get('requests_today', 0),
                        'requests_total': self.api_keys[api_key].get('requests_total', 0),
                        'last_used': self.api_keys[api_key].get('last_used')
                    }
                }
            return {}
        else:
            # Aggregate statistics for all keys
            total_stats = {
                'total_api_keys': len(self.api_keys),
                'active_api_keys': sum(1 for k in self.api_keys.values() if k.get('is_active', True)),
                'total_requests': sum(k.get('requests_total', 0) for k in self.api_keys.values()),
                'total_tokens': sum(k.get('tokens_used_total', 0) for k in self.api_keys.values()),
                'requests_today': sum(k.get('requests_today', 0) for k in self.api_keys.values()),
                'tokens_today': sum(k.get('tokens_used_today', 0) for k in self.api_keys.values())
            }
            return total_stats
    
    # Task Management Methods (each task is a gateway configuration)
    def add_task(self, config: Dict) -> str:
        """Add a new gateway configuration task."""
        task_id = config.get('task_id') or f"gateway_{int(time.time())}"
        
        with self.lock:
            task = OllamaTask(task_id, config)
            self.tasks[task_id] = task
        
        self.save_config()
        logger.info(f"Added new gateway configuration: {task_id}")
        return task_id
    
    def get_task(self, task_id: str) -> Optional[OllamaTask]:
        """Get a task by ID."""
        with self.lock:
            return self.tasks.get(task_id)
    
    def get_all_tasks(self) -> List[Dict]:
        """Get all tasks as dictionaries."""
        with self.lock:
            return [task.to_dict() for task in self.tasks.values()]
    
    def update_task(self, task_id: str, updates: Dict) -> bool:
        """Update a gateway configuration task."""
        with self.lock:
            if task_id not in self.tasks:
                return False
            
            task = self.tasks[task_id]
            if task.is_running:
                return False  # Cannot update running task
            
            # Update gateway configuration fields
            for key, value in updates.items():
                if key not in ['task_id', 'is_running', 'status', 'thread', 'processed_jobs', 'failed_jobs', 'created_at', 'redis_client', 'last_activity']:
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
            
            del self.tasks[task_id]
        
        self.save_config()
        logger.info(f"Deleted task: {task_id}")
        return True
    
    def _process_queue_worker(self, task: OllamaTask):
        """Worker loop that processes jobs from Redis queue."""
        logger.info(f"[Task {task.task_id}] Worker started")
        print(f"[DEBUG] [Task {task.task_id}] Queue worker started")
        
        # Initialize Redis connection for this task
        print(f"[DEBUG] [Task {task.task_id}] Initializing Redis connection...")
        print(f"[DEBUG] [Task {task.task_id}] Redis config: {task.redis_host}:{task.redis_port} DB:{task.redis_db}")
        task.redis_client = task._init_redis()
        if not task.redis_client:
            logger.error(f"[Task {task.task_id}] Cannot start: Redis connection failed")
            print(f"[ERROR] [Task {task.task_id}] Cannot start: Redis connection failed")
            print(f"[ERROR] [Task {task.task_id}] Make sure Redis is running and accessible at {task.redis_host}:{task.redis_port}")
            task.status = 'error'
            task.is_running = False
            return
        
        print(f"[DEBUG] [Task {task.task_id}] Redis connection established successfully")
        queue_name = f"ollama_queue:{task.task_id}"  # Task-specific queue
        print(f"[DEBUG] [Task {task.task_id}] Queue name: {queue_name}")
        print(f"[DEBUG] [Task {task.task_id}] Starting to poll queue for jobs...")
        
        while not task.stop_event.is_set():
            try:
                # Try to get a job from the queue (blocking with timeout)
                job_data_str = task.redis_client.brpop(queue_name, timeout=1)
                
                if job_data_str:
                    # job_data_str is a tuple: (queue_name, job_data)
                    job_data = json.loads(job_data_str[1])
                    job_id = job_data.get('job_id')
                    
                    logger.info(f"[Task {task.task_id}] Processing job {job_id}")
                    print(f"[DEBUG] [Task {task.task_id}] ========================================")
                    print(f"[DEBUG] [Task {task.task_id}] Processing job: {job_id}")
                    print(f"[DEBUG] [Task {task.task_id}] Endpoint: {job_data.get('endpoint', 'N/A')}")
                    print(f"[DEBUG] [Task {task.task_id}] Method: {job_data.get('method', 'N/A')}")
                    task.last_activity = datetime.now().isoformat()
                    
                    try:
                        # Update job status
                        task.redis_client.setex(
                            f"job:{job_id}",
                            3600,
                            json.dumps({**job_data, 'status': 'processing', 'worker': task.task_id})
                        )
                        
                        # Process the job - forward to Ollama using task's configuration
                        ollama_url = task.ollama_url
                        endpoint = job_data.get('endpoint', '/api/generate')
                        method = job_data.get('method', 'POST')
                        data = job_data.get('data', {})
                        headers = job_data.get('headers', {})
                        
                        # Make request to Ollama
                        url = urljoin(ollama_url, endpoint.lstrip('/'))
                        response = requests.request(
                            method=method,
                            url=url,
                            json=data,
                            headers=headers,
                            timeout=300  # 5 minute timeout
                        )
                        
                        # Store result
                        result = {
                            'status': 'completed' if response.status_code == 200 else 'failed',
                            'status_code': response.status_code,
                            'response': response.text[:1000] if response.text else '',  # Limit response size
                            'completed_at': datetime.now().isoformat()
                        }
                        
                        task.redis_client.setex(
                            f"job:{job_id}",
                            3600,
                            json.dumps({**job_data, **result})
                        )
                        
                        # Update task statistics
                        task.processed_jobs += 1
                        if response.status_code != 200:
                            task.failed_jobs += 1
                        
                        # Add to job history (keep latest 50)
                        job_record = {
                            'job_id': job_id,
                            'api_key': job_data.get('api_key', '')[:20] + '...' if job_data.get('api_key') else 'N/A',
                            'endpoint': job_data.get('endpoint', ''),
                            'method': job_data.get('method', ''),
                            'status': 'completed' if response.status_code == 200 else 'failed',
                            'status_code': response.status_code,
                            'created_at': job_data.get('created_at', ''),
                            'completed_at': datetime.now().isoformat(),
                            'tokens_used': data.get('num_tokens', 0) if isinstance(data, dict) else 0
                        }
                        
                        with self.lock:
                            task.job_history.append(job_record)
                            # Keep only latest 50
                            if len(task.job_history) > 50:
                                task.job_history = task.job_history[-50:]
                        
                        logger.info(f"[Task {task.task_id}] Job {job_id} completed")
                        
                    except Exception as e:
                        logger.error(f"[Task {task.task_id}] Error processing job {job_id}: {e}")
                        task.failed_jobs += 1
                        
                        # Update job status to failed
                        try:
                            if task.redis_client:
                                task.redis_client.setex(
                                    f"job:{job_id}",
                                    3600,
                                    json.dumps({**job_data, 'status': 'failed', 'error': str(e)})
                                )
                        except:
                            pass
                        
                        # Add to job history
                        job_record = {
                            'job_id': job_id,
                            'api_key': job_data.get('api_key', '')[:20] + '...' if job_data.get('api_key') else 'N/A',
                            'endpoint': job_data.get('endpoint', ''),
                            'method': job_data.get('method', ''),
                            'status': 'error',
                            'status_code': 0,
                            'created_at': job_data.get('created_at', ''),
                            'completed_at': datetime.now().isoformat(),
                            'error': str(e),
                            'tokens_used': 0
                        }
                        
                        with self.lock:
                            task.job_history.append(job_record)
                            # Keep only latest 50
                            if len(task.job_history) > 50:
                                task.job_history = task.job_history[-50:]
                
            except Exception as e:
                if not task.stop_event.is_set():
                    logger.error(f"[Task {task.task_id}] Error in worker loop: {e}")
                    time.sleep(1)
        
        task.is_running = False
        task.status = 'stopped'
        logger.info(f"[Task {task.task_id}] Worker stopped")
    
    def _create_fastapi_app(self, task: OllamaTask):
        """Create FastAPI app for the gateway."""
        if not FASTAPI_AVAILABLE:
            logger.error(f"[Task {task.task_id}] FastAPI not available. Cannot create gateway server.")
            print(f"[ERROR] FastAPI not available. Install with: pip install fastapi uvicorn")
            return None
        
        logger.info(f"[Task {task.task_id}] Creating FastAPI app for gateway on port {task.gateway_port}")
        print(f"[DEBUG] Creating FastAPI app for gateway '{task.name}' on port {task.gateway_port}")
        
        app = FastAPI(title=f"Ollama Gateway - {task.name}")
        
        @app.websocket("/ws/{path:path}")
        async def websocket_proxy(websocket: WebSocket, path: str):
            """WebSocket endpoint for real-time inference streaming."""
            await websocket.accept()
            logger.info(f"[Task {task.task_id}] WebSocket connection established for /{path}")
            print(f"[DEBUG] [Task {task.task_id}] WebSocket connection established for /{path}")
            
            try:
                # Get API key from query parameters or initial message
                api_key = None
                query_params = dict(websocket.query_params)
                api_key = query_params.get('api_key') or query_params.get('token')
                
                # If not in query, wait for initial message with auth
                request_data = {}
                if not api_key:
                    try:
                        initial_msg = await websocket.receive_text()
                        initial_data = json.loads(initial_msg)
                        api_key = initial_data.get('api_key') or initial_data.get('token')
                        # Extract request data from initial message
                        request_data = initial_data.get('data', {})
                    except Exception as e:
                        logger.warning(f"[Task {task.task_id}] Error parsing initial WebSocket message: {e}")
                        await websocket.close(code=1008, reason="API key required")
                        return
                
                if not api_key:
                    await websocket.close(code=1008, reason="API key required")
                    return
                
                # Validate API key
                key_info = self.validate_api_key(api_key)
                if not key_info:
                    await websocket.close(code=1008, reason="Invalid API key")
                    return
                
                logger.info(f"[Task {task.task_id}] WebSocket API key validated for: {key_info.get('name', 'Unknown')}")
                print(f"[DEBUG] [Task {task.task_id}] WebSocket API key validated")
                
                # Check rate limit (for direct mode, we can check here)
                if task.mode == 'direct':
                    redis_client = task.redis_client or task._init_redis()
                    can_proceed, error_msg = self.check_rate_limit(api_key, redis_client=redis_client)
                    if not can_proceed:
                        await websocket.close(code=1008, reason=error_msg or "Rate limit exceeded")
                        return
                
                # If request_data is empty, wait for it
                if not request_data:
                    try:
                        msg = await websocket.receive_text()
                        request_data = json.loads(msg)
                    except Exception as e:
                        logger.warning(f"[Task {task.task_id}] Error receiving request data: {e}")
                        request_data = {}
                
                # Determine endpoint
                endpoint = f"/{path}" if path else "/api/generate"
                
                # For direct mode, forward to Ollama immediately
                if task.mode == 'direct':
                    ollama_url = urljoin(task.ollama_url, endpoint.lstrip('/'))
                    logger.info(f"[Task {task.task_id}] WebSocket forwarding to {ollama_url}")
                    print(f"[DEBUG] [Task {task.task_id}] WebSocket forwarding to {ollama_url}")
                    
                    try:
                        # Make streaming request to Ollama
                        response = requests.post(
                            ollama_url,
                            json=request_data,
                            stream=True,
                            timeout=300
                        )
                        
                        # Stream response chunks through WebSocket
                        estimated_tokens = 0
                        for line in response.iter_lines():
                            if line:
                                try:
                                    # Send each line as WebSocket message
                                    await websocket.send_text(line.decode('utf-8'))
                                    
                                    # Try to parse and count tokens
                                    try:
                                        line_data = json.loads(line)
                                        if 'response' in line_data:
                                            estimated_tokens += len(line_data.get('response', '').split())
                                    except:
                                        pass
                                except Exception as e:
                                    logger.error(f"[Task {task.task_id}] Error sending WebSocket message: {e}")
                                    break
                        
                        # Update statistics
                        task.processed_jobs += 1
                        task.last_activity = datetime.now().isoformat()
                        tokens = estimated_tokens or request_data.get('num_tokens', 0) or request_data.get('num_predict', 0)
                        self.record_request(api_key, tokens, request_data.get('model', ''), success=True)
                        
                    except Exception as e:
                        logger.error(f"[Task {task.task_id}] Error in WebSocket forwarding: {e}")
                        print(f"[ERROR] [Task {task.task_id}] Error in WebSocket forwarding: {e}")
                        task.failed_jobs += 1
                        tokens = request_data.get('num_tokens', 0) or request_data.get('num_predict', 0)
                        self.record_request(api_key, tokens, request_data.get('model', ''), success=False, error=str(e))
                        await websocket.send_text(json.dumps({'error': str(e)}))
                else:
                    # Redis mode: queue and notify via WebSocket
                    job_id = self.queue_request(
                        task_id=task.task_id,
                        api_key=api_key,
                        endpoint=endpoint,
                        method='POST',
                        data=request_data,
                        headers={}
                    )
                    
                    # Send job ID
                    await websocket.send_text(json.dumps({
                        'job_id': job_id,
                        'status': 'queued',
                        'message': 'Request queued. Poll job status via HTTP API.'
                    }))
                
            except WebSocketDisconnect:
                logger.info(f"[Task {task.task_id}] WebSocket client disconnected")
                print(f"[DEBUG] [Task {task.task_id}] WebSocket client disconnected")
            except Exception as e:
                logger.error(f"[Task {task.task_id}] WebSocket error: {e}", exc_info=True)
                print(f"[ERROR] [Task {task.task_id}] WebSocket error: {e}")
                try:
                    await websocket.close(code=1011, reason=str(e))
                except:
                    pass
        
        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
        async def gateway_proxy(request: Request, path: str):
            """Proxy all requests to Ollama with API key validation."""
            logger.info(f"[Task {task.task_id}] Received {request.method} request to /{path}")
            print(f"[DEBUG] [Task {task.task_id}] Received {request.method} request to /{path}")
            
            # Get API key from header
            auth_header = request.headers.get("Authorization", "")
            api_key = auth_header.replace("Bearer ", "") if auth_header else ""
            if not api_key:
                api_key = request.headers.get("X-API-Key", "")
            
            logger.debug(f"[Task {task.task_id}] API key from headers: {'Present' if api_key else 'Missing'}")
            print(f"[DEBUG] [Task {task.task_id}] API key from headers: {'Present' if api_key else 'Missing'}")
            
            if not api_key:
                logger.warning(f"[Task {task.task_id}] Request rejected: No API key provided")
                print(f"[WARN] [Task {task.task_id}] Request rejected: No API key provided")
                raise HTTPException(status_code=401, detail="API key required")
            
            # Validate API key
            logger.debug(f"[Task {task.task_id}] Validating API key: {api_key[:20]}...")
            print(f"[DEBUG] [Task {task.task_id}] Validating API key: {api_key[:20]}...")
            key_info = self.validate_api_key(api_key)
            if not key_info:
                logger.warning(f"[Task {task.task_id}] Request rejected: Invalid API key")
                print(f"[WARN] [Task {task.task_id}] Request rejected: Invalid API key")
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            logger.info(f"[Task {task.task_id}] API key validated for: {key_info.get('name', 'Unknown')}")
            print(f"[DEBUG] [Task {task.task_id}] API key validated for: {key_info.get('name', 'Unknown')}")
            
            # Check rate limit (use task's Redis client if available)
            logger.debug(f"[Task {task.task_id}] Checking rate limit...")
            print(f"[DEBUG] [Task {task.task_id}] Checking rate limit...")
            redis_client = task.redis_client or task._init_redis()
            can_proceed, error_msg = self.check_rate_limit(api_key, redis_client=redis_client)
            if not can_proceed:
                logger.warning(f"[Task {task.task_id}] Request rejected: {error_msg}")
                print(f"[WARN] [Task {task.task_id}] Request rejected: {error_msg}")
                raise HTTPException(status_code=429, detail=error_msg or "Rate limit exceeded")
            
            # Get request body
            try:
                body = await request.body()
                data = json.loads(body) if body else {}
                logger.debug(f"[Task {task.task_id}] Request body parsed: {len(str(data))} chars")
                print(f"[DEBUG] [Task {task.task_id}] Request body parsed: {len(str(data))} chars")
            except Exception as e:
                logger.warning(f"[Task {task.task_id}] Error parsing request body: {e}")
                print(f"[WARN] [Task {task.task_id}] Error parsing request body: {e}")
                data = {}
            
            # Check token limit if tokens are in request
            tokens = data.get('num_tokens', 0) or data.get('num_predict', 0)
            if tokens > 0:
                logger.debug(f"[Task {task.task_id}] Checking token limit: {tokens} tokens")
                print(f"[DEBUG] [Task {task.task_id}] Checking token limit: {tokens} tokens")
                can_proceed, error_msg = self.check_token_limit(api_key, tokens)
                if not can_proceed:
                    logger.warning(f"[Task {task.task_id}] Request rejected: {error_msg}")
                    print(f"[WARN] [Task {task.task_id}] Request rejected: {error_msg}")
                    raise HTTPException(status_code=429, detail=error_msg or "Token limit exceeded")
            
            # Handle request based on mode
            if task.mode == 'direct':
                # Direct mode: forward immediately to Ollama
                logger.info(f"[Task {task.task_id}] Direct mode: forwarding request to Ollama")
                print(f"[DEBUG] [Task {task.task_id}] Direct mode: forwarding to {task.ollama_url}/{path}")
                
                try:
                    # Prepare headers (remove gateway-specific headers)
                    forward_headers = {k: v for k, v in request.headers.items() 
                                     if k.lower() not in ['host', 'authorization', 'x-api-key']}
                    
                    # Forward request to Ollama
                    ollama_url = urljoin(task.ollama_url, path.lstrip('/'))
                    print(f"[DEBUG] [Task {task.task_id}] Forwarding {request.method} to {ollama_url}")
                    
                    # Handle streaming responses
                    if path in ['/api/generate', '/api/chat'] and request.method == 'POST':
                        # For streaming endpoints, stream the response
                        def generate():
                            try:
                                response = requests.request(
                                    method=request.method,
                                    url=ollama_url,
                                    json=data,
                                    headers=forward_headers,
                                    stream=True,
                                    timeout=300
                                )
                                
                                # Update statistics
                                task.processed_jobs += 1
                                task.last_activity = datetime.now().isoformat()
                                
                                # Try to estimate tokens (if available in response)
                                estimated_tokens = 0
                                for line in response.iter_lines():
                                    if line:
                                        yield line + b'\n'
                                        # Try to parse JSON to count tokens if available
                                        try:
                                            line_data = json.loads(line)
                                            if 'response' in line_data:
                                                estimated_tokens += len(line_data.get('response', '').split())
                                        except:
                                            pass
                                
                                # Record request after streaming
                                self.record_request(api_key, estimated_tokens or tokens, data.get('model', ''), success=True)
                                
                            except Exception as e:
                                logger.error(f"[Task {task.task_id}] Error forwarding request: {e}")
                                print(f"[ERROR] [Task {task.task_id}] Error forwarding request: {e}")
                                task.failed_jobs += 1
                                self.record_request(api_key, tokens, data.get('model', ''), success=False, error=str(e))
                                raise
                        
                        return StreamingResponse(generate(), media_type="application/json")
                    else:
                        # For non-streaming endpoints, return full response
                        response = requests.request(
                            method=request.method,
                            url=ollama_url,
                            json=data if body else None,
                            headers=forward_headers,
                            timeout=300
                        )
                        
                        # Update statistics
                        task.processed_jobs += 1
                        task.last_activity = datetime.now().isoformat()
                        if response.status_code != 200:
                            task.failed_jobs += 1
                        
                        # Record request
                        self.record_request(api_key, tokens, data.get('model', ''), 
                                           success=response.status_code == 200,
                                           error=response.text[:200] if response.status_code != 200 else '')
                        
                        # Add to job history
                        job_record = {
                            'job_id': f"direct_{int(time.time() * 1000)}",
                            'api_key': api_key[:20] + '...',
                            'endpoint': f"/{path}",
                            'method': request.method,
                            'status': 'completed' if response.status_code == 200 else 'failed',
                            'status_code': response.status_code,
                            'created_at': datetime.now().isoformat(),
                            'completed_at': datetime.now().isoformat(),
                            'tokens_used': tokens
                        }
                        
                        with self.lock:
                            task.job_history.append(job_record)
                            if len(task.job_history) > 50:
                                task.job_history = task.job_history[-50:]
                        
                        return JSONResponse(
                            content=response.json() if response.headers.get('content-type', '').startswith('application/json') else {'response': response.text},
                            status_code=response.status_code
                        )
                        
                except Exception as e:
                    logger.error(f"[Task {task.task_id}] Error in direct forwarding: {e}")
                    print(f"[ERROR] [Task {task.task_id}] Error in direct forwarding: {e}")
                    task.failed_jobs += 1
                    self.record_request(api_key, tokens, data.get('model', ''), success=False, error=str(e))
                    raise HTTPException(status_code=500, detail=f"Error forwarding to Ollama: {str(e)}")
            else:
                # Redis mode: queue the request
                logger.info(f"[Task {task.task_id}] Redis mode: queueing request to endpoint: /{path}")
                print(f"[DEBUG] [Task {task.task_id}] Redis mode: queueing request to endpoint: /{path}")
                try:
                    job_id = self.queue_request(
                        task_id=task.task_id,
                        api_key=api_key,
                        endpoint=f"/{path}",
                        method=request.method,
                        data=data,
                        headers=dict(request.headers)
                    )
                    logger.info(f"[Task {task.task_id}] Request queued with job_id: {job_id}")
                    print(f"[DEBUG] [Task {task.task_id}] Request queued with job_id: {job_id}")
                except Exception as e:
                    logger.error(f"[Task {task.task_id}] Error queueing request: {e}")
                    print(f"[ERROR] [Task {task.task_id}] Error queueing request: {e}")
                    raise HTTPException(status_code=500, detail=f"Error queueing request: {str(e)}")
                
                # Record request
                self.record_request(api_key, tokens, data.get('model', ''), success=True)
                
                # Return job ID
                logger.info(f"[Task {task.task_id}] Returning response for job_id: {job_id}")
                print(f"[DEBUG] [Task {task.task_id}] Returning response for job_id: {job_id}")
                return JSONResponse({
                    "job_id": job_id,
                    "status": "queued",
                    "message": "Request queued successfully"
                })
        
        logger.info(f"[Task {task.task_id}] FastAPI app created successfully")
        print(f"[DEBUG] [Task {task.task_id}] FastAPI app created successfully")
        return app
    
    def _run_fastapi_server(self, task: OllamaTask):
        """Run FastAPI server in a separate thread."""
        try:
            logger.info(f"[Task {task.task_id}] Starting FastAPI server setup...")
            print(f"[DEBUG] [Task {task.task_id}] Starting FastAPI server setup...")
            print(f"[DEBUG] [Task {task.task_id}] Gateway port: {task.gateway_port}")
            print(f"[DEBUG] [Task {task.task_id}] Mode: {task.mode}")
            print(f"[DEBUG] [Task {task.task_id}] Ollama URL: {task.ollama_url}")
            if task.mode == 'redis':
                print(f"[DEBUG] [Task {task.task_id}] Redis: {task.redis_host}:{task.redis_port}")
            else:
                print(f"[DEBUG] [Task {task.task_id}] Direct mode: No Redis required")
            
            app = self._create_fastapi_app(task)
            if not app:
                logger.error(f"[Task {task.task_id}] Failed to create FastAPI app")
                print(f"[ERROR] [Task {task.task_id}] Failed to create FastAPI app")
                task.status = 'error'
                task.is_running = False
                return
            
            task.fastapi_app = app
            logger.info(f"[Task {task.task_id}] Creating uvicorn config...")
            print(f"[DEBUG] [Task {task.task_id}] Creating uvicorn config for port {task.gateway_port}")
            
            config = uvicorn.Config(
                app=app,
                host="0.0.0.0",
                port=task.gateway_port,
                log_level="info",
                access_log=True  # Enable access logs for debugging
            )
            server = uvicorn.Server(config)
            task.fastapi_server = server
            
            logger.info(f"[Task {task.task_id}] Starting FastAPI server on 0.0.0.0:{task.gateway_port}")
            print(f"[INFO] [Task {task.task_id}] ========================================")
            print(f"[INFO] [Task {task.task_id}] Starting Ollama Gateway Server")
            print(f"[INFO] [Task {task.task_id}] Name: {task.name}")
            print(f"[INFO] [Task {task.task_id}] Port: {task.gateway_port}")
            print(f"[INFO] [Task {task.task_id}] Ollama URL: {task.ollama_url}")
            print(f"[INFO] [Task {task.task_id}] ========================================")
            print(f"[INFO] [Task {task.task_id}] Server will be available at: http://0.0.0.0:{task.gateway_port}")
            print(f"[INFO] [Task {task.task_id}] Or locally at: http://localhost:{task.gateway_port}")
            print(f"[INFO] [Task {task.task_id}] Starting uvicorn server...")
            
            try:
                server.run()
            except OSError as e:
                if "Address already in use" in str(e) or "address already in use" in str(e).lower():
                    logger.error(f"[Task {task.task_id}] Port {task.gateway_port} is already in use!")
                    print(f"[ERROR] [Task {task.task_id}] Port {task.gateway_port} is already in use!")
                    print(f"[ERROR] [Task {task.task_id}] Check what's using the port: lsof -i :{task.gateway_port}")
                    raise
                else:
                    raise
        except Exception as e:
            logger.error(f"[Task {task.task_id}] Error running FastAPI server: {e}", exc_info=True)
            print(f"[ERROR] [Task {task.task_id}] Error running FastAPI server: {e}")
            import traceback
            print(f"[ERROR] [Task {task.task_id}] Traceback:")
            traceback.print_exc()
            task.status = 'error'
            task.is_running = False
    
    def start_task(self, task_id: str) -> bool:
        """Start a worker task and gateway server."""
        print(f"[DEBUG] ========================================")
        print(f"[DEBUG] Starting task: {task_id}")
        print(f"[DEBUG] ========================================")
        
        with self.lock:
            if task_id not in self.tasks:
                logger.warning(f"[Task {task_id}] Cannot start: Task not found")
                print(f"[ERROR] [Task {task_id}] Cannot start: Task not found")
                return False
            
            task = self.tasks[task_id]
            if task.is_running:
                logger.warning(f"[Task {task_id}] Cannot start: Task is already running")
                print(f"[WARN] [Task {task_id}] Cannot start: Task is already running")
                return False
            
            task.is_running = True
            task.status = 'running'
            task.stop_event.clear()
        
        logger.info(f"[Task {task_id}] Starting task '{task.name}' on port {task.gateway_port}")
        print(f"[INFO] [Task {task_id}] Starting task '{task.name}' on port {task.gateway_port}")
        print(f"[DEBUG] [Task {task_id}] Task configuration:")
        print(f"[DEBUG] [Task {task_id}]   - Name: {task.name}")
        print(f"[DEBUG] [Task {task_id}]   - Mode: {task.mode}")
        print(f"[DEBUG] [Task {task_id}]   - Gateway Port: {task.gateway_port}")
        print(f"[DEBUG] [Task {task_id}]   - Ollama URL: {task.ollama_url}")
        print(f"[DEBUG] [Task {task_id}]   - Redis Host: {task.redis_host}")
        print(f"[DEBUG] [Task {task_id}]   - Redis Port: {task.redis_port}")
        print(f"[DEBUG] [Task {task_id}]   - Redis DB: {task.redis_db}")
        print(f"[DEBUG] [Task {task_id}]   - FastAPI Available: {FASTAPI_AVAILABLE}")
        print(f"[DEBUG] [Task {task_id}]   - Redis Available: {REDIS_AVAILABLE}")
        
        # Start FastAPI gateway server in separate thread
        if FASTAPI_AVAILABLE:
            print(f"[DEBUG] [Task {task_id}] Starting FastAPI server thread...")
            def run_server():
                try:
                    print(f"[DEBUG] [Task {task_id}] FastAPI server thread started")
                    self._run_fastapi_server(task)
                except Exception as e:
                    logger.error(f"Error in FastAPI server thread for {task_id}: {e}", exc_info=True)
                    print(f"[ERROR] [Task {task_id}] Error in FastAPI server thread: {e}")
                    import traceback
                    traceback.print_exc()
                    task.status = 'error'
                    task.is_running = False
            
            server_thread = threading.Thread(target=run_server, daemon=True, name=f"FastAPI-{task_id}")
            server_thread.start()
            print(f"[DEBUG] [Task {task_id}] FastAPI server thread started, waiting 1 second...")
            time.sleep(1)  # Give server more time to start
            print(f"[DEBUG] [Task {task_id}] Checking if server started successfully...")
        else:
            print(f"[ERROR] [Task {task_id}] FastAPI not available! Install with: pip install fastapi uvicorn")
            logger.error(f"[Task {task_id}] FastAPI not available")
        
        # Start queue worker in separate thread (only for Redis mode)
        if task.mode == 'redis':
            print(f"[DEBUG] [Task {task_id}] Redis mode: Starting queue worker thread...")
            def run_worker():
                try:
                    print(f"[DEBUG] [Task {task_id}] Queue worker thread started")
                    self._process_queue_worker(task)
                except Exception as e:
                    logger.error(f"Error in task worker thread for {task_id}: {e}", exc_info=True)
                    print(f"[ERROR] [Task {task_id}] Error in queue worker thread: {e}")
                    import traceback
                    traceback.print_exc()
                    task.status = 'error'
                    task.is_running = False
            
            worker_thread = threading.Thread(target=run_worker, daemon=True, name=f"Worker-{task_id}")
            worker_thread.start()
            print(f"[DEBUG] [Task {task_id}] Queue worker thread started")
        else:
            print(f"[DEBUG] [Task {task_id}] Direct mode: No queue worker needed (requests forwarded directly)")
        
        print(f"[INFO] [Task {task_id}] Task started successfully!")
        print(f"[DEBUG] [Task {task_id}] Check if port {task.gateway_port} is listening with: lsof -i :{task.gateway_port}")
        
        return True
    
    def stop_task(self, task_id: str) -> bool:
        """Stop a running task and gateway server."""
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
    
    def get_task_job_history(self, task_id: str, limit: int = 50) -> List[Dict]:
        """Get job history for a task (latest N jobs)."""
        with self.lock:
            if task_id not in self.tasks:
                return []
            
            task = self.tasks[task_id]
            # Return latest jobs, up to limit
            return task.job_history[-limit:] if task.job_history else []
    
    def get_task_api_examples(self, task_id: str) -> Dict:
        """Get API usage examples for a task."""
        with self.lock:
            if task_id not in self.tasks:
                return {}
            
            task = self.tasks[task_id]
            
            # Get a sample API key for demonstration
            sample_api_key = "YOUR_API_KEY_HERE"
            if self.api_keys:
                # Use first active key as example
                for key, info in self.api_keys.items():
                    if info.get('is_active', True):
                        sample_api_key = key
                        break
            
            gateway_url = f"http://localhost:{task.gateway_port}"
            gateway_ws_url = f"ws://localhost:{task.gateway_port}"
            
            examples = {
                'task_id': task_id,
                'task_name': task.name,
                'gateway_url': gateway_url,
                'gateway_ws_url': gateway_ws_url,
                'ollama_url': task.ollama_url,
                'sample_api_key': sample_api_key[:30] + '...' if len(sample_api_key) > 30 else sample_api_key,
                'examples': {
                    'websocket': {
                        'description': 'Real-time inference streaming via WebSocket',
                        'javascript': f'''// Connect to WebSocket endpoint
const ws = new WebSocket("{gateway_ws_url}/ws/api/generate?api_key={sample_api_key}");

// Send request data after connection
ws.onopen = () => {{
    ws.send(JSON.stringify({{
        "model": "llama2",
        "prompt": "Why is the sky blue?",
        "stream": true
    }}));
}};

// Receive streaming responses
ws.onmessage = (event) => {{
    const data = JSON.parse(event.data);
    console.log(data.response || data);
}};

ws.onerror = (error) => {{
    console.error("WebSocket error:", error);
}};

ws.onclose = () => {{
    console.log("WebSocket closed");
}};''',
                        'python': f'''import asyncio
import websockets
import json

async def stream_inference():
    uri = "{gateway_ws_url}/ws/api/generate?api_key={sample_api_key}"
    async with websockets.connect(uri) as websocket:
        # Send request
        request = {{
            "model": "llama2",
            "prompt": "Why is the sky blue?",
            "stream": True
        }}
        await websocket.send(json.dumps(request))
        
        # Receive streaming responses
        async for message in websocket:
            data = json.loads(message)
            print(data.get("response", ""), end="", flush=True)
            if data.get("done", False):
                break

asyncio.run(stream_inference())''',
                        'json': {
                            "model": "llama2",
                            "prompt": "Why is the sky blue?",
                            "stream": True
                        }
                    },
                    'generate': {
                        'description': 'Generate text using a model',
                        'curl': f'''curl -X POST {gateway_url}/api/generate \\
  -H "Authorization: Bearer {sample_api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "llama2",
    "prompt": "Why is the sky blue?",
    "stream": false
  }}' ''',
                        'json': {
                            "model": "llama2",
                            "prompt": "Why is the sky blue?",
                            "stream": False
                        },
                        'python': f'''import requests

url = "{gateway_url}/api/generate"
headers = {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
}}
data = {{
    "model": "llama2",
    "prompt": "Why is the sky blue?",
    "stream": False
}}

response = requests.post(url, json=data, headers=headers)
print(response.json())'''
                    },
                    'chat': {
                        'description': 'Chat with a model',
                        'curl': f'''curl -X POST {gateway_url}/api/chat \\
  -H "Authorization: Bearer {sample_api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "llama2",
    "messages": [
      {{"role": "user", "content": "Hello!"}}
    ]
  }}' ''',
                        'json': {
                            "model": "llama2",
                            "messages": [
                                {"role": "user", "content": "Hello!"}
                            ]
                        },
                        'python': f'''import requests

url = "{gateway_url}/api/chat"
headers = {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
}}
data = {{
    "model": "llama2",
    "messages": [
        {{"role": "user", "content": "Hello!"}}
    ]
}}

response = requests.post(url, json=data, headers=headers)
print(response.json())'''
                    },
                    'embeddings': {
                        'description': 'Get embeddings for text',
                        'curl': f'''curl -X POST {gateway_url}/api/embeddings \\
  -H "Authorization: Bearer {sample_api_key}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "llama2",
    "prompt": "Hello world"
  }}' ''',
                        'json': {
                            "model": "llama2",
                            "prompt": "Hello world"
                        },
                        'python': f'''import requests

url = "{gateway_url}/api/embeddings"
headers = {{
    "Authorization": "Bearer {sample_api_key}",
    "Content-Type": "application/json"
}}
data = {{
    "model": "llama2",
    "prompt": "Hello world"
}}

response = requests.post(url, json=data, headers=headers)
print(response.json())'''
                    }
                },
                'authentication': {
                    'header_bearer': f'Authorization: Bearer {sample_api_key}',
                    'header_x_api_key': f'X-API-Key: {sample_api_key}',
                    'note': 'You can use either Authorization Bearer token or X-API-Key header'
                }
            }
            
            return examples
    
    def get_task_available_models(self, task_id: str) -> Dict:
        """Get list of available models from Ollama for a task."""
        with self.lock:
            if task_id not in self.tasks:
                return {'error': 'Task not found'}
            
            task = self.tasks[task_id]
            
            try:
                # Fetch models from Ollama API
                ollama_url = task.ollama_url.rstrip('/')
                models_url = f"{ollama_url}/api/tags"
                
                logger.info(f"[Task {task_id}] Fetching available models from {models_url}")
                print(f"[DEBUG] [Task {task_id}] Fetching available models from {models_url}")
                
                response = requests.get(models_url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    models = data.get('models', [])
                    
                    # Format models list
                    formatted_models = []
                    for model in models:
                        model_info = {
                            'name': model.get('name', ''),
                            'modified_at': model.get('modified_at', ''),
                            'size': model.get('size', 0),
                            'digest': model.get('digest', ''),
                            'details': model.get('details', {})
                        }
                        formatted_models.append(model_info)
                    
                    logger.info(f"[Task {task_id}] Found {len(formatted_models)} available models")
                    print(f"[DEBUG] [Task {task_id}] Found {len(formatted_models)} available models")
                    
                    return {
                        'task_id': task_id,
                        'task_name': task.name,
                        'ollama_url': task.ollama_url,
                        'models': formatted_models,
                        'count': len(formatted_models),
                        'success': True
                    }
                else:
                    error_msg = f"Failed to fetch models: HTTP {response.status_code}"
                    logger.error(f"[Task {task_id}] {error_msg}")
                    print(f"[ERROR] [Task {task_id}] {error_msg}")
                    return {
                        'task_id': task_id,
                        'error': error_msg,
                        'success': False
                    }
                    
            except requests.exceptions.ConnectionError as e:
                error_msg = f"Cannot connect to Ollama at {task.ollama_url}"
                logger.error(f"[Task {task_id}] {error_msg}: {e}")
                print(f"[ERROR] [Task {task_id}] {error_msg}: {e}")
                return {
                    'task_id': task_id,
                    'error': error_msg,
                    'success': False
                }
            except Exception as e:
                error_msg = f"Error fetching models: {str(e)}"
                logger.error(f"[Task {task_id}] {error_msg}", exc_info=True)
                print(f"[ERROR] [Task {task_id}] {error_msg}")
                import traceback
                traceback.print_exc()
                return {
                    'task_id': task_id,
                    'error': error_msg,
                    'success': False
                }

