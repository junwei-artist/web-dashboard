#!/usr/bin/env python3
"""
Rsync Manager for handling rsync operations.
Supports two modes:
1. Upload new files only (--update flag)
2. Upload files destination doesn't have (--ignore-existing flag)
"""

import subprocess
import threading
import time
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Callable
import logging

logger = logging.getLogger(__name__)
# Set logger level to DEBUG to show all debug messages
logger.setLevel(logging.DEBUG)


class RsyncJob:
    """Represents a single rsync job configuration."""
    
    def __init__(self, job_id: str, config: Dict):
        self.job_id = job_id
        self.name = config.get('name', f'Job {job_id}')
        self.sync_type = config.get('sync_type', 'new_files_only')  # 'new_files_only' or 'missing_files'
        self.destination_ip = config.get('destination_ip', '')
        self.destination_folder = config.get('destination_folder', '')
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.source_folder = config.get('source_folder', '')
        # Ensure update_interval is an integer (form data comes as string)
        update_interval = config.get('update_interval', 60)
        self.update_interval = int(update_interval) if isinstance(update_interval, (int, str)) else 60
        self.is_running = False
        self.is_persistent = False
        self.process = None
        self.last_run = None
        self.status = 'stopped'  # stopped, running, error
        self.output_log = []
        self.error_log = []
        self.thread = None
        self.stop_event = threading.Event()
        
    def to_dict(self):
        """Convert job to dictionary."""
        return {
            'job_id': self.job_id,
            'name': self.name,
            'sync_type': self.sync_type,
            'destination_ip': self.destination_ip,
            'destination_folder': self.destination_folder,
            'username': self.username,
            'password': '***' if self.password else '',
            'source_folder': self.source_folder,
            'update_interval': self.update_interval,
            'is_running': self.is_running,
            'is_persistent': self.is_persistent,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'status': self.status
        }


class RsyncManager:
    """Manages rsync jobs and operations."""
    
    def __init__(self, config_file: str = 'rsync_config.json'):
        self.config_file = config_file
        self.jobs: Dict[str, RsyncJob] = {}
        self.lock = threading.Lock()
        self.output_callbacks: Dict[str, Callable] = {}  # job_id -> callback
        self.load_config()
        
    def load_config(self):
        """Load rsync configurations from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    for job_id, config in data.get('jobs', {}).items():
                        job = RsyncJob(job_id, config)
                        self.jobs[job_id] = job
                logger.info(f"Loaded {len(self.jobs)} rsync jobs from config")
            except Exception as e:
                logger.error(f"Error loading rsync config: {e}")
    
    def save_config(self):
        """Save rsync configurations to file."""
        try:
            data = {
                'jobs': {}
            }
            with self.lock:
                for job_id, job in self.jobs.items():
                    # Don't save password in plain text, but keep it in memory
                    job_config = job.to_dict()
                    # Restore password from job object
                    job_config['password'] = job.password
                    data['jobs'][job_id] = job_config
            
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Saved rsync config")
        except Exception as e:
            logger.error(f"Error saving rsync config: {e}")
    
    def add_job(self, config: Dict) -> str:
        """Add a new rsync job."""
        job_id = config.get('job_id') or f"job_{int(time.time())}"
        
        with self.lock:
            job = RsyncJob(job_id, config)
            self.jobs[job_id] = job
        
        self.save_config()
        return job_id
    
    def update_job(self, job_id: str, config: Dict) -> bool:
        """Update an existing rsync job."""
        with self.lock:
            if job_id not in self.jobs:
                logger.warning(f"[Rsync Job {job_id}] Cannot update: Job not found")
                return False
            
            job = self.jobs[job_id]
            logger.info(f"[Rsync Job {job_id}] Updating job: {job.name}")
            # Update fields
            for key, value in config.items():
                if key != 'job_id' and hasattr(job, key):
                    # Don't update password if it's not provided (empty string or None)
                    if key == 'password' and (not value or value == ''):
                        logger.debug(f"[Rsync Job {job_id}] Skipping password update (not provided)")
                        continue
                    # Ensure update_interval is an integer
                    if key == 'update_interval':
                        value = int(value) if isinstance(value, (int, str)) else 60
                    old_value = getattr(job, key, None)
                    setattr(job, key, value)
                    if old_value != value:
                        logger.debug(f"[Rsync Job {job_id}] Updated {key}: {old_value} -> {value}")
        
        self.save_config()
        logger.info(f"[Rsync Job {job_id}] Job updated successfully")
        return True
    
    def delete_job(self, job_id: str) -> bool:
        """Delete an rsync job."""
        with self.lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            if job.is_running:
                self.stop_job(job_id)
            
            del self.jobs[job_id]
        
        self.save_config()
        return True
    
    def get_job(self, job_id: str) -> Optional[RsyncJob]:
        """Get a job by ID."""
        with self.lock:
            return self.jobs.get(job_id)
    
    def get_all_jobs(self) -> List[Dict]:
        """Get all jobs as dictionaries."""
        with self.lock:
            return [job.to_dict() for job in self.jobs.values()]
    
    def get_job_command(self, job_id: str) -> Optional[str]:
        """Get the rsync command string for a job."""
        with self.lock:
            if job_id not in self.jobs:
                return None
            
            job = self.jobs[job_id]
            
            # Determine rsync options based on sync type
            if job.sync_type == 'new_files_only':
                # --update: skip files that are newer on the receiver
                rsync_options = '-avz --update --progress'
            else:  # missing_files
                # --ignore-existing: skip files that exist on receiver (matches user's requirement)
                rsync_options = '-avz --ignore-existing --progress'
            
            # Build destination
            if job.username:
                destination = f"{job.username}@{job.destination_ip}:{job.destination_folder}"
            else:
                destination = f"{job.destination_ip}:{job.destination_folder}"
            
            # Build command string (matching user's format)
            if job.password:
                # Use sshpass to provide password
                cmd = f"sshpass -p '***' rsync {rsync_options} \\\n  {job.source_folder} \\\n  {destination}"
            else:
                # Use SSH key authentication (matches user's format: rsync -avz --ignore-existing \ source \ destination)
                cmd = f"rsync {rsync_options} \\\n  {job.source_folder} \\\n  {destination}"
            
            return cmd
    
    def set_output_callback(self, job_id: str, callback: Callable):
        """Set callback for real-time output."""
        self.output_callbacks[job_id] = callback
    
    def _run_rsync(self, job: RsyncJob, one_time: bool = False):
        """Run rsync command for a job."""
        try:
            logger.debug(f"[Rsync Job {job.job_id}] Starting rsync execution (one_time={one_time}, persistent={job.is_persistent})")
            logger.debug(f"[Rsync Job {job.job_id}] Job: {job.name}")
            logger.debug(f"[Rsync Job {job.job_id}] Source: {job.source_folder}")
            logger.debug(f"[Rsync Job {job.job_id}] Destination: {job.username}@{job.destination_ip}:{job.destination_folder}")
            logger.debug(f"[Rsync Job {job.job_id}] Sync type: {job.sync_type}")
            
            # Build rsync command
            # Format: rsync [options] source destination
            # For SSH: rsync [options] source user@host:destination
            
            # Determine rsync options based on sync type
            if job.sync_type == 'new_files_only':
                # --update: skip files that are newer on the receiver
                rsync_options = ['-avz', '--update', '--progress']
                logger.debug(f"[Rsync Job {job.job_id}] Using mode: Upload New Files Only (--update)")
            else:  # missing_files
                # --ignore-existing: skip files that exist on receiver
                rsync_options = ['-avz', '--ignore-existing', '--progress']
                logger.debug(f"[Rsync Job {job.job_id}] Using mode: Upload Missing Files (--ignore-existing)")
            
            # Build destination
            if job.username:
                destination = f"{job.username}@{job.destination_ip}:{job.destination_folder}"
            else:
                destination = f"{job.destination_ip}:{job.destination_folder}"
            
            # Use SSH with password via sshpass if password is provided
            env = os.environ.copy()
            if job.password:
                # Check if sshpass is available
                try:
                    subprocess.run(['sshpass', '-V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                    # Use sshpass to provide password
                    cmd = ['sshpass', '-p', job.password, 'rsync'] + rsync_options + [job.source_folder, destination]
                    logger.debug(f"[Rsync Job {job.job_id}] Using sshpass for password authentication")
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # sshpass not available, try using SSH_ASKPASS or expect
                    # For now, log error and suggest using SSH keys
                    logger.warning(f"[Rsync Job {job.job_id}] sshpass not found. Please install sshpass or use SSH key authentication.")
                    job.status = 'error'
                    job.error_log.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'error',
                        'message': 'sshpass not found. Please install sshpass (apt-get install sshpass / brew install hudochenkov/sshpass/sshpass) or use SSH key authentication.'
                    })
                    return
            else:
                # Use SSH key authentication
                cmd = ['rsync'] + rsync_options + [job.source_folder, destination]
                logger.debug(f"[Rsync Job {job.job_id}] Using SSH key authentication")
            
            # Log the command (without password)
            cmd_str = ' '.join(cmd)
            if job.password:
                # Mask password in log
                cmd_str = cmd_str.replace(job.password, '***')
            logger.debug(f"[Rsync Job {job.job_id}] Executing command: {cmd_str}")
            
            job.status = 'running'
            job.last_run = datetime.now()
            logger.info(f"[Rsync Job {job.job_id}] Job started at {job.last_run.isoformat()}")
            
            # Run rsync
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=env
            )
            job.process = process
            
            # Initialize logs
            job.output_log = []
            job.error_log = []
            
            # Read output in a separate thread to allow stopping
            def read_output():
                while True:
                    # Check if job should be stopped
                    if job.stop_event.is_set():
                        try:
                            process.terminate()
                            process.wait(timeout=5)
                        except:
                            try:
                                process.kill()
                            except:
                                pass
                        return
                    
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        line = output.strip()
                        if line:
                            log_entry = {
                                'timestamp': datetime.now().isoformat(),
                                'type': 'output',
                                'message': line
                            }
                            job.output_log.append(log_entry)
                            
                            # Log to console as debug
                            logger.debug(f"[Rsync Job {job.job_id}] OUTPUT: {line}")
                            
                            # Call callback if set
                            if job.job_id in self.output_callbacks:
                                try:
                                    self.output_callbacks[job.job_id](log_entry)
                                except Exception as e:
                                    logger.error(f"[Rsync Job {job.job_id}] Error in output callback: {e}")
            
            # Start reading output in separate thread
            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()
            
            # Wait for process to complete
            logger.debug(f"[Rsync Job {job.job_id}] Waiting for rsync process to complete...")
            return_code = process.wait()
            
            job.process = None
            
            logger.debug(f"[Rsync Job {job.job_id}] Process completed with return code: {return_code}")
            
            if return_code == 0:
                job.status = 'completed'
                logger.info(f"[Rsync Job {job.job_id}] Job completed successfully")
            else:
                job.status = 'error'
                logger.error(f"[Rsync Job {job.job_id}] Job failed with return code: {return_code}")
            
            # If persistent and not one-time, schedule next run
            if job.is_persistent and not one_time and not job.stop_event.is_set():
                # Mark as waiting for next run
                job.status = 'waiting'
                logger.info(f"[Rsync Job {job.job_id}] Job completed. Scheduling next run in {job.update_interval} seconds (persistent mode).")
                
                # Schedule next run after the interval
                def schedule_next_run():
                    # Check again if still persistent and not stopped
                    with self.lock:
                        if job.is_persistent and not job.stop_event.is_set() and job.is_running:
                            job.status = 'running'
                            logger.info(f"[Rsync Job {job.job_id}] Starting next run (persistent mode, interval: {job.update_interval}s).")
                            # Run in a new thread to avoid blocking
                            threading.Thread(target=self._run_rsync, args=[job, False], daemon=True).start()
                        else:
                            # Job was stopped, mark as stopped
                            job.is_running = False
                            if job.status != 'error':
                                job.status = 'stopped'
                            logger.info(f"[Rsync Job {job.job_id}] Persistent job stopped (no longer persistent or stop requested)")
                
                # Ensure update_interval is an integer for Timer
                interval = int(job.update_interval) if isinstance(job.update_interval, (int, str)) else 60
                threading.Timer(interval, schedule_next_run).start()
            else:
                # Not persistent or stopped, mark as stopped
                with self.lock:
                    job.is_running = False
                    if job.status != 'error':
                        job.status = 'stopped'
                logger.info(f"[Rsync Job {job.job_id}] Job finished (one-time execution)")
            
        except Exception as e:
            logger.error(f"Error running rsync for job {job.job_id}: {e}")
            job.status = 'error'
            job.error_log.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'error',
                'message': str(e)
            })
            if job.job_id in self.output_callbacks:
                try:
                    self.output_callbacks[job.job_id]({
                        'type': 'error',
                        'message': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                except:
                    pass
    
    def start_job(self, job_id: str, persistent: bool = False) -> bool:
        """Start an rsync job."""
        with self.lock:
            if job_id not in self.jobs:
                logger.warning(f"[Rsync Job {job_id}] Cannot start: Job not found")
                return False
            
            job = self.jobs[job_id]
            if job.is_running:
                logger.warning(f"[Rsync Job {job_id}] Cannot start: Job is already running")
                return False
            
            job.is_running = True
            job.is_persistent = persistent
            job.stop_event.clear()
        
        logger.info(f"[Rsync Job {job_id}] Starting job '{job.name}' (persistent={persistent}, interval={job.update_interval}s)")
        
        # Run in separate thread
        def run():
            self._run_rsync(job, one_time=not persistent)
            # Only set is_running to False if not persistent or if explicitly stopped
            with self.lock:
                if not job.is_persistent or job.stop_event.is_set():
                    job.is_running = False
                    logger.debug(f"[Rsync Job {job_id}] Job thread finished, is_running set to False")
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        job.thread = thread
        
        return True
    
    def stop_job(self, job_id: str) -> bool:
        """Stop a running rsync job."""
        with self.lock:
            if job_id not in self.jobs:
                logger.warning(f"[Rsync Job {job_id}] Cannot stop: Job not found")
                return False
            
            job = self.jobs[job_id]
            if not job.is_running:
                logger.warning(f"[Rsync Job {job_id}] Cannot stop: Job is not running")
                return False
            
            logger.info(f"[Rsync Job {job_id}] Stopping job '{job.name}'")
            job.is_persistent = False
            job.stop_event.set()
            
            if job.process:
                logger.debug(f"[Rsync Job {job_id}] Terminating rsync process...")
                try:
                    job.process.terminate()
                    job.process.wait(timeout=5)
                    logger.debug(f"[Rsync Job {job_id}] Process terminated successfully")
                except:
                    try:
                        logger.debug(f"[Rsync Job {job_id}] Process termination timed out, killing process...")
                        job.process.kill()
                    except:
                        pass
            
            job.is_running = False
            job.status = 'stopped'
        
        logger.info(f"[Rsync Job {job_id}] Job stopped successfully")
        return True
    
    def run_job_once(self, job_id: str) -> bool:
        """Run a job once (one-time execution)."""
        return self.start_job(job_id, persistent=False)
    
    def get_job_logs(self, job_id: str, limit: int = 100) -> Dict:
        """Get logs for a job."""
        with self.lock:
            if job_id not in self.jobs:
                return {'output': [], 'error': []}
            
            job = self.jobs[job_id]
            return {
                'output': job.output_log[-limit:],
                'error': job.error_log[-limit:]
            }

