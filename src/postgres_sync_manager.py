#!/usr/bin/env python3
"""
PostgreSQL Database Sync Manager.
Supports two sync modes:
1. Complete model - bidirectional sync based on row IDs
2. One-way sync - from source to target only
"""

import psycopg2
import psycopg2.extras
from psycopg2.extensions import quote_ident
import threading
import time
import os
import json
import csv
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class PostgresSyncJob:
    """Represents a single PostgreSQL sync job configuration."""
    
    def __init__(self, job_id: str, config: Dict):
        self.job_id = job_id
        self.name = config.get('name', f'Job {job_id}')
        self.sync_type = config.get('sync_type', 'complete_model')  # 'complete_model' or 'one_way'
        self.source_host = config.get('source_host', '')
        # Ensure ports are integers (JSON might store as string)
        source_port = config.get('source_port', 5432)
        self.source_port = int(source_port) if source_port else 5432
        self.source_database = config.get('source_database', '')
        self.source_user = config.get('source_user', '')
        self.source_password = config.get('source_password', '')
        self.target_host = config.get('target_host', '')
        target_port = config.get('target_port', 5432)
        self.target_port = int(target_port) if target_port else 5432
        self.target_database = config.get('target_database', '')
        self.target_user = config.get('target_user', '')
        self.target_password = config.get('target_password', '')
        # Ensure check_interval is an integer (JSON might store as string)
        check_interval = config.get('check_interval', 60)
        self.check_interval = int(check_interval) if check_interval else 60
        self.is_running = False
        self.is_persistent = False
        self.status = 'stopped'  # stopped, running, error
        self.last_run = None
        self.last_sync_stats = {}
        self.monitor_rows = []  # Last 20 rows for monitoring
        self.thread = None
        self.stop_event = threading.Event()
        self.failed_rows_log_dir = 'postgres_sync_logs'
        self.current_log_file = None
        self.current_log_row_count = 0
        
    def to_dict(self):
        """Convert job to dictionary."""
        return {
            'job_id': self.job_id,
            'name': self.name,
            'sync_type': self.sync_type,
            'source_host': self.source_host,
            'source_port': self.source_port,
            'source_database': self.source_database,
            'source_user': self.source_user,
            'source_password': '***' if self.source_password else '',
            'target_host': self.target_host,
            'target_port': self.target_port,
            'target_database': self.target_database,
            'target_user': self.target_user,
            'target_password': '***' if self.target_password else '',
            'check_interval': self.check_interval,
            'is_running': self.is_running,
            'is_persistent': self.is_persistent,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'status': self.status,
            'last_sync_stats': self.last_sync_stats,
            'monitor_rows': self.monitor_rows[-20:]  # Last 20 rows
        }


class PostgresSyncManager:
    """Manages PostgreSQL database sync jobs."""
    
    def __init__(self, config_file: str = 'postgres_sync_config.json'):
        self.config_file = config_file
        self.jobs: Dict[str, PostgresSyncJob] = {}
        self.lock = threading.Lock()
        self.output_callbacks: Dict[str, Callable] = {}  # job_id -> callback
        self.load_config()
        
        # Ensure log directory exists
        for job_id, job in self.jobs.items():
            log_dir = os.path.join(job.failed_rows_log_dir, job_id)
            os.makedirs(log_dir, exist_ok=True)
    
    def load_config(self):
        """Load PostgreSQL sync configurations from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    for job_id, config in data.get('jobs', {}).items():
                        job = PostgresSyncJob(job_id, config)
                        self.jobs[job_id] = job
                        # Ensure log directory exists
                        log_dir = os.path.join(job.failed_rows_log_dir, job_id)
                        os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Loaded {len(self.jobs)} PostgreSQL sync jobs from config")
            except Exception as e:
                logger.error(f"Error loading PostgreSQL sync config: {e}")
    
    def save_config(self):
        """Save PostgreSQL sync configurations to file."""
        try:
            data = {
                'jobs': {}
            }
            with self.lock:
                for job_id, job in self.jobs.items():
                    job_config = job.to_dict()
                    # Restore passwords from job object
                    job_config['source_password'] = job.source_password
                    job_config['target_password'] = job.target_password
                    data['jobs'][job_id] = job_config
            
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Saved PostgreSQL sync config")
        except Exception as e:
            logger.error(f"Error saving PostgreSQL sync config: {e}")
    
    def add_job(self, config: Dict) -> str:
        """Add a new PostgreSQL sync job."""
        job_id = config.get('job_id') or f"postgres_sync_{int(time.time())}"
        
        with self.lock:
            job = PostgresSyncJob(job_id, config)
            self.jobs[job_id] = job
            # Ensure log directory exists
            log_dir = os.path.join(job.failed_rows_log_dir, job_id)
            os.makedirs(log_dir, exist_ok=True)
        
        self.save_config()
        return job_id
    
    def update_job(self, job_id: str, config: Dict) -> bool:
        """Update an existing PostgreSQL sync job."""
        with self.lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            
            # Update fields
            for key, value in config.items():
                if key != 'job_id' and hasattr(job, key):
                    # Handle password fields specially - only update if provided
                    if key == 'source_password':
                        if value and value.strip():  # Only update if non-empty
                            setattr(job, key, value)
                        # Otherwise keep existing password (don't update)
                    elif key == 'target_password':
                        if value and value.strip():  # Only update if non-empty
                            setattr(job, key, value)
                        # Otherwise keep existing password (don't update)
                    elif key == 'check_interval':
                        # Ensure check_interval is an integer
                        setattr(job, key, int(value) if value else 60)
                    elif key in ('source_port', 'target_port'):
                        # Ensure ports are integers
                        setattr(job, key, int(value) if value else 5432)
                    else:
                        setattr(job, key, value)
        
        self.save_config()
        return True
    
    def delete_job(self, job_id: str) -> bool:
        """Delete a PostgreSQL sync job."""
        with self.lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            if job.is_running:
                self.stop_job(job_id)
            
            del self.jobs[job_id]
        
        self.save_config()
        return True
    
    def get_job(self, job_id: str) -> Optional[PostgresSyncJob]:
        """Get a job by ID."""
        with self.lock:
            return self.jobs.get(job_id)
    
    def get_all_jobs(self) -> List[Dict]:
        """Get all jobs as dictionaries."""
        with self.lock:
            return [job.to_dict() for job in self.jobs.values()]
    
    def set_output_callback(self, job_id: str, callback: Callable):
        """Set callback for real-time output."""
        self.output_callbacks[job_id] = callback
    
    def _get_connection(self, host: str, port: int, database: str, user: str, password: str):
        """Get PostgreSQL connection."""
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password,
                connect_timeout=10
            )
            return conn
        except Exception as e:
            logger.error(f"Error connecting to PostgreSQL: {e}")
            raise
    
    def _get_table_primary_key(self, conn, table_name: str) -> Optional[str]:
        """Get the primary key column name for a table."""
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT a.attname
                    FROM pg_index i
                    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                    WHERE i.indrelid = %s::regclass
                    AND i.indisprimary
                    LIMIT 1
                """, (table_name,))
                result = cur.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting primary key for table {table_name}: {e}")
            return None
    
    def _get_all_tables(self, conn) -> List[str]:
        """Get all table names from a database."""
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT tablename
                    FROM pg_tables
                    WHERE schemaname = 'public'
                    ORDER BY tablename
                """)
                return [row[0] for row in cur.fetchall()]
        except Exception as e:
            logger.error(f"Error getting tables: {e}")
            return []
    
    def _get_table_columns(self, conn, table_name: str) -> List[str]:
        """Get column names for a table."""
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                    AND table_name = %s
                    ORDER BY ordinal_position
                """, (table_name,))
                return [row[0] for row in cur.fetchall()]
        except Exception as e:
            logger.error(f"Error getting columns for table {table_name}: {e}")
            return []
    
    def _get_row_ids(self, conn, table_name: str, id_column: str) -> Set:
        """Get all row IDs from a table."""
        try:
            with conn.cursor() as cur:
                # Properly quote identifiers to prevent SQL injection
                quoted_table = quote_ident(table_name, conn)
                quoted_column = quote_ident(id_column, conn)
                cur.execute(f"SELECT {quoted_column} FROM {quoted_table}")
                return set(row[0] for row in cur.fetchall())
        except Exception as e:
            logger.error(f"Error getting row IDs from {table_name}: {e}")
            return set()
    
    def _get_row_data(self, conn, table_name: str, id_column: str, row_id) -> Optional[Dict]:
        """Get a single row's data by ID."""
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Properly quote identifiers to prevent SQL injection
                quoted_table = quote_ident(table_name, conn)
                quoted_column = quote_ident(id_column, conn)
                cur.execute(f"SELECT * FROM {quoted_table} WHERE {quoted_column} = %s", (row_id,))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error getting row data from {table_name} for ID {row_id}: {e}")
            return None
    
    def _insert_row(self, conn, table_name: str, columns: List[str], row_data: Dict) -> bool:
        """Insert a row into a table."""
        try:
            with conn.cursor() as cur:
                # Properly quote identifiers to prevent SQL injection
                quoted_table = quote_ident(table_name, conn)
                quoted_columns = [quote_ident(col, conn) for col in columns]
                placeholders = ', '.join(['%s'] * len(columns))
                column_names = ', '.join(quoted_columns)
                values = [row_data.get(col) for col in columns]
                cur.execute(f"INSERT INTO {quoted_table} ({column_names}) VALUES ({placeholders})", values)
                conn.commit()
                return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error inserting row into {table_name}: {e}")
            return False
    
    def _log_failed_row(self, job: PostgresSyncJob, table_name: str, row_id: str, error: str, row_data: Dict = None):
        """Log a failed row to CSV file."""
        try:
            # Check if we need a new log file
            if job.current_log_row_count >= 1000 or job.current_log_file is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                log_dir = os.path.join(job.failed_rows_log_dir, job.job_id)
                os.makedirs(log_dir, exist_ok=True)
                job.current_log_file = os.path.join(log_dir, f'failed_rows_{timestamp}.csv')
                job.current_log_row_count = 0
                
                # Write header
                with open(job.current_log_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['timestamp', 'table_name', 'row_id', 'error', 'row_data'])
            
            # Write row
            with open(job.current_log_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                row_data_str = json.dumps(row_data) if row_data else ''
                writer.writerow([
                    datetime.now().isoformat(),
                    table_name,
                    str(row_id),
                    str(error),
                    row_data_str
                ])
            job.current_log_row_count += 1
        except Exception as e:
            logger.error(f"Error logging failed row: {e}")
    
    def _add_log(self, job: PostgresSyncJob, level: str, message: str):
        """Add a log message and send to callback."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'log',
            'level': level,  # info, success, error, warning, skipped
            'message': message
        }
        
        # Call callback if set
        if job.job_id in self.output_callbacks:
            try:
                self.output_callbacks[job.job_id](log_entry)
            except Exception as e:
                logger.error(f"Error in output callback: {e}")
    
    def _add_monitor_row(self, job: PostgresSyncJob, status: str, table_name: str, row_id: str, message: str):
        """Add a row to the monitor display (keep last 20)."""
        monitor_row = {
            'timestamp': datetime.now().isoformat(),
            'type': 'status',
            'status': status,  # success, error, skipped
            'table_name': table_name,
            'row_id': str(row_id),
            'message': message
        }
        job.monitor_rows.append(monitor_row)
        # Keep only last 20
        if len(job.monitor_rows) > 20:
            job.monitor_rows = job.monitor_rows[-20:]
        
        # Call callback if set
        if job.job_id in self.output_callbacks:
            try:
                self.output_callbacks[job.job_id](monitor_row)
            except Exception as e:
                logger.error(f"Error in output callback: {e}")
    
    def _sync_complete_model(self, job: PostgresSyncJob):
        """Sync using complete model - bidirectional sync based on row IDs."""
        try:
            self._add_log(job, 'info', f"Starting complete model sync for job {job.name}")
            
            # Connect to both databases
            self._add_log(job, 'info', f"Connecting to source database: {job.source_host}:{job.source_port}/{job.source_database}")
            source_conn = self._get_connection(
                job.source_host, job.source_port, job.source_database,
                job.source_user, job.source_password
            )
            self._add_log(job, 'success', "Connected to source database")
            
            self._add_log(job, 'info', f"Connecting to target database: {job.target_host}:{job.target_port}/{job.target_database}")
            target_conn = self._get_connection(
                job.target_host, job.target_port, job.target_database,
                job.target_user, job.target_password
            )
            self._add_log(job, 'success', "Connected to target database")
            
            # Get all tables
            self._add_log(job, 'info', "Retrieving table list from databases...")
            source_tables = self._get_all_tables(source_conn)
            target_tables = self._get_all_tables(target_conn)
            common_tables = set(source_tables) & set(target_tables)
            self._add_log(job, 'info', f"Found {len(common_tables)} common tables to sync")
            
            stats = {
                'tables_processed': 0,
                'rows_synced_source_to_target': 0,
                'rows_synced_target_to_source': 0,
                'rows_failed': 0,
                'rows_skipped': 0
            }
            
            for table_name in common_tables:
                # Check if stop was requested
                if job.stop_event.is_set():
                    self._add_log(job, 'warning', 'Stop requested, exiting sync early')
                    break
                
                try:
                    self._add_log(job, 'info', f"Processing table: {table_name}")
                    # Get primary key
                    id_column = self._get_table_primary_key(source_conn, table_name)
                    if not id_column:
                        # Try target
                        id_column = self._get_table_primary_key(target_conn, table_name)
                    if not id_column:
                        self._add_log(job, 'warning', f"Table {table_name} has no primary key, skipping")
                        self._add_monitor_row(job, 'skipped', table_name, 'N/A', 'No primary key found')
                        continue
                    
                    self._add_log(job, 'info', f"Using primary key column: {id_column} for table {table_name}")
                    
                    # Get columns
                    source_columns = self._get_table_columns(source_conn, table_name)
                    target_columns = self._get_table_columns(target_conn, table_name)
                    common_columns = [col for col in source_columns if col in target_columns]
                    if id_column not in common_columns:
                        common_columns.insert(0, id_column)
                    
                    # Get row IDs from both databases
                    self._add_log(job, 'info', f"Getting row IDs from {table_name}...")
                    source_ids = self._get_row_ids(source_conn, table_name, id_column)
                    target_ids = self._get_row_ids(target_conn, table_name, id_column)
                    self._add_log(job, 'info', f"Source has {len(source_ids)} rows, target has {len(target_ids)} rows")
                    
                    # Find missing IDs
                    missing_in_target = source_ids - target_ids
                    missing_in_source = target_ids - source_ids
                    self._add_log(job, 'info', f"Missing in target: {len(missing_in_target)}, Missing in source: {len(missing_in_source)}")
                    
                    # Sync from source to target
                    for row_id in missing_in_target:
                        # Check if stop was requested
                        if job.stop_event.is_set():
                            self._add_log(job, 'warning', 'Stop requested, exiting sync early')
                            break
                        try:
                            row_data = self._get_row_data(source_conn, table_name, id_column, row_id)
                            if row_data:
                                # Filter to common columns only
                                filtered_data = {col: row_data.get(col) for col in common_columns if col in row_data}
                                if self._insert_row(target_conn, table_name, list(filtered_data.keys()), filtered_data):
                                    stats['rows_synced_source_to_target'] += 1
                                    self._add_monitor_row(job, 'success', table_name, row_id, 'Synced to target')
                                else:
                                    stats['rows_failed'] += 1
                                    error_msg = f"Failed to insert row {row_id} into target"
                                    self._log_failed_row(job, table_name, row_id, error_msg, filtered_data)
                                    self._add_monitor_row(job, 'error', table_name, row_id, error_msg)
                        except Exception as e:
                            stats['rows_failed'] += 1
                            error_msg = f"Error syncing row {row_id} to target: {str(e)}"
                            self._log_failed_row(job, table_name, row_id, error_msg)
                            self._add_monitor_row(job, 'error', table_name, row_id, error_msg)
                            # Skip this round, continue with next row
                            continue
                    
                    # Check if stop was requested before syncing from target to source
                    if job.stop_event.is_set():
                        self._add_log(job, 'warning', 'Stop requested, exiting sync early')
                        break
                    
                    # Sync from target to source
                    for row_id in missing_in_source:
                        # Check if stop was requested
                        if job.stop_event.is_set():
                            self._add_log(job, 'warning', 'Stop requested, exiting sync early')
                            break
                        
                        try:
                            row_data = self._get_row_data(target_conn, table_name, id_column, row_id)
                            if row_data:
                                # Filter to common columns only
                                filtered_data = {col: row_data.get(col) for col in common_columns if col in row_data}
                                if self._insert_row(source_conn, table_name, list(filtered_data.keys()), filtered_data):
                                    stats['rows_synced_target_to_source'] += 1
                                    self._add_monitor_row(job, 'success', table_name, row_id, 'Synced to source')
                                else:
                                    stats['rows_failed'] += 1
                                    error_msg = f"Failed to insert row {row_id} into source"
                                    self._log_failed_row(job, table_name, row_id, error_msg, filtered_data)
                                    self._add_monitor_row(job, 'error', table_name, row_id, error_msg)
                        except Exception as e:
                            stats['rows_failed'] += 1
                            error_msg = f"Error syncing row {row_id} to source: {str(e)}"
                            self._log_failed_row(job, table_name, row_id, error_msg)
                            self._add_monitor_row(job, 'error', table_name, row_id, error_msg)
                            # Skip this round, continue with next row
                            continue
                    
                    stats['tables_processed'] += 1
                except Exception as e:
                    error_msg = f"Error processing table {table_name}: {str(e)}"
                    logger.error(error_msg)
                    self._add_monitor_row(job, 'error', table_name, 'N/A', error_msg)
                    # Skip this table in this round, continue with next
                    continue
            
            source_conn.close()
            target_conn.close()
            
            job.last_sync_stats = stats
            job.status = 'stopped'
            
        except Exception as e:
            logger.error(f"Error in complete model sync: {e}")
            job.status = 'error'
            error_msg = f"Sync error: {str(e)}"
            self._add_log(job, 'error', error_msg)
            self._add_monitor_row(job, 'error', 'SYSTEM', 'N/A', error_msg)
    
    def _sync_one_way(self, job: PostgresSyncJob):
        """Sync using one-way model - from source to target only."""
        try:
            self._add_log(job, 'info', f"Starting one-way sync for job {job.name}")
            
            # Connect to both databases
            self._add_log(job, 'info', f"Connecting to source database: {job.source_host}:{job.source_port}/{job.source_database}")
            source_conn = self._get_connection(
                job.source_host, job.source_port, job.source_database,
                job.source_user, job.source_password
            )
            self._add_log(job, 'success', "Connected to source database")
            
            self._add_log(job, 'info', f"Connecting to target database: {job.target_host}:{job.target_port}/{job.target_database}")
            target_conn = self._get_connection(
                job.target_host, job.target_port, job.target_database,
                job.target_user, job.target_password
            )
            self._add_log(job, 'success', "Connected to target database")
            
            # Get all tables from source
            self._add_log(job, 'info', "Retrieving table list from databases...")
            source_tables = self._get_all_tables(source_conn)
            target_tables = self._get_all_tables(target_conn)
            common_tables = set(source_tables) & set(target_tables)
            self._add_log(job, 'info', f"Found {len(common_tables)} common tables to sync")
            
            stats = {
                'tables_processed': 0,
                'rows_synced': 0,
                'rows_failed': 0,
                'rows_skipped': 0
            }
            
            for table_name in common_tables:
                # Check if stop was requested
                if job.stop_event.is_set():
                    self._add_log(job, 'warning', 'Stop requested, exiting sync early')
                    break
                
                try:
                    self._add_log(job, 'info', f"Processing table: {table_name}")
                    # Get primary key
                    id_column = self._get_table_primary_key(source_conn, table_name)
                    if not id_column:
                        self._add_log(job, 'warning', f"Table {table_name} has no primary key, skipping")
                        self._add_monitor_row(job, 'skipped', table_name, 'N/A', 'No primary key found')
                        continue
                    
                    self._add_log(job, 'info', f"Using primary key column: {id_column} for table {table_name}")
                    
                    # Get columns
                    source_columns = self._get_table_columns(source_conn, table_name)
                    target_columns = self._get_table_columns(target_conn, table_name)
                    common_columns = [col for col in source_columns if col in target_columns]
                    if id_column not in common_columns:
                        common_columns.insert(0, id_column)
                    
                    # Get row IDs from both databases
                    self._add_log(job, 'info', f"Getting row IDs from {table_name}...")
                    source_ids = self._get_row_ids(source_conn, table_name, id_column)
                    target_ids = self._get_row_ids(target_conn, table_name, id_column)
                    self._add_log(job, 'info', f"Source has {len(source_ids)} rows, target has {len(target_ids)} rows")
                    
                    # Find missing IDs in target
                    missing_in_target = source_ids - target_ids
                    self._add_log(job, 'info', f"Missing in target: {len(missing_in_target)} rows to sync")
                    
                    # Sync from source to target
                    for row_id in missing_in_target:
                        # Check if stop was requested
                        if job.stop_event.is_set():
                            self._add_log(job, 'warning', 'Stop requested, exiting sync early')
                            break
                        try:
                            row_data = self._get_row_data(source_conn, table_name, id_column, row_id)
                            if row_data:
                                # Filter to common columns only
                                filtered_data = {col: row_data.get(col) for col in common_columns if col in row_data}
                                if self._insert_row(target_conn, table_name, list(filtered_data.keys()), filtered_data):
                                    stats['rows_synced'] += 1
                                    self._add_monitor_row(job, 'success', table_name, row_id, 'Synced to target')
                                else:
                                    stats['rows_failed'] += 1
                                    error_msg = f"Failed to insert row {row_id} into target"
                                    self._log_failed_row(job, table_name, row_id, error_msg, filtered_data)
                                    self._add_monitor_row(job, 'error', table_name, row_id, error_msg)
                        except Exception as e:
                            stats['rows_failed'] += 1
                            error_msg = f"Error syncing row {row_id} to target: {str(e)}"
                            self._log_failed_row(job, table_name, row_id, error_msg)
                            self._add_monitor_row(job, 'error', table_name, row_id, error_msg)
                            # Skip this round, continue with next row
                            continue
                    
                    stats['tables_processed'] += 1
                except Exception as e:
                    error_msg = f"Error processing table {table_name}: {str(e)}"
                    logger.error(error_msg)
                    self._add_monitor_row(job, 'error', table_name, 'N/A', error_msg)
                    # Skip this table in this round, continue with next
                    continue
            
            source_conn.close()
            target_conn.close()
            
            job.last_sync_stats = stats
            # Note: is_running will be set to False by _run_sync after this method returns
            # Status is set here to indicate sync completed (even with some failures)
            job.status = 'stopped'
            self._add_log(job, 'success', f"Sync completed. Tables: {stats['tables_processed']}, "
                         f"Rows synced: {stats['rows_synced']}, "
                         f"Failed: {stats['rows_failed']}")
            
        except Exception as e:
            logger.error(f"Error in one-way sync: {e}")
            # Note: is_running will be set to False by _run_sync in exception handler
            job.status = 'error'
            error_msg = f"Sync error: {str(e)}"
            self._add_log(job, 'error', error_msg)
            self._add_monitor_row(job, 'error', 'SYSTEM', 'N/A', error_msg)
    
    def _run_sync(self, job: PostgresSyncJob, one_time: bool = False):
        """Run sync for a job."""
        # Use try-finally to ensure is_running is ALWAYS reset
        try:
            # Check if persistent mode is still enabled (for scheduled runs)
            if not one_time:
                with self.lock:
                    if not job.is_persistent:
                        # Persistent mode was disabled, don't run
                        job.is_running = False
                        job.status = 'stopped'
                        return
                    
                    # Check if previous task is still running - skip this run if so
                    if job.is_running:
                        logger.info(f"Previous task for job {job.job_id} is still running, skipping this scheduled run. Will retry in {job.check_interval} seconds.")
                        self._add_monitor_row(job, 'skipped', 'SYSTEM', 'N/A', f"Skipped scheduled run - previous task still running. Next check in {job.check_interval}s")
                        # Schedule next run
                        def schedule_next_run():
                            try:
                                logger.info(f"Timer fired for job {job.job_id}, checking if ready to run")
                                self._run_sync(job, one_time=False)
                            except Exception as e:
                                logger.error(f"Error in scheduled sync for job {job.job_id}: {e}")
                        
                        timer = threading.Timer(job.check_interval, schedule_next_run)
                        timer.daemon = True
                        timer.start()
                        return
                    
                    # Set running flag for this execution
                    job.is_running = True
            
            # Check if we should stop before starting
            if job.stop_event.is_set():
                with self.lock:
                    job.is_running = False
                    job.status = 'stopped'
                    job.stop_event.clear()  # Clear the event
                return
            
            job.status = 'running'
            job.last_run = datetime.now()
            self._add_log(job, 'info', f"Starting sync execution (type: {job.sync_type})")
            
            try:
                if job.sync_type == 'complete_model':
                    self._sync_complete_model(job)
                else:  # one_way
                    self._sync_one_way(job)
            except Exception as sync_error:
                # Sync method had an error, but we still need to mark as complete
                logger.error(f"Error in sync method for job {job.job_id}: {sync_error}")
                job.status = 'error'
                self._add_log(job, 'error', f"Sync method error: {str(sync_error)}")
            
            # Check if we should stop after sync completes
            if job.stop_event.is_set():
                with self.lock:
                    job.is_running = False
                    job.status = 'stopped'
                    job.stop_event.clear()  # Reset for next run
                self._add_log(job, 'info', 'Sync stopped by user request')
                return
            
            # Mark task as completed (sync went through all rows, even if some failed)
            # This is the sign of finish - all rows processed
            with self.lock:
                job.is_running = False
                if job.status == 'running':
                    job.status = 'stopped'
            self._add_log(job, 'info', 'Sync execution completed - all rows processed')
            
            # If persistent and not one-time, schedule next run
            if job.is_persistent and not one_time:
                # Double-check persistent is still enabled before scheduling
                with self.lock:
                    if job.is_persistent and not job.stop_event.is_set():
                        # Schedule next run using a wrapper to ensure proper execution
                        def schedule_next_run():
                            try:
                                logger.info(f"Timer fired for job {job.job_id}, starting scheduled sync")
                                self._add_log(job, 'info', f"Timer triggered - checking if ready to run...")
                                self._run_sync(job, one_time=False)
                            except Exception as e:
                                logger.error(f"Error in scheduled sync for job {job.job_id}: {e}")
                        
                        timer = threading.Timer(job.check_interval, schedule_next_run)
                        timer.daemon = True  # Ensure timer doesn't prevent shutdown
                        timer.start()
                        logger.info(f"Scheduled next sync for job {job.job_id} in {job.check_interval} seconds")
                        self._add_log(job, 'info', f"Next sync scheduled in {job.check_interval} seconds")
                    else:
                        logger.info(f"Persistent mode disabled or stopped for job {job.job_id}, not scheduling next run")
            
        except Exception as e:
            logger.error(f"Error running sync for job {job.job_id}: {e}")
            with self.lock:
                job.is_running = False
                job.status = 'error'
            self._add_monitor_row(job, 'error', 'SYSTEM', 'N/A', f"Sync error: {str(e)}")
            self._add_log(job, 'error', f"Fatal sync error: {str(e)}")
            
            # If persistent and error occurred, still try to schedule next run
            if job.is_persistent and not one_time:
                with self.lock:
                    if job.is_persistent and not job.stop_event.is_set():
                        def schedule_next_run_after_error():
                            try:
                                logger.info(f"Timer fired for job {job.job_id} after error, checking if ready to run")
                                self._run_sync(job, one_time=False)
                            except Exception as e:
                                logger.error(f"Error in scheduled sync for job {job.job_id}: {e}")
                        
                        timer = threading.Timer(job.check_interval, schedule_next_run_after_error)
                        timer.daemon = True
                        timer.start()
                        logger.info(f"Scheduled next sync for job {job.job_id} after error in {job.check_interval} seconds")
        finally:
            # ALWAYS ensure is_running is False when we exit this method
            # This is the critical fix - ensures task is marked as finished
            # The finally block guarantees this runs even if there's an exception or early return
            with self.lock:
                was_running = job.is_running
                job.is_running = False
                # If status was still 'running', mark it as stopped (task completed)
                if job.status == 'running':
                    job.status = 'stopped'
                    if was_running:
                        logger.info(f"Job {job.job_id} completed - reset is_running flag")
                elif was_running:
                    # Status was already set but is_running wasn't reset - log it
                    logger.debug(f"Job {job.job_id} status is {job.status}, reset is_running flag")
    
    def start_job(self, job_id: str, persistent: bool = False) -> bool:
        """Start a PostgreSQL sync job."""
        with self.lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            if job.is_running:
                return False
            
            job.is_running = True
            job.is_persistent = persistent
            job.stop_event.clear()
            logger.info(f"Starting job {job_id}, persistent={persistent}")
        
        # Run in separate thread
        def run():
            try:
                self._run_sync(job, one_time=not persistent)
            except Exception as e:
                logger.error(f"Error in job thread for {job_id}: {e}")
            finally:
                # Only set is_running to False if it's a one-time job
                # For persistent jobs, is_running will be managed by _run_sync
                if not persistent:
                    with self.lock:
                        job.is_running = False
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        job.thread = thread
        
        return True
    
    def stop_job(self, job_id: str) -> bool:
        """Stop a running PostgreSQL sync job (stops both task and persistent mode)."""
        with self.lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            if not job.is_running:
                return False
            
            job.is_persistent = False
            job.stop_event.set()
            job.is_running = False
            job.status = 'stopped'
        
        return True
    
    def stop_task(self, job_id: str) -> bool:
        """Stop only the currently running task, but keep persistent mode enabled."""
        with self.lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            if not job.is_running:
                return False
            
            # Signal the task to stop
            job.stop_event.set()
            # Set is_running to False immediately so new tasks can start
            # The sync will check stop_event and exit gracefully
            job.is_running = False
            job.status = 'stopped'
            self._add_log(job, 'info', 'Task stop requested - will exit after current operation')
        
        return True
    
    def stop_persistent(self, job_id: str) -> bool:
        """Stop persistent mode, but allow current task to finish if running."""
        with self.lock:
            if job_id not in self.jobs:
                return False
            
            job = self.jobs[job_id]
            if not job.is_persistent:
                return False
            
            # Disable persistent mode (will prevent next scheduled run)
            job.is_persistent = False
            # Don't stop current task if running, let it finish
        
        return True
    
    def run_job_once(self, job_id: str) -> bool:
        """Run a job once (one-time execution)."""
        return self.start_job(job_id, persistent=False)
    
    def get_job_logs(self, job_id: str) -> Dict:
        """Get logs for a job (monitor rows)."""
        with self.lock:
            if job_id not in self.jobs:
                return {'monitor_rows': []}
            
            job = self.jobs[job_id]
            return {
                'monitor_rows': job.monitor_rows[-20:]  # Last 20 rows
            }

