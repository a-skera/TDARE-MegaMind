"""
Real-time Log Receiver
Handles continuous log reception from multiple endpoints

By TDARE-Team -> please for any questions or if you want to use our 

production grade platform contact us and for any creativity have fun. 
"""

import json
import re
import time
import queue
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os


class LogReceiver:
    """Real-time log receiver for continuous log processing"""
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize log receiver
        
        Args:
            callback: Function to call when new log is received
                     Signature: callback(log_entry: dict)
        """
        self.callback = callback
        self.log_queue = queue.Queue(maxsize=10000)  # Buffer up to 10k logs
        self.running = False
        self.thread = None
        self.observers = []
        self.processed_files = set()
        self.last_position = {}  # Track file positions for tail-like behavior
        
    def start(self):
        """Start the log receiver"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._process_queue, daemon=True)
        self.thread.start()
        print("[LogReceiver] Started real-time log receiver")
    
    def stop(self):
        """Stop the log receiver"""
        self.running = False
        
        # Stop all file watchers
        for observer in self.observers:
            observer.stop()
            observer.join()
        self.observers.clear()
        
        if self.thread:
            self.thread.join(timeout=2)
        
        print("[LogReceiver] Stopped log receiver")
    
    def watch_directory(self, directory: str, pattern: str = "*.json"):
        """
        Watch a directory for new log files
        
        Args:
            directory: Directory path to watch
            pattern: File pattern to match (default: *.json)
        """
        try:
            dir_path = Path(directory)
            if not dir_path.exists():
                print(f"[LogReceiver] Directory does not exist: {directory}")
                return
            
            event_handler = LogFileHandler(self, pattern)
            observer = Observer()
            observer.schedule(event_handler, str(dir_path), recursive=True)
            observer.start()
            self.observers.append(observer)
            
            # Also process existing files
            self._process_existing_files(dir_path, pattern)
            
            print(f"[LogReceiver] Watching directory: {directory}")
        except Exception as e:
            print(f"[LogReceiver] Error setting up directory watch: {e}")
    
    def watch_file(self, file_path: str):
        """
        Watch a single log file for new entries (tail-like behavior)
        
        Args:
            file_path: Path to log file
        """
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                print(f"[LogReceiver] File does not exist: {file_path}")
                return
            
            # Process existing content first
            self._tail_file(file_path)
            
            # Set up file watcher
            parent_dir = file_path_obj.parent
            event_handler = LogFileHandler(self, file_path_obj.name)
            observer = Observer()
            observer.schedule(event_handler, str(parent_dir), recursive=False)
            observer.start()
            self.observers.append(observer)
            
            print(f"[LogReceiver] Watching file: {file_path}")
        except Exception as e:
            print(f"[LogReceiver] Error setting up file watch: {e}")
    
    def add_log_entry(self, log_entry: Dict[str, Any]):
        """
        Add a log entry to the processing queue
        
        Args:
            log_entry: Log entry dictionary
        """
        try:
            self.log_queue.put_nowait(log_entry)
        except queue.Full:
            print("[LogReceiver] Warning: Log queue full, dropping oldest entry")
            try:
                self.log_queue.get_nowait()  # Remove oldest
                self.log_queue.put_nowait(log_entry)  # Add new
            except queue.Empty:
                pass
    
    def _process_queue(self):
        """Process log queue in background thread"""
        while self.running:
            try:
                # Get log entry with timeout
                log_entry = self.log_queue.get(timeout=1)
                
                # Process the log
                processed = self._process_log_entry(log_entry)
                
                # Call callback if provided
                if self.callback and processed:
                    try:
                        self.callback(processed)
                    except Exception as e:
                        print(f"[LogReceiver] Callback error: {e}")
                
                self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[LogReceiver] Error processing log: {e}")
    
    def _process_log_entry(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a single log entry
        
        Args:
            log_entry: Raw log entry
            
        Returns:
            Processed log entry or None if invalid
        """
        try:
            # Ensure log has required fields
            if 'timestamp' not in log_entry:
                log_entry['timestamp'] = time.time()
            
            if 'received_at' not in log_entry:
                log_entry['received_at'] = datetime.now().isoformat()
            
            # Parse JSON if raw_line exists
            if 'raw_line' in log_entry and 'data' not in log_entry:
                parsed = self._parse_log_line(log_entry['raw_line'])
                if parsed:
                    log_entry.update(parsed)
            
            return log_entry
        except Exception as e:
            print(f"[LogReceiver] Error processing log entry: {e}")
            return None
    
    def _parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line into structured data"""
        try:
            line = line.strip()
            if not line:
                return None
            
            # Try JSON parsing first
            try:
                data = json.loads(line)
                return {'data': data, 'format': 'json'}
            except json.JSONDecodeError:
                pass
            
            # Try FluentBit format: event_type: [timestamp, {json_data}]
            match = re.search(r'\[[\d.]+\s*,\s*(\{.*?\})\]', line, re.DOTALL)
            if match:
                json_str = match.group(1)
                try:
                    data = json.loads(json_str)
                    timestamp_match = re.search(r'\[([\d.]+)', line)
                    timestamp = float(timestamp_match.group(1)) if timestamp_match else time.time()
                    return {
                        'data': data,
                        'timestamp': timestamp,
                        'format': 'fluentbit'
                    }
                except json.JSONDecodeError:
                    pass
            
            # Fallback: treat as plain text
            return {
                'data': {'message': line},
                'format': 'text'
            }
        except Exception as e:
            print(f"[LogReceiver] Error parsing log line: {e}")
            return None
    
    def _process_existing_files(self, directory: Path, pattern: str):
        """Process existing files in directory"""
        try:
            for file_path in directory.glob(pattern):
                if file_path.is_file():
                    self._tail_file(str(file_path))
        except Exception as e:
            print(f"[LogReceiver] Error processing existing files: {e}")
    
    def _tail_file(self, file_path: str):
        """Read new lines from a file (tail-like behavior)"""
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return
            
            # Get current file size
            current_size = file_path_obj.stat().st_size
            
            # Check if we've seen this file before
            if file_path in self.last_position:
                start_pos = self.last_position[file_path]
            else:
                # First time: read last 100 lines to avoid processing entire file
                start_pos = max(0, current_size - 10000)  # Last ~10KB
                self.processed_files.add(file_path)
            
            if start_pos >= current_size:
                return  # No new content
            
            # Read new content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(start_pos)
                for line in f:
                    line = line.strip()
                    if line:
                        self.add_log_entry({
                            'raw_line': line,
                            'source_file': file_path,
                            'timestamp': time.time()
                        })
            
            # Update position
            self.last_position[file_path] = current_size
            
        except Exception as e:
            print(f"[LogReceiver] Error tailing file {file_path}: {e}")


class LogFileHandler(FileSystemEventHandler):
    """File system event handler for log files"""
    
    def __init__(self, receiver: LogReceiver, pattern: str):
        """
        Initialize file handler
        
        Args:
            receiver: LogReceiver instance
            pattern: File pattern to match
        """
        self.receiver = receiver
        self.pattern = pattern
        self.last_modified = {}
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        # Check pattern match
        if not self._matches_pattern(file_path):
            return
        
        # Avoid duplicate processing
        current_time = time.time()
        if file_path in self.last_modified:
            if current_time - self.last_modified[file_path] < 0.5:  # 500ms debounce
                return
        
        self.last_modified[file_path] = current_time
        
        # Process file
        self.receiver._tail_file(file_path)
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        if self._matches_pattern(file_path):
            # Small delay to ensure file is fully written
            time.sleep(0.1)
            self.receiver._tail_file(file_path)
    
    def _matches_pattern(self, file_path: str) -> bool:
        """Check if file matches the pattern"""
        import fnmatch
        filename = Path(file_path).name
        return fnmatch.fnmatch(filename, self.pattern)


