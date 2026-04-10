import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.engine import EncryptionEngine

class VaultEventHandler(FileSystemEventHandler):
    def __init__(self, password: str, log_callback, executor=None):
        self.password = password
        self.log_callback = log_callback
        self.executor = executor

    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        if file_path.endswith((".vault", ".tmp")):
            return

        self.log_callback(f"Detected: {os.path.basename(file_path)}. Waiting for copy...")
        if self.executor:
            self.executor.submit(self.process_file, file_path)
        else:
            threading.Thread(target=self.process_file, args=(file_path,), daemon=True).start()

    def process_file(self, file_path: str):
        try:
            last_size = -1
            while True:
                if not os.path.exists(file_path):
                    return
                current_size = os.path.getsize(file_path)
                if current_size == last_size and current_size > 0:
                    break
                last_size = current_size
                time.sleep(0.5)

            self.log_callback(f"Locking: {os.path.basename(file_path)}...")
            # Engine now handles deletion of source file (The Purge)
            encrypted_path = EncryptionEngine.encrypt_file(file_path, self.password)
            
            if encrypted_path:
                self.log_callback(f"Encrypted: {os.path.basename(encrypted_path)}")
        except Exception as e:
            self.log_callback(f"Error Processing {os.path.basename(file_path)}: {e}")

class VaultWatcher:
    def __init__(self, directory: str, password: str, log_callback, executor=None):
        self.directory = directory
        self.password = password
        self.log_callback = log_callback
        self.observer = Observer()
        self.event_handler = VaultEventHandler(password, log_callback, executor)

    def start(self):
        self.observer.schedule(self.event_handler, self.directory, recursive=False)
        self.observer.start()
        self.log_callback("Watcher Started.")

    def stop(self):
        self.observer.stop()
        self.observer.join()
        self.log_callback("Watcher Stopped.")
