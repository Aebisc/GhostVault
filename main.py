import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from src.interface import GhostVaultUI
from src.watcher import VaultWatcher
from src.engine import EncryptionEngine

class VaultManager:
    def __init__(self):
        self.ui = GhostVaultUI(
            on_activate_callback=self.activate_vault,
            on_deactivate_callback=self.deactivate_vault
        )
        self.watcher = None
        self.current_folder = None
        self.current_password = None
        self.executor = ThreadPoolExecutor(max_workers=1) # Sequential I/O for SSD health in Ultra-Fast Mode
        
        # Set protocol for closing the window
        self.ui.protocol("WM_DELETE_WINDOW", self.on_close)

        # Initial Auto-Detect for default folder
        self.ui.auto_detect_state(os.path.abspath("./vaults"))

    def activate_vault(self, directory, password):
        try:
            # Atomic check: Verify password if vault already exists
            if not EncryptionEngine.verify_vault(directory, password):
                self.ui.log("INVALID PASSWORD: This vault is locked with a different key.")
                return False

            # Setup metadata if it's a new vault
            meta_path = os.path.join(directory, ".vault_meta")
            if not os.path.exists(meta_path):
                EncryptionEngine.setup_vault_meta(directory, password)
            # Migration Step: Warn about engine change if existing vault files are found
            existing_vaults = [f for f in os.listdir(directory) if f.endswith(".vault")]
            if existing_vaults:
                self.ui.log("--- ENGINE MIGRATION WARNING ---")
                self.ui.log("This version uses AES-128 for high-speed throughput.")
                self.ui.log("Existing .vault files (AES-256) may be incompatible.")
                self.ui.log("Ensure files are decrypted with the old engine if needed.")
                self.ui.log("--------------------------------")

            self.current_folder = directory
            self.current_password = password
            self.watcher = VaultWatcher(directory, password, self.ui.log, self.executor)
            self.watcher.start()
            
            # Submitting sweep to a background thread to keep UI responsive
            threading.Thread(target=self.initial_sweep, args=(directory, password), daemon=True).start()
            return True
        except Exception as e:
            self.ui.log(f"Activation Failed: {e}")
            return False

    def initial_sweep(self, directory, password):
        self.ui.log("Running parallel vault sweep...")
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        
        # Filter for cleartext files only
        to_encrypt = []
        for f in files:
            if not f.endswith((".vault", ".tmp")):
                to_encrypt.append(os.path.join(directory, f))
        
        if not to_encrypt:
            self.ui.log("No cleartext files to secure.")
            return

        def process_encrypt(f_path):
            try:
                base_name = os.path.basename(f_path)
                self.ui.log(f"Auto-locking: {base_name}")
                EncryptionEngine.encrypt_file(f_path, password)
            except Exception as e:
                self.ui.log(f"Encryption failed for {os.path.basename(f_path)}: {e}")

        # Parallel execution using ThreadPool
        list(self.executor.map(process_encrypt, to_encrypt))
        self.ui.log("Sweep complete. Vault is secure.")

    def deactivate_vault(self, directory, password=None):
        if not password:
            password = self.current_password

        # Security Lock: Check if password matches .vault_meta
        if not EncryptionEngine.verify_vault(directory, password):
            self.ui.log("SECURITY LOCK: Invalid Password for this Vault.")
            return False

        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        
        self.current_folder = directory # Ensure it's set for cleanup
        self.ui.log("Vault Shield INACTIVE. Auto-restoring files...")
        # Auto-Restore: Deactivation triggers immediate decryption of all vault files.
        self.decrypt_all(directory, password)
        return True

    def decrypt_all(self, directory, password):
        if not directory or not password:
            return

        def run_decrypt():
            self.ui.log("Unlocking files in parallel...")
            files = [f for f in os.listdir(directory) if f.endswith(".vault")]
            
            to_decrypt = []
            for f in files:
                full_path = os.path.join(directory, f)
                clear_path = full_path[:-6]
                
                # State-Aware Skip Logic: If file is already cleartext, skip it
                if os.path.exists(clear_path):
                    continue
                to_decrypt.append(full_path)
                
            if not to_decrypt:
                self.ui.log("All files already restored or no vaults found.")
                return

            def process_decrypt(f_path):
                try:
                    EncryptionEngine.decrypt_file(f_path, password)
                    self.ui.log(f"Unlocked: {os.path.basename(f_path[:-6])}")
                except Exception:
                    self.ui.log(f"Failed to unlock {os.path.basename(f_path)}")

            # Parallel execution
            list(self.executor.map(process_decrypt, to_decrypt))
            self.ui.log("Decryption complete. Files restored.")
        
        threading.Thread(target=run_decrypt, daemon=True).start()

    def emergency_lock(self):
        # Scan folder for cleartext and re-encrypt
        if not self.current_folder or not self.current_password:
            return
            
        directory = self.current_folder
        password = self.current_password
        
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        to_lock = [os.path.join(directory, f) for f in files if not f.endswith((".vault", ".tmp"))]
        
        if to_lock:
            # Parallel execution during shutdown
            list(self.executor.map(lambda f: EncryptionEngine.encrypt_file(f, password), to_lock))

    def on_close(self):
        # We don't want to auto-restore on close, we want to EMERGENCY LOCK.
        # But if the user deactivated first, files are already restored.
        if self.watcher:
            self.emergency_lock()
            self.watcher.stop()
        self.executor.shutdown(wait=True)
        self.ui.destroy()
        sys.exit(0)

    def run(self):
        self.ui.mainloop()

if __name__ == "__main__":
    manager = VaultManager()
    manager.run()
