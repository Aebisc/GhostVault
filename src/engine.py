import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import random

class EncryptionEngine:
    ITERATIONS = 64000 # Reduced iterations for near-instant responsiveness while maintaining security
    HEADER_SIZE = 5 * 1024 * 1024 # 5MB Scramble Zone for Ultra-Fast Mode
    PROTECTED_FILES = [".vault_meta", "desktop.ini", "thumbs.db"]

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16, # AES-128
            salt=salt,
            iterations=EncryptionEngine.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def setup_vault_meta(folder_path: str, password: str):
        """Creates a hidden .vault_meta file with salt and password hash"""
        meta_path = os.path.join(folder_path, ".vault_meta")
        salt = os.urandom(16)
        key_hash = EncryptionEngine.derive_key(password, salt)
        
        with open(meta_path, 'wb') as f:
            f.write(salt)
            f.write(key_hash)
        
        # Hide file on Windows (Hiding Only)
        try:
            os.system(f'attrib +h "{meta_path}"')
        except Exception:
            pass

    @staticmethod
    def verify_vault(folder_path: str, password: str) -> bool:
        """Checks if password matches the hash stored in .vault_meta"""
        meta_path = os.path.join(folder_path, ".vault_meta")
        if not os.path.exists(meta_path):
            return True # Assumed new vault if meta missing
            
        try:
            with open(meta_path, 'rb') as f:
                salt = f.read(16)
                stored_hash = f.read(16)
            
            return EncryptionEngine.derive_key(password, salt) == stored_hash
        except Exception:
            return False

    @staticmethod
    def get_filename_map(folder_path: str) -> dict:
        """Reads the filename map from .vault_meta"""
        meta_path = os.path.join(folder_path, ".vault_meta")
        if not os.path.exists(meta_path):
            return {}
        try:
            with open(meta_path, 'rb') as f:
                f.seek(32) # Skip Salt and Hash
                data = f.read()
                return json.loads(data.decode()) if data else {}
        except Exception:
            return {}

    @staticmethod
    def update_meta_map(folder_path: str, random_id: str, original_name: str = None, remove: bool = False):
        """Updates or removes an entry in the filename map within .vault_meta"""
        meta_path = os.path.join(folder_path, ".vault_meta")
        if not os.path.exists(meta_path):
            return
            
        try:
            with open(meta_path, 'rb+') as f:
                salt = f.read(16)
                key_hash = f.read(16)
                data = f.read()
                filename_map = json.loads(data.decode()) if data else {}
                
                if remove:
                    if random_id in filename_map:
                        del filename_map[random_id]
                else:
                    filename_map[random_id] = original_name
                
                f.seek(32)
                f.write(json.dumps(filename_map).encode())
                f.truncate()
        except Exception:
            pass

    @staticmethod
    def encrypt_file(file_path: str, password: str):
        """In-place header scrambling (AES-CTR)"""
        # Atomic Safety: Check if file is already encrypted or missing
        if not os.path.exists(file_path) or file_path.endswith(".vault"):
            return None
            
        # Exclusion Protocol: Skip protected system files
        if os.path.basename(file_path).lower() in [f.lower() for f in EncryptionEngine.PROTECTED_FILES]:
            return None
        
        try:
            salt = os.urandom(16)
            nonce = os.urandom(16) # CTR mode uses 16-byte nonce/IV
            key = EncryptionEngine.derive_key(password, salt)

            with open(file_path, 'r+b') as f:
                # Read the scramble zone
                header_data = f.read(EncryptionEngine.HEADER_SIZE)
                if not header_data:
                    return None
                
                # Encrypt in-place using AES-CTR (Preserves data length)
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                scrambled_data = encryptor.update(header_data) + encryptor.finalize()
                
                # Overwrite the header with scrambled bytes
                f.seek(0)
                f.write(scrambled_data)
                
                # Signature: Append Salt(16) + Nonce(16) to the end for future decryption
                f.seek(0, 2)
                f.write(salt)
                f.write(nonce)
            
            # Post-Process: Obfuscate name and Rename to .vault
            folder = os.path.dirname(file_path)
            original_name = os.path.basename(file_path)
            filename_map = EncryptionEngine.get_filename_map(folder)
            
            while True:
                random_id = str(random.randint(1, 100000))
                if random_id not in filename_map and not os.path.exists(os.path.join(folder, random_id + ".vault")):
                    break
            
            # Save mapping and rename
            EncryptionEngine.update_meta_map(folder, random_id, original_name)
            new_path = os.path.join(folder, f"{random_id}.vault")
            
            if os.path.exists(new_path):
                os.remove(new_path)
            os.rename(file_path, new_path)
            return new_path
        except Exception:
            return None

    @staticmethod
    def decrypt_file(vault_path: str, password: str) -> str:
        """In-place header descrambling (AES-CTR)"""
        if not vault_path.endswith(".vault"):
            return None
        
        try:
            with open(vault_path, 'r+b') as f:
                # Determine file size to locate signature
                f.seek(0, 2)
                file_size = f.tell()
                
                if file_size < 32: # Salt(16) + Nonce(16) Minimum
                    return None
                
                # Extract Signature (Last 32 bytes)
                f.seek(file_size - 32)
                salt = f.read(16)
                nonce = f.read(16)
                
                # Remove signature from file end
                f.seek(file_size - 32)
                f.truncate()
                
                # Derive key using stored salt
                key = EncryptionEngine.derive_key(password, salt)
                
                # Read the scrambled header
                f.seek(0)
                scrambled_data = f.read(EncryptionEngine.HEADER_SIZE)
                
                # Decrypt using AES-CTR (Bitwise reversal)
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                original_header = decryptor.update(scrambled_data) + decryptor.finalize()
                
                # Restore original header data
                f.seek(0)
                f.write(original_header)
            
            # Post-Process: Restore original name and remove .vault extension
            folder = os.path.dirname(vault_path)
            vault_name = os.path.basename(vault_path)
            random_id = vault_name[:-6] # Remove .vault
            
            filename_map = EncryptionEngine.get_filename_map(folder)
            original_name = filename_map.get(random_id)
            
            if original_name:
                new_path = os.path.join(folder, original_name)
                # Cleanup map entry
                EncryptionEngine.update_meta_map(folder, random_id, remove=True)
            else:
                # Fallback if map entry missing
                new_path = vault_path[:-6]

            if os.path.exists(new_path):
                os.remove(new_path)
            os.rename(vault_path, new_path)
            return new_path
        except Exception:
            return None
