# 🛡️ GhostVault: Secure File Guardian

GhostVault is a high-performance Windows desktop application designed for near-instant file encryption and protection. It uses **In-Place Header Scrambling** to secure files of any size (including 4K videos) in milliseconds without the overhead of full-file rewriting.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-AES--128--CTR-red.svg)

## ✨ Key Features

*   **⚡ Ultra-Fast Locking:** Scrambles only the first 5MB (Header) of the file, making locking/unlocking near-instant for massive files.
*   **🎭 Filename Obfuscation:** Automatically renames your files to random numerical identifiers to hide their contents.
*   **👁️ Active Watchdog:** Monitors your vault folder in real-time. Any file moved or copied into the vault  while it is active and the app is launched is automatically encrypted.
*   **🚨 Emergency Lock:** Closing the application or "Deactivating" immediately re-secures all cleartext files.
*   **📂 Persistent State:** Automatically detects existing vaults and requires password verification before granting access.

### 📸 Visual Comparison (Ghost Mode)

| Before Locking (Original) | After Locking (Ghost Mode) |
| :---: | :---: |
| ![before](https://github.com/user-attachments/assets/a86f6302-e7c3-4883-849a-83a6b6c9b959)
 | ![after](https://github.com/user-attachments/assets/58492418-93d6-4d28-8563-f2a3f5909ec9) |

## 🚀 Getting Started

### Option 1: Using the Compiled Executable (Recommended)
For users who just want to run the app without installing Python:
1.  check the **Releases** section.
2.  Run `GhostVault_V1.0.exe`.

### Option 2: Running from Source
1.  Clone the repository:
    ```bash
    git clone https://github.com/Aebisc/GhostVault.git
    cd GhostVault
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the application:
    ```bash
    python main.py
    ```

## 🛠️ How to Use

1.  **Select Folder:** Browse for a folder you want to turn into a secure vault.
2.  **Set Password:** Enter a strong password. This password is required to unlock your files later.
3.  **Activate Vault:** Click **ACTIVATE**. The app will perform an initial sweep to secure existing files and start the real-time monitor.
4.  **Add Files:** Simply drop files into the folder; GhostVault will lock them instantly.
5.  **Deactivate:** To access your files, enter your password and click **DEACTIVATE**. Your files will be restored with their original names.

## 🔒 Security Architecture

*   **Encryption:** AES-128 in CTR (Counter) mode for the header zone.
*   **Metadata:** Uses PBKDF2HMAC (SHA256) with 64,000 iterations for password verification.
*   **Scrambled Zone:** 5MB fixed overhead ensures O(1) time complexity relative to file size.
*   **State Management:** Hidden `.vault_meta` file tracks salt, hash, and filename mappings.

---
*Created by [Aebisc]. Guaranteed data integrity with mandatory verification checks before original file cleanup.*
