import os
import subprocess
import time
import customtkinter as ctk
from tkinter import filedialog
from src.engine import EncryptionEngine

class GhostVaultUI(ctk.CTk):
    def __init__(self, on_activate_callback, on_deactivate_callback):
        super().__init__()

        self.on_activate = on_activate_callback
        self.on_deactivate = on_deactivate_callback
        self.is_active = False

        # Basic Window Config
        self.title("GhostVault - Secure File Guardian")
        self.geometry("800x650")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Grid Configuration
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        # --- Header ---
        self.header_label = ctk.CTkLabel(self, text="GHOST VAULT", font=("Inter", 32, "bold"))
        self.header_label.grid(row=0, column=0, pady=(20, 10))

        # --- Path Selector ---
        self.path_frame = ctk.CTkFrame(self)
        self.path_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.path_frame.grid_columnconfigure(1, weight=1)

        self.path_label = ctk.CTkLabel(self.path_frame, text="Vault Folder:")
        self.path_label.grid(row=0, column=0, padx=10, pady=10)

        self.path_entry = ctk.CTkEntry(self.path_frame, placeholder_text="Select a folder to monitor...")
        self.path_entry.insert(0, os.path.abspath("./vaults"))
        self.path_entry.configure(state="readonly")
        self.path_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.browse_btn = ctk.CTkButton(self.path_frame, text="Browse", width=100, command=self.browse_folder)
        self.browse_btn.grid(row=0, column=2, padx=10, pady=10)

        self.open_folder_btn = ctk.CTkButton(self.path_frame, text="Open Folder", width=100, command=self.open_vault_folder)
        self.open_folder_btn.grid(row=0, column=3, padx=10, pady=10)

        # --- Password Input ---
        self.pass_frame = ctk.CTkFrame(self)
        self.pass_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        self.pass_frame.grid_columnconfigure(1, weight=1)

        self.pass_label = ctk.CTkLabel(self.pass_frame, text="Vault Password:")
        self.pass_label.grid(row=0, column=0, padx=10, pady=10)

        self.pass_entry = ctk.CTkEntry(self.pass_frame, show="*")
        self.pass_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.pass_entry.bind("<KeyRelease>", lambda e: self.check_password_match())

        self.show_pass_btn = ctk.CTkButton(self.pass_frame, text="👁", width=40, command=self.toggle_pass_visibility)
        self.show_pass_btn.grid(row=0, column=2, padx=10, pady=10)

        # --- Controls ---
        self.controls_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.controls_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        self.controls_frame.grid_columnconfigure(0, weight=1)

        self.activate_btn = ctk.CTkButton(self.controls_frame, text="ACTIVATE VAULT", height=50, 
                                          font=("Inter", 18, "bold"), fg_color="green", hover_color="#228B22",
                                          command=self.toggle_vault)
        self.activate_btn.grid(row=0, column=0, sticky="ew")

        # --- Activity Log ---
        self.log_label = ctk.CTkLabel(self, text="Activity Log", font=("Inter", 14, "bold"))
        self.log_label.grid(row=4, column=0, padx=20, pady=(10, 0), sticky="w")

        self.log_box = ctk.CTkTextbox(self, height=200)
        self.log_box.grid(row=5, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.log_box.configure(state="disabled")

    def toggle_pass_visibility(self):
        if self.pass_entry.cget("show") == "*":
            self.pass_entry.configure(show="")
        else:
            self.pass_entry.configure(show="*")

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.path_entry.configure(state="normal")
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, folder)
            self.path_entry.configure(state="readonly")
            self.log(f"Target folder changed to: {folder}")
            self.auto_detect_state(folder)

    def auto_detect_state(self, folder):
        """Checks for .vault_meta to determine UI state"""
        meta_path = os.path.join(folder, ".vault_meta")
        if os.path.exists(meta_path):
            self.is_active = True
            self.activate_btn.configure(text="DEACTIVATE VAULT", fg_color="red", hover_color="#8B0000")
            self.log("Vault Persistent State detected: UNLOCKED/IN-PLACE.")
            self.check_password_match()
        else:
            self.is_active = False
            self.activate_btn.configure(text="ACTIVATE VAULT", fg_color="green", hover_color="#228B22", state="normal")
            self.log("Ready to initialize new vault.")

    def check_password_match(self):
        """Order 14: Enforce password verification for existing vaults"""
        folder = self.path_entry.get()
        password = self.pass_entry.get()
        meta_path = os.path.join(folder, ".vault_meta")

        if os.path.exists(meta_path):
            if not password:
                self.activate_btn.configure(state="disabled")
            elif EncryptionEngine.verify_vault(folder, password):
                self.activate_btn.configure(state="normal")
            else:
                self.activate_btn.configure(state="disabled")
        else:
            self.activate_btn.configure(state="normal")

    def open_vault_folder(self):
        folder = self.path_entry.get()
        if os.path.exists(folder):
            subprocess.Popen(f'explorer "{os.path.abspath(folder)}"')
        else:
            self.log(f"Error: Folder {folder} does not exist.")

    def log(self, message):
        self.log_box.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{timestamp}] {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def toggle_vault(self):
        password = self.pass_entry.get()
        if not password:
            self.log("Error: Please enter a password.")
            return

        if not self.is_active:
            success = self.on_activate(self.path_entry.get(), password)
            if success:
                self.is_active = True
                self.activate_btn.configure(text="DEACTIVATE VAULT", fg_color="red", hover_color="#8B0000")
                self.pass_entry.configure(state="disabled")
                self.browse_btn.configure(state="disabled")
                self.log("Vault Shield ACTIVE.")
        else:
            # Deactivate with password check
            success = self.on_deactivate(self.path_entry.get(), password)
            if success:
                self.is_active = False
                self.activate_btn.configure(text="ACTIVATE VAULT", fg_color="green", hover_color="#228B22")
                self.pass_entry.configure(state="normal")
                self.browse_btn.configure(state="normal")
                self.log("Vault Shield INACTIVE.")
            else:
                # Security Lock Logic: disable toggle on wrong password
                self.activate_btn.configure(state="disabled")
                self.log("SECURITY LOCK: Invalid Password for this Vault.")
