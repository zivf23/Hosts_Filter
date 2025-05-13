#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import shutil
import subprocess
import ctypes
import requests
import win32file
import win32con
import win32api # הוספת import נדרש
import hashlib
import base64
import getpass
import pywintypes
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from collections import OrderedDict
import threading

# Path to the system's network configuration file
TARGET_CONFIG_PATH = r"C:\Windows\System32\drivers\etc\hosts"
TARGET_CONFIG_BACKUP_PATH = TARGET_CONFIG_PATH + ".backup_app"

# The remote filter list URL
REMOTE_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"

# A log file where we save all messages
APP_LOG_FILE = "AppActivityLog.txt"

# Directory and file to store the hashed password for deactivation
APP_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".appfilterconfig")
AUTH_DATA_FILE = os.path.join(APP_CONFIG_DIR, "filter_auth.dat")

# Markers for application's data section in the configuration file
BEGIN_MARKER = "# --- BEGIN: Filter rules applied by App ---"
END_MARKER = "# --- END: Filter rules applied by App ---"

# Ensure app config directory exists
os.makedirs(APP_CONFIG_DIR, exist_ok=True)

def ensure_file_hidden(file_path):
    """
    Ensures that the specified file has the 'hidden' attribute set on Windows.
    Does nothing if the file does not exist or if attributes cannot be set.
    """
    try:
        if os.path.exists(file_path):
            attrs = win32api.GetFileAttributes(file_path)
            if not (attrs & win32con.FILE_ATTRIBUTE_HIDDEN):
                win32api.SetFileAttributes(file_path, attrs | win32con.FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        # Silently ignore if cannot hide file (e.g., permissions issues, file in use by another process)
        pass

class Logger:
    """
    Handles logging to file (hidden) and the GUI status bar.
    No console output by default.
    """
    def __init__(self, log_file, status_var=None):
        self.log_file = log_file
        self.status_var = status_var
        self._try_hide_log_file() # Attempt to hide log file on initialization

    def _try_hide_log_file(self):
        ensure_file_hidden(self.log_file)
        
    def write(self, message, level="INFO", also_print_to_console=False): # ברירת המחדל שונתה ל-False
        """
        Log a message to file and optionally update the status variable.
        Console printing is off by default.
        """
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{level}] {message}\n"
        
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
            self._try_hide_log_file() # Ensure file remains hidden after write
        except Exception:
            # הודעת השגיאה הזו הוסרה כדי למנוע פלט למסך
            # print(f"Warning: Couldn't write to log file: {e}")
            pass # Fail silently if log writing itself fails
            
        if also_print_to_console: # רק אם במפורש נדרש להדפיס לקונסול
            print(message) # כמעט ולא יהיה שימוש בזה עכשיו
            
        if self.status_var:
            self.status_var.set(message) # עדכון הסטטוס ב-GUI נשאר

# Initialize logger
logger = Logger(APP_LOG_FILE)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

def safe_write_file(file_path, content):
    max_retries = 5
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            handle = win32file.CreateFile(
                file_path, win32con.GENERIC_WRITE, 0, None,
                win32con.OPEN_ALWAYS, win32con.FILE_ATTRIBUTE_NORMAL, None
            )
            try:
                win32file.SetFilePointer(handle, 0, win32file.FILE_BEGIN)
                win32file.SetEndOfFile(handle)
                win32file.WriteFile(handle, content.encode('utf-8'))
                logger.write(f"Successfully updated system configuration.")
                return True
            finally:
                win32file.CloseHandle(handle)
        except pywintypes.error as e:
            if e.winerror == 32:
                logger.write(f"Configuration file in use (attempt {attempt+1}/{max_retries}), retrying...", level="WARN")
                time.sleep(retry_delay)
            else:
                logger.write(f"Windows error during file write {e.winerror}: {e.strerror}", level="ERROR")
                return False
        except Exception as e:
            logger.write(f"Failed to write to configuration file: {e}", level="ERROR")
            return False
    logger.write(f"Failed to write to configuration file after {max_retries} attempts.", level="ERROR")
    return False

def hash_password(password):
    salt = b"AppSecureFilterSalt789"
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(key).decode('utf-8')

def save_password(password):
    hashed_pw = hash_password(password)
    try:
        with open(AUTH_DATA_FILE, 'w') as f:
            f.write(hashed_pw)
        logger.write("Authentication details saved.")
        ensure_file_hidden(AUTH_DATA_FILE) # Also hide auth file
        return True
    except Exception as e:
        logger.write(f"Failed to save authentication data: {e}", level="ERROR")
        return False

def verify_password(password):
    try:
        if not os.path.exists(AUTH_DATA_FILE):
            logger.write("No authentication data found.", level="ERROR")
            return False
        with open(AUTH_DATA_FILE, 'r') as f:
            stored_hash = f.read().strip()
        return hash_password(password) == stored_hash
    except Exception as e:
        logger.write(f"Password verification failed: {e}", level="ERROR")
        return False

def is_filter_active():
    if not os.path.exists(TARGET_CONFIG_PATH):
        return False
    try:
        with open(TARGET_CONFIG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            existing_content = f.read()
        return BEGIN_MARKER in existing_content and END_MARKER in existing_content
    except:
        return False

def deactivate_filter():
    logger.write("Deactivating content filter...")
    if not os.path.exists(TARGET_CONFIG_PATH):
        logger.write("System configuration file not found.", level="ERROR")
        return False
    try:
        with open(TARGET_CONFIG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            existing_content = f.read()
        if BEGIN_MARKER in existing_content and END_MARKER in existing_content:
            start_idx = existing_content.find(BEGIN_MARKER)
            end_idx = existing_content.find(END_MARKER) + len(END_MARKER)
            cleaned_content = existing_content[:start_idx] + existing_content[end_idx:]
            cleaned_content = cleaned_content.rstrip() + '\n'
            if not safe_write_file(TARGET_CONFIG_PATH, cleaned_content):
                logger.write("Failed to write cleaned system configuration.", level="ERROR")
                return False
            try:
                # capture_output=True מונע הדפסה לקונסול
                subprocess.run(["ipconfig", "/flushdns"], check=False, capture_output=True)
                logger.write("DNS cache flushed.")
            except Exception as e:
                logger.write(f"DNS flush error: {e}", level="WARN")
            logger.write("Content filtering deactivated from system configuration.")
            return True
        else:
            logger.write("No filter data found in system configuration.", level="INFO")
            return True
    except Exception as e:
        logger.write(f"Deactivation failed: {e}", level="ERROR")
        return False

def activate_filter(): # רק הפונקציה הזו שונתה, שאר הקוד נשאר זהה לקודם
    logger.write("Activating content filter...")
    if not os.path.exists(TARGET_CONFIG_PATH):
        logger.write("System configuration file not found.", level="ERROR")
        return False

    if not os.path.exists(TARGET_CONFIG_BACKUP_PATH):
        try:
            shutil.copy2(TARGET_CONFIG_PATH, TARGET_CONFIG_BACKUP_PATH)
            logger.write(f"Configuration backup created.")
            ensure_file_hidden(TARGET_CONFIG_BACKUP_PATH) # Hide backup file
        except Exception as e:
            logger.write(f"Failed creating backup: {e}", level="ERROR")
            return False
    else:
        logger.write("Configuration backup already exists.")

    logger.write(f"Downloading filter list from remote source...")
    try:
        resp = requests.get(REMOTE_URL, timeout=30)
        if resp.status_code != 200:
            logger.write(f"Filter list download failed (status {resp.status_code}).", level="ERROR")
            return False
        lines = resp.text.splitlines()
        logger.write("Filter list downloaded.")
    except Exception as e:
        logger.write(f"Failed to download filter list: {e}", level="ERROR")
        return False
        
    unique_items = OrderedDict()
    for line in lines:
        ln = line.strip()
        if ln and not ln.startswith("#"):
            parts = ln.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                unique_items[parts[1]] = None 
    
    items_to_filter = list(unique_items.keys())
    logger.write(f"Found {len(items_to_filter)} unique items for filtering from downloaded list.")
    
    filter_rule_lines = [] # These are the 0.0.0.0 rules from downloaded list
    current_items = []
    max_items_per_line = 9
    max_line_length = 250
    
    for item_to_filter in items_to_filter:
        test_line = "0.0.0.0 " + " ".join(current_items + [item_to_filter])
        if len(current_items) >= max_items_per_line or len(test_line) > max_line_length:
            if current_items:
                filter_rule_lines.append("0.0.0.0 " + " ".join(current_items))
            current_items = [item_to_filter]
        else:
            current_items.append(item_to_filter)
    if current_items:
        filter_rule_lines.append("0.0.0.0 " + " ".join(current_items))
        
    total_items = len(items_to_filter)
    total_lines_from_download = len(filter_rule_lines)
    # logger.write(f"Compressed {total_items} items to {total_lines_from_download} lines (ratio: {compression_ratio:.1f}x)")
    # No longer logging compression ratio here as we add more lines below.

    # ----- BEGIN: Add SafeSearch and YouTube Restricted Mode entries -----
    logger.write("Preparing Google SafeSearch and YouTube Restricted Mode rules...")

    additional_rules = ["\n# --- Added by App: Enforce Safe Browse ---"]
    
    # Enforce Google SafeSearch by mapping to forcesafesearch.google.com (216.239.38.120)
    google_safe_search_ip = "216.239.38.120"
    google_domains_for_safesearch = [
        "www.google.com", "google.com",
        "www.google.ad", "www.google.ae", "www.google.al", "www.google.am", "www.google.as", "www.google.at", "www.google.az", "www.google.ba", 
        "www.google.be", "www.google.bf", "www.google.bg", "www.google.bi", "www.google.bj", "www.google.bs", "www.google.bt", "www.google.by", 
        "www.google.ca", "www.google.cat", "www.google.cc", "www.google.cd", "www.google.cf", "www.google.cg", "www.google.ch", "www.google.ci", 
        "www.google.cl", "www.google.cm", "www.google.co.ao", "www.google.co.bw", "www.google.co.ck", "www.google.co.cr", "www.google.co.id", 
        "www.google.co.il", "www.google.co.in", "www.google.co.jp", "www.google.co.ke", "www.google.co.kr", "www.google.co.ls", "www.google.co.ma", 
        "www.google.co.mz", "www.google.co.nz", "www.google.co.th", "www.google.co.tz", "www.google.co.ug", "www.google.co.uk", "www.google.co.uz", 
        "www.google.co.ve", "www.google.co.vi", "www.google.co.za", "www.google.co.zm", "www.google.co.zw", "www.google.com.af", 
        "www.google.com.ag", "www.google.com.ai", "www.google.com.ar", "www.google.com.au", "www.google.com.bd", "www.google.com.bh", 
        "www.google.com.bn", "www.google.com.bo", "www.google.com.br", "www.google.com.bz", "www.google.com.co", "www.google.com.cu", 
        "www.google.com.cy", "www.google.com.do", "www.google.com.ec", "www.google.com.eg", "www.google.com.et", "www.google.com.fj", 
        "www.google.com.gh", "www.google.com.gi", "www.google.com.gt", "www.google.com.hk", "www.google.com.jm", "www.google.com.kh", 
        "www.google.com.kw", "www.google.com.lb", "www.google.com.ly", "www.google.com.mm", "www.google.com.mt", "www.google.com.mx", 
        "www.google.com.my", "www.google.com.na", "www.google.com.nf", "www.google.com.ng", "www.google.com.ni", "www.google.com.np", 
        "www.google.com.om", "www.google.com.pa", "www.google.com.pe", "www.google.com.pg", "www.google.com.ph", "www.google.com.pk", 
        "www.google.com.pr", "www.google.com.py", "www.google.com.qa", "www.google.com.sa", "www.google.com.sb", "www.google.com.sg", 
        "www.google.com.sl", "www.google.com.sv", "www.google.com.tj", "www.google.com.tr", "www.google.com.tw", "www.google.com.ua", 
        "www.google.com.uy", "www.google.com.vc", "www.google.com.vn", "www.google.cv", "www.google.cz", "www.google.de", "www.google.dj", 
        "www.google.dk", "www.google.dm", "www.google.dz", "www.google.ee", "www.google.es", "www.google.fi", "www.google.fm", "www.google.fr", 
        "www.google.ga", "www.google.ge", "www.google.gg", "www.google.gl", "www.google.gm", "www.google.gp", "www.google.gr", "www.google.gy", 
        "www.google.hn", "www.google.hr", "www.google.ht", "www.google.hu", "www.google.ie", "www.google.im", "www.google.iq", "www.google.is", 
        "www.google.it", "www.google.je", "www.google.jo", "www.google.kg", "www.google.ki", "www.google.kz", "www.google.la", "www.google.li", 
        "www.google.lk", "www.google.lt", "www.google.lu", "www.google.lv", "www.google.md", "www.google.me", "www.google.mg", "www.google.mk", 
        "www.google.ml", "www.google.mn", "www.google.ms", "www.google.mu", "www.google.mv", "www.google.mw", "www.google.ne", "www.google.nl", 
        "www.google.no", "www.google.nr", "www.google.nu", "www.google.pl", "www.google.pn", "www.google.ps", "www.google.pt", "www.google.ro", 
        "www.google.rs", "www.google.ru", "www.google.rw", "www.google.sc", "www.google.se", "www.google.sh", "www.google.si", "www.google.sk", 
        "www.google.sm", "www.google.sn", "www.google.so", "www.google.st", "www.google.td", "www.google.tg", "www.google.tk", "www.google.tl", 
        "www.google.tm", "www.google.tn", "www.google.to", "www.google.tt", "www.google.vu", "www.google.ws"
    ]
    for domain in google_domains_for_safesearch:
        additional_rules.append(f"{google_safe_search_ip} {domain} # Google SafeSearch")

    # Enforce YouTube Restricted Mode (Strict) by mapping to restrict.youtube.com (216.239.38.119)
    youtube_restricted_ip = "216.239.38.119"
    youtube_domains_for_restricted_mode = [
        "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
        "youtube.googleapis.com", "www.youtube-nocookie.com"
    ]
    for domain in youtube_domains_for_restricted_mode:
        additional_rules.append(f"{youtube_restricted_ip} {domain} # YouTube Restricted Mode")
    
    additional_rules.append("# --- End of Safe Browse rules ---\n")
    logger.write(f"Prepared {len(google_domains_for_safesearch) + len(youtube_domains_for_restricted_mode)} Safe Browse rules.")
    # ----- END: Add SafeSearch and YouTube Restricted Mode entries -----


    try:
        with open(TARGET_CONFIG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            existing_content = f.read()
    except Exception as e:
        logger.write(f"Failed reading system configuration: {e}", level="ERROR")
        return False

    if BEGIN_MARKER in existing_content and END_MARKER in existing_content:
        start_idx = existing_content.find(BEGIN_MARKER)
        end_idx = existing_content.find(END_MARKER) + len(END_MARKER)
        cleaned_content = existing_content[:start_idx] + existing_content[end_idx:]
        logger.write("Removed existing filter data from system configuration.")
    else:
        cleaned_content = existing_content
        logger.write("No existing filter data found.")
    
    if cleaned_content and not cleaned_content.endswith('\n'):
        cleaned_content += '\n'
        
    # Construct new content
    new_content = cleaned_content + '\n' + BEGIN_MARKER + '\n'
    # Add rules from downloaded list first
    for line in filter_rule_lines:
        new_content += line + '\n'
    
    # Add SafeSearch/YouTube rules
    for entry in additional_rules: # This includes the section comments and individual rules
        new_content += entry + '\n'
        
    new_content += END_MARKER + '\n'


    logger.write("Writing updated system configuration...")
    if not safe_write_file(TARGET_CONFIG_PATH, new_content):
        logger.write("Failed to update system configuration.", level="ERROR")
        return False

    logger.write("Flushing DNS cache...")
    try:
        subprocess.run(["ipconfig", "/flushdns"], check=False, capture_output=True)
        logger.write("DNS cache flushed.")
    except Exception as e:
        logger.write(f"DNS flush error: {e}", level="WARN")

    logger.write("Content filtering activated!")
    return True

class PasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, title, prompt_text, confirm=False):
        self.prompt_text = prompt_text
        self.confirm = confirm
        self.result = None
        super().__init__(parent, title)
    
    def body(self, master):
        ttk.Label(master, text=self.prompt_text).grid(row=0, column=0, pady=5)
        self.password_entry = ttk.Entry(master, show="*", width=30)
        self.password_entry.grid(row=1, column=0, pady=5, padx=10)
        if self.confirm:
            ttk.Label(master, text="Confirm password:").grid(row=2, column=0, pady=5)
            self.confirm_entry = ttk.Entry(master, show="*", width=30)
            self.confirm_entry.grid(row=3, column=0, pady=5, padx=10)
        return self.password_entry
    
    def apply(self):
        if self.confirm:
            if self.password_entry.get() != self.confirm_entry.get():
                messagebox.showerror("Error", "Passwords do not match", parent=self) # Ensure messagebox has parent
                self.result = None
            elif not self.password_entry.get():
                messagebox.showerror("Error", "Password cannot be empty", parent=self)
                self.result = None
            else:
                self.result = self.password_entry.get()
        else:
            self.result = self.password_entry.get()

class ContentFilterApp:
    def __init__(self, root_window): # שונה ל-root_window למניעת בלבול עם os.path.root
        self.root = root_window
        self.root.title("Content Filter Utility")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, font=('Arial', 10))
        self.style.configure("TLabel", font=('Arial', 10))
        self.style.configure("Header.TLabel", font=('Arial', 12, 'bold'))
        self.style.configure("Status.TLabel", font=('Arial', 9))
        
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        header = ttk.Label(self.main_frame, text="Content Filter", style="Header.TLabel")
        header.pack(pady=10)
        
        description_text = ("This tool helps protect your system by managing access "
                            "to online content using system configuration settings.")
        description = ttk.Label(self.main_frame, text=description_text, wraplength=400)
        description.pack(pady=10)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        global logger
        logger = Logger(APP_LOG_FILE, self.status_var)
        
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.X, pady=10)
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT, padx=5)
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT, padx=5)
        self.status_indicator = ttk.Label(status_frame, text="●", foreground="gray")
        self.status_indicator.pack(side=tk.RIGHT, padx=5)
        
        self.update_status_indicator()
        
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(pady=20)
        self.activate_button = ttk.Button(button_frame, text="Activate Filter", command=self.activate_handler)
        self.activate_button.pack(side=tk.LEFT, padx=10)
        self.deactivate_button = ttk.Button(button_frame, text="Deactivate Filter", command=self.deactivate_handler)
        self.deactivate_button.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(self.main_frame, orient=tk.HORIZONTAL, length=460, mode='indeterminate')
        self.progress.pack(pady=10)
        
        # log_frame = ttk.LabelFrame(self.main_frame, text="Activity Log (Recent)") # הוספתי Recent
        # log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        # self.log_text_widget = tk.Text(log_frame, height=8, width=60, wrap=tk.WORD, state=tk.DISABLED) # מתחיל כ-disabled
        # self.log_text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.load_log_to_gui()
        
        version_label = ttk.Label(self.main_frame, text="v1.2.0", foreground="gray")
        version_label.pack(side=tk.RIGHT, padx=5, pady=5)
    
    def update_status_indicator(self):
        if is_filter_active():
            self.status_indicator.config(text="●", foreground="green")
            self.status_var.set("Content filtering active")
        else:
            self.status_indicator.config(text="●", foreground="red")
            self.status_var.set("Content filtering inactive")
    
    def load_log_to_gui(self): # שם שונה מ-load_log למניעת בלבול
        try:
            if os.path.exists(APP_LOG_FILE):
                with open(APP_LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                last_lines = lines[-10:] if len(lines) > 10 else lines
                self.log_text_widget.config(state=tk.NORMAL) # אפשר עריכה זמנית
                self.log_text_widget.delete(1.0, tk.END)
                for line in last_lines:
                    self.log_text_widget.insert(tk.END, line)
                self.log_text_widget.see(tk.END)
                self.log_text_widget.config(state=tk.DISABLED) # מנע עריכה
        except Exception:
             pass # Silently ignore

    def activate_handler(self):
        if not os.path.exists(AUTH_DATA_FILE):
            password_dialog = PasswordDialog(self.root, "Create Password", 
                                             "Enter a password for deactivation:", confirm=True)
            if password_dialog.result is None:
                messagebox.showinfo("Cancelled", "Activation cancelled", parent=self.root)
                return
            if not save_password(password_dialog.result):
                messagebox.showerror("Error", "Failed to save password", parent=self.root)
                return
        
        self.status_var.set("Activating...")
        self.progress.start()
        self.disable_buttons()
        threading.Thread(target=self.activate_thread, daemon=True).start()
    
    def activate_thread(self):
        success = activate_filter()
        self.root.after(0, self.finish_activation, success)
    
    def finish_activation(self, success):
        self.progress.stop()
        self.enable_buttons()
        self.update_status_indicator()
        self.load_log_to_gui()
        if success:
            messagebox.showinfo("Success", "Content filter activated successfully!", parent=self.root)
        else:
            messagebox.showerror("Error", "Failed to activate content filter. Check log for details.", parent=self.root)
    
    def deactivate_handler(self):
        if not os.path.exists(AUTH_DATA_FILE):
            messagebox.showerror("Error", "No authentication data. Cannot deactivate.", parent=self.root)
            return
        
        password_dialog = PasswordDialog(self.root, "Password Required", "Enter deactivation password:")
        if password_dialog.result is None: return
        if not verify_password(password_dialog.result):
            messagebox.showerror("Error", "Incorrect password. Deactivation aborted.", parent=self.root)
            return
        
        self.status_var.set("Deactivating...")
        self.progress.start()
        self.disable_buttons()
        threading.Thread(target=self.deactivate_thread, daemon=True).start()
    
    def deactivate_thread(self):
        success = deactivate_filter()
        self.root.after(0, self.finish_deactivation, success)
    
    def finish_deactivation(self, success):
        self.progress.stop()
        self.enable_buttons()
        self.update_status_indicator()
        self.load_log_to_gui()
        if success:
            messagebox.showinfo("Success", "Content filter deactivated successfully!", parent=self.root)
        else:
            messagebox.showerror("Error", "Failed to deactivate content filter. Check log for details.", parent=self.root)
    
    def disable_buttons(self):
        self.activate_button.config(state=tk.DISABLED)
        self.deactivate_button.config(state=tk.DISABLED)
    
    def enable_buttons(self):
        self.activate_button.config(state=tk.NORMAL)
        self.deactivate_button.config(state=tk.NORMAL)

def main():
    if not is_admin():
        run_as_admin()
        return 
    
    root_tk = tk.Tk() # שם משתנה שונה
    app = ContentFilterApp(root_tk)
    root_tk.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # הודעת השגיאה הקריטית הזו לא תודפס לקונסול אם אין כזה
        # היא כן תופיע ב-messagebox
        fallback_log_message = f"Critical error in application: {str(e)}"
        try:
            # ננסה לכתוב ללוג הראשי אם הוא קיים
            logger.write(fallback_log_message, level="CRITICAL", also_print_to_console=False)
        except NameError: # אם logger לא הוגדר
             # נסיר את ההדפסה לקונסול גם כאן
             # print(fallback_log_message) 
            pass # אין מה לעשות אם הלוגר הבסיסי נכשל ואין קונסול
        except Exception: # כל שגיאה אחרת בכתיבה ללוג
            pass

        # הודעת שגיאה גרפית תמיד תוצג
        try:
            # ניסיון להציג messagebox. ייתכן ש-tkinter לא מאותחל אם השגיאה מוקדמת מאוד.
            # יצירת root זמני אם צריך, רק עבור ה-messagebox.
            temp_root_for_error = tk.Tk()
            temp_root_for_error.withdraw() # הסתר חלון ראשי זמני
            messagebox.showerror("Critical Error", fallback_log_message, parent=temp_root_for_error)
            temp_root_for_error.destroy()
        except tk.TclError: # אם tkinter לא זמין כלל
            # במקרה קיצון כזה, אין דרך להציג הודעה גרפית.
            # והסרנו את ההדפסה לקונסול.
            pass
        except Exception:
            # כל שגיאה אחרת בהצגת ה-messagebox.
            pass