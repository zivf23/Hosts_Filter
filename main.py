# -*- coding: utf-8 -*-

"""
HostsBlockOnly.py
-----------------

An optimized script that manages content filtering by updating your Windows hosts file.
It:

1. Runs as admin (otherwise can't write to C:\Windows\System32\drivers\etc\hosts).
2. Backs up the existing hosts (if no backup exists).
3. Downloads a blocklist from GitHub (or any URL).
4. Completely replaces any existing blocklist entries with the new ones.
5. Compresses multiple domains into single hosts lines to reduce file size.
6. Uses proper file locking and handles "file in use" errors.
7. Flushes DNS.
8. Logs each step to "HostsBlockLog.txt" and also prints messages to the user.

Usage (after you compile into an .exe or run directly):

1. Right-click -> Run as Administrator (or run in admin shell).
2. The script will do the rest, printing progress and saving logs.

Dependencies:

* Python 3
* pip install requests pywin32
* Windows admin privileges
"""

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
import win32api
import pywintypes
from collections import OrderedDict  # For deduplication while preserving order

# The path to the Windows hosts file.
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
BACKUP_PATH = HOSTS_PATH + ".backup"

# The remote blocklist URL (StevenBlack porn-only list):
REMOTE_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"

# A log file where we save all messages:
LOG_FILE = "HostsBlockLog.txt"

# Marker comments to identify our blocklist section
BEGIN_MARKER = "# --- BEGIN: Blocklist added by HostsBlockOnly script ---"
END_MARKER = "# --- END: Blocklist added by HostsBlockOnly script ---"

def write_log(message: str, also_print: bool = True):
    """
    Append a timestamped line to LOG_FILE.
    also_print: if True, also print to console for the user.
    """
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        # If we can't write to the log file, at least print
        print(f"Warning: Couldn't write to log file: {e}")
        
    if also_print:
        print(message)

def is_admin() -> bool:
    """
    Return True if the current process is running with Administrator privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def safe_write_file(file_path, content):
    """
    Write to a file using proper file locking to avoid "file in use" errors.
    Will retry if file is locked.
    """
    max_retries = 5
    retry_delay = 1  # seconds
    
    for attempt in range(max_retries):
        try:
            # Try to open with exclusive access
            handle = win32file.CreateFile(
                file_path,
                win32con.GENERIC_WRITE,
                0,  # No sharing - exclusive access
                None,
                win32con.OPEN_ALWAYS,
                win32con.FILE_ATTRIBUTE_NORMAL,
                None
            )
            
            try:
                # Truncate the file
                win32file.SetFilePointer(handle, 0, win32file.FILE_BEGIN)
                win32file.SetEndOfFile(handle)
                
                # Write the content
                win32file.WriteFile(handle, content.encode('utf-8'))
                
                write_log(f"[+] Successfully wrote to file: {file_path}")
                return True
            finally:
                win32file.CloseHandle(handle)
                
        except pywintypes.error as e:
            if e.winerror == 32:  # ERROR_SHARING_VIOLATION
                write_log(f"[*] File in use (attempt {attempt+1}/{max_retries}), retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                write_log(f"[ERROR] Windows error {e.winerror}: {e.strerror}")
                return False
        
        except Exception as e:
            write_log(f"[ERROR] Failed to write to file: {e}")
            return False
    
    write_log(f"[ERROR] Failed to write to file after {max_retries} attempts: file is in use")
    return False

def main():
    # 1) Check if we are admin
    if not is_admin():
        print("[ERROR] You must run this script as Administrator!")
        print("Right-click the .exe -> 'Run as administrator', or open an admin CMD/Powershell.")
        return

    # 2) If the hosts file doesn't exist, we can't do anything
    if not os.path.exists(HOSTS_PATH):
        write_log("[ERROR] hosts file not found, cannot proceed.")
        return

    # 3) If no backup, create one
    if not os.path.exists(BACKUP_PATH):
        try:
            shutil.copy2(HOSTS_PATH, BACKUP_PATH)
            write_log(f"[+] Created hosts backup => {BACKUP_PATH}")
        except Exception as e:
            write_log(f"[ERROR] Failed creating backup => {e}")
            return
    else:
        write_log("[*] Backup already exists, no need to recreate.")

    # 4) Download the blocklist
    write_log(f"[*] Downloading blocklist from => {REMOTE_URL}")
    try:
        resp = requests.get(REMOTE_URL, timeout=30)
        if resp.status_code != 200:
            write_log(f"[ERROR] Blocklist download failed with status {resp.status_code}.")
            return
        lines = resp.text.splitlines()
    except Exception as e:
        write_log(f"[ERROR] Failed to download => {e}")
        return
        
    # 5) Extract domains and compress multiple domains into single lines
    # First, deduplicate domains while preserving order
    unique_domains = OrderedDict()
    for line in lines:
        ln = line.strip()
        if ln and not ln.startswith("#"):
            parts = ln.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                unique_domains[parts[1]] = None
    
    domains = list(unique_domains.keys())
    write_log(f"[*] Found {len(domains)} unique domains from remote list.")
    
    # Compress domains: up to 9 domains per line or 250 characters max per line
    # This significantly reduces the size of the hosts file
    block_lines = []
    current_domains = []
    max_domains_per_line = 9
    max_line_length = 250
    
    for domain in domains:
        # Check if adding this domain would exceed our limits
        test_line = "0.0.0.0 " + " ".join(current_domains + [domain])
        
        if len(current_domains) >= max_domains_per_line or len(test_line) > max_line_length:
            # Current line is full, save it and start a new one
            if current_domains:
                block_lines.append("0.0.0.0 " + " ".join(current_domains))
            current_domains = [domain]
        else:
            # Add domain to current line
            current_domains.append(domain)
    
    # Don't forget to add the last batch of domains
    if current_domains:
        block_lines.append("0.0.0.0 " + " ".join(current_domains))
        
    total_domains = len(domains)
    total_lines = len(block_lines)
    compression_ratio = total_domains / total_lines if total_lines > 0 else 0
    write_log(f"[+] Compressed {total_domains} domains to {total_lines} lines (compression ratio: {compression_ratio:.1f}x)")
    write_log(f"[+] Estimated file size savings: {(total_domains - total_lines) * 10} bytes")

    # 6) Read existing hosts file
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            existing_content = f.read()
    except Exception as e:
        write_log(f"[ERROR] Reading hosts => {e}")
        return

    # 7) Remove any existing blocklist section (between our markers)
    if BEGIN_MARKER in existing_content and END_MARKER in existing_content:
        start_idx = existing_content.find(BEGIN_MARKER)
        end_idx = existing_content.find(END_MARKER) + len(END_MARKER)
        
        # Remove the section including markers
        cleaned_content = existing_content[:start_idx] + existing_content[end_idx:]
        write_log("[*] Removed existing blocklist section from hosts file.")
    else:
        cleaned_content = existing_content
        write_log("[*] No existing blocklist section found.")
    
    # 8) Ensure content ends with newline
    if cleaned_content and not cleaned_content.endswith('\n'):
        cleaned_content += '\n'
        
    # 9) Add our new blocklist
    new_content = cleaned_content + '\n' + BEGIN_MARKER + '\n'
    for line in block_lines:
        new_content += line + '\n'
    new_content += END_MARKER + '\n'

    # 10) Write the updated hosts file
    write_log("[*] Writing updated hosts file...")
    if not safe_write_file(HOSTS_PATH, new_content):
        write_log("[ERROR] Failed to update hosts file.")
        return

    # 11) Flush DNS
    write_log("[*] Flushing DNS cache...")
    try:
        subprocess.run(["ipconfig", "/flushdns"], check=False, capture_output=True)
        write_log("[✓] DNS cache flushed successfully.")
    except Exception as e:
        write_log(f"[WARNING] DNS flush error => {e}", also_print=True)

    write_log("[DONE] The system is now using the updated hosts file. Enjoy safer browsing!")
    print("\nPress Enter to exit...")
    input()  # Wait for user to acknowledge

if __name__=="__main__":
    # If user runs directly:  python HostsBlockOnly.py
    # Or after building with PyInstaller -> HostsBlockOnly.exe
    try:
        main()
    except Exception as e:
        write_log(f"[CRITICAL ERROR] {str(e)}")
        print(f"\nAn unexpected error occurred: {str(e)}")
        print("Press Enter to exit...")
        input()

        