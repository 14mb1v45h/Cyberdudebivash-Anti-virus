import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import hashlib
import shutil
import time
import threading
import requests  # For updating virus definitions
from watchdog.observers import Observer  # pip install watchdog
from watchdog.events import FileSystemEventHandler

# Dummy virus signatures (hashes of known malware files - in reality, load from a DB)
VIRUS_SIGNATURES = {
    'eicar_test': '44d88612fea8a8f36de82e1278abb02f',  # MD5 of EICAR test file
    # Add more real signatures here
}

QUARANTINE_DIR = os.path.join(os.path.expanduser("~"), "CyberdudeQuarantine")
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

SIGNATURES_URL = "https://example.com/virus_signatures.json"  # Replace with real URL for updates

class RealTimeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            scan_file(event.src_path)

def compute_hash(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception:
        return None

def scan_file(file_path):
    file_hash = compute_hash(file_path)
    if file_hash in VIRUS_SIGNATURES.values():
        messagebox.showwarning("Malware Detected", f"Malware found in {file_path}! Quarantining...")
        quarantine_file(file_path)
        return True
    return False

def scan_directory(directory):
    infected_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if scan_file(file_path):
                infected_files.append(file_path)
    return infected_files

def quarantine_file(file_path):
    try:
        shutil.move(file_path, QUARANTINE_DIR)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to quarantine {file_path}: {e}")

def update_signatures():
    try:
        response = requests.get(SIGNATURES_URL)
        if response.status_code == 200:
            global VIRUS_SIGNATURES
            VIRUS_SIGNATURES = response.json()
            messagebox.showinfo("Update", "Virus signatures updated successfully!")
        else:
            messagebox.showerror("Update Error", "Failed to fetch updates.")
    except Exception as e:
        messagebox.showerror("Update Error", f"Error updating signatures: {e}")

# GUI Setup
root = tk.Tk()
root.title("Cyberdudebivash Anti-virus")
root.geometry("800x600")

# Header Label
tk.Label(root, text="Cyberdudebivash Anti-virus", font=("Arial", 20, "bold")).pack(pady=10)

# Features Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Scan Tab
scan_frame = ttk.Frame(notebook)
notebook.add(scan_frame, text="Scan")

tk.Label(scan_frame, text="Select Directory to Scan:", font=("Arial", 12)).pack(pady=10)

def select_directory():
    dir_path = filedialog.askdirectory()
    if dir_path:
        infected = scan_directory(dir_path)
        if infected:
            messagebox.showwarning("Scan Results", f"Infected files: {len(infected)}\n" + "\n".join(infected))
        else:
            messagebox.showinfo("Scan Results", "No malware found!")

scan_button = tk.Button(scan_frame, text="Choose Directory & Scan", command=select_directory)
scan_button.pack(pady=10)

# Real-Time Protection Tab
realtime_frame = ttk.Frame(notebook)
notebook.add(realtime_frame, text="Real-Time Protection")

realtime_status = tk.StringVar(value="Off")
tk.Label(realtime_frame, text="Real-Time Monitoring:", font=("Arial", 12)).pack(pady=10)
tk.Label(realtime_frame, textvariable=realtime_status).pack()

observer = None

def toggle_realtime():
    global observer
    if realtime_status.get() == "Off":
        path = os.path.expanduser("~")  # Monitor home directory; customize as needed
        event_handler = RealTimeHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        realtime_status.set("On")
    else:
        if observer:
            observer.stop()
            observer.join()
        realtime_status.set("Off")

toggle_button = tk.Button(realtime_frame, text="Toggle Real-Time", command=toggle_realtime)
toggle_button.pack(pady=10)

# Quarantine Tab
quarantine_frame = ttk.Frame(notebook)
notebook.add(quarantine_frame, text="Quarantine")

tk.Label(quarantine_frame, text="Quarantined Files:", font=("Arial", 12)).pack(pady=10)

quar_list = tk.Listbox(quarantine_frame, height=10, width=80)
quar_list.pack(pady=10)

def refresh_quarantine():
    quar_list.delete(0, tk.END)
    for file in os.listdir(QUARANTINE_DIR):
        quar_list.insert(tk.END, file)

refresh_button = tk.Button(quarantine_frame, text="Refresh", command=refresh_quarantine)
refresh_button.pack()

def restore_file():
    selected = quar_list.curselection()
    if selected:
        file_name = quar_list.get(selected[0])
        orig_path = filedialog.askdirectory(title="Select Restore Location")
        if orig_path:
            shutil.move(os.path.join(QUARANTINE_DIR, file_name), orig_path)
            refresh_quarantine()

restore_button = tk.Button(quarantine_frame, text="Restore Selected", command=restore_file)
restore_button.pack(pady=5)

def delete_file():
    selected = quar_list.curselection()
    if selected:
        file_name = quar_list.get(selected[0])
        os.remove(os.path.join(QUARANTINE_DIR, file_name))
        refresh_quarantine()

delete_button = tk.Button(quarantine_frame, text="Delete Selected", command=delete_file)
delete_button.pack(pady=5)

# Update Tab
update_frame = ttk.Frame(notebook)
notebook.add(update_frame, text="Update")

tk.Label(update_frame, text="Update Virus Definitions:", font=("Arial", 12)).pack(pady=10)
update_button = tk.Button(update_frame, text="Update Now", command=update_signatures)
update_button.pack()

# Settings Tab (for other features like Firewall, VPN placeholders)
settings_frame = ttk.Frame(notebook)
notebook.add(settings_frame, text="Settings")

tk.Label(settings_frame, text="Advanced Features (Placeholders):", font=("Arial", 12)).pack(pady=10)
tk.Label(settings_frame, text="- Firewall: Enabled").pack()
tk.Label(settings_frame, text="- VPN: Connect to secure server").pack()
tk.Label(settings_frame, text="- Dark Web Monitoring: Active").pack()
tk.Label(settings_frame, text="- Parental Controls: Configure").pack()
tk.Label(settings_frame, text="- Safe Banking: Enabled").pack()

# Run the app
root.mainloop()