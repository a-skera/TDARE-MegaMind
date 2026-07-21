import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, scrolledtext, ttk
import requests
import subprocess
import pystray
from PIL import Image
import threading
import sys
import os
import time

# ---------------- GLOBALS ----------------
SERVER_URL = ""
process = None
login_credentials = {}
tray_icon = None
tray_running = False
app_locked = False

# ---------------- HELPERS ----------------
def resource_path(relative_path):
    """Get absolute path for PyInstaller EXE or normal script"""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def log_output(message):
    output_box.configure(state="normal")
    output_box.insert(tk.END, message + "\n")
    output_box.see(tk.END)
    output_box.configure(state="disabled")

def start_hover_effect(widget, color_on="#A3BE8C", color_off="#4C566A"):
    def on_enter(e):
        widget.config(bg=color_on)
    def on_leave(e):
        widget.config(bg=color_off)
    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)
    widget.config(bg=color_off, fg="#ECEFF4", font=("Arial", 10, "bold"))

# ---------------- LOGIN ----------------
def attempt_login():
    global SERVER_URL
    username = entry_username.get()
    password = entry_password.get()
    server_ip = entry_server.get()

    if not username or not password or not server_ip:
        messagebox.showerror("Error", "Fill all fields")
        return

    global login_credentials
    login_credentials = {"username": username, "password": password}
    SERVER_URL = f"http://{server_ip}:5000/login"

    try:
        response = requests.post(SERVER_URL, json=login_credentials, timeout=5)
        if response.status_code == 200:
            login_frame.pack_forget()
            show_dashboard(server_ip)
            log_output("[+] Login successful!")
        else:
            messagebox.showerror("Failed", "Invalid credentials")
            log_output("[!] Login failed")
    except requests.exceptions.RequestException:
        messagebox.showerror("Error", "Cannot connect to server")
        log_output("[!] Cannot connect to server")

# ---------------- FLUENT BIT ----------------
def browse_config():
    file_path = filedialog.askopenfilename(filetypes=[("Config Files", "*.conf")])
    if file_path:
        entry_config.delete(0, tk.END)
        entry_config.insert(0, file_path)

def require_auth(action_name):
    """Prompt for password verification before sensitive action"""
    pwd = simpledialog.askstring(f"{action_name} - Authentication",
                                 "Enter password:", show="*")
    if pwd == login_credentials.get("password"):
        return True
    else:
        messagebox.showerror("Error", "Incorrect password")
        return False

def get_fluent_bit_path():
    """Detect Fluent Bit path for EXE or script"""
    bundled_path = resource_path("fluent-bit/bin/fluent-bit.exe")
    if os.path.exists(bundled_path):
        return bundled_path
    from shutil import which
    if which("fluent-bit.exe"):
        return "fluent-bit.exe"
    return "fluent-bit.exe"

def run_fluentbit():
    global process
    config_path = entry_config.get()
    if not config_path:
        messagebox.showerror("Error", "Select a config file")
        return
    try:
        cmd = [get_fluent_bit_path(), "-c", config_path]
        process = subprocess.Popen(cmd)
        fluent_status.config(bg="green")
        log_output("[+] Fluent Bit started successfully")
        update_tray_tooltip()
    except Exception as e:
        messagebox.showerror("Error", str(e))
        log_output(f"[!] Fluent Bit failed to start: {e}")

def stop_fluentbit():
    global process
    if process and require_auth("Stop Fluent Bit"):
        process.terminate()
        process = None
        log_output("[!] Fluent Bit stopped")
        fluent_status.config(bg="red")
        update_tray_tooltip()

# ---------------- DASHBOARD ----------------
def show_dashboard(server_ip):
    global notebook, output_box, entry_config, btn_run_fluent, fluent_status, server_status, btn_lock

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    # ---------- TAB: Connection ----------
    tab_connection = tk.Frame(notebook, bg="#3B4252")
    notebook.add(tab_connection, text="Connection")

    tk.Label(tab_connection, text=f"Connected to server: {server_ip}", bg="#3B4252", fg="#ECEFF4", font=("Arial", 12, "bold")).pack(pady=10)

    tk.Label(tab_connection, text="Server Status:", bg="#3B4252", fg="#ECEFF4").pack(pady=5)
    global server_status
    server_status = tk.Label(tab_connection, text="", bg="green", width=2, height=1)
    server_status.pack(pady=5)

    # ---------- TAB: Fluent Bit ----------
    tab_fluent = tk.Frame(notebook, bg="#3B4252")
    notebook.add(tab_fluent, text="Fluent Bit")

    tk.Label(tab_fluent, text="Fluent Bit Config File:", bg="#3B4252", fg="#ECEFF4").pack(pady=5)
    global entry_config
    entry_config = tk.Entry(tab_fluent, width=50)
    entry_config.pack()

    tk.Button(tab_fluent, text="Browse Config", command=browse_config).pack(pady=5)

    btn_run_fluent = tk.Button(tab_fluent, text="Run Fluent Bit", command=run_fluentbit)
    btn_run_fluent.pack(pady=5)
    start_hover_effect(btn_run_fluent, "#A3BE8C", "#4C566A")

    btn_stop_fluent = tk.Button(tab_fluent, text="Stop Fluent Bit", command=stop_fluentbit)
    btn_stop_fluent.pack(pady=5)
    start_hover_effect(btn_stop_fluent, "#BF616A", "#4C566A")

    tk.Label(tab_fluent, text="Fluent Bit Status:", bg="#3B4252", fg="#ECEFF4").pack(pady=5)
    global fluent_status
    fluent_status = tk.Label(tab_fluent, text="", bg="red", width=2, height=1)
    fluent_status.pack(pady=5)

    # ---------- TAB: Logs ----------
    tab_logs = tk.Frame(notebook, bg="#3B4252")
    notebook.add(tab_logs, text="Logs")

    global output_box
    output_box = scrolledtext.ScrolledText(tab_logs, height=20, bg="#3B4252", fg="#ECEFF4", state="disabled")
    output_box.pack(fill="both", expand=True, padx=10, pady=10)

    # ---------- Lock Button ----------
    btn_lock = tk.Button(root, text="Lock Application", command=lock_application)
    btn_lock.pack(pady=5)
    start_hover_effect(btn_lock, "#D08770", "#4C566A")

# ---------------- AUTHENTICATION HELPER ----------------
def auth_then(action):
    """Run password prompt safely on main thread before executing action"""
    def ask_and_run():
        pwd = simpledialog.askstring("Authentication", "Enter password:", show="*")
        if pwd == login_credentials.get("password"):
            action()
        else:
            messagebox.showerror("Error", "Incorrect password")
    root.after(0, ask_and_run)

# ---------------- SYSTEM TRAY ----------------
def create_tray_icon():
    icon_path = resource_path("TDARE__.ico")
    return Image.open(icon_path)

def update_tray_tooltip():
    global tray_icon
    if tray_icon:
        server_text = entry_server.get() if SERVER_URL else "N/A"
        conn_status = "Connected" if SERVER_URL else "Disconnected"
        fluent_status_text = "Running" if process else "Stopped"
        tray_icon.title = f"TDARE Client\nServer: {server_text} ({conn_status})\nLogs Engine: {fluent_status_text}"

def unlock_from_tray():
    auth_then(lambda: root.deiconify())

def exit_from_tray():
    auth_then(exit_app)

def minimize_to_tray():
    global tray_icon, tray_running
    root.withdraw()
    if not tray_running:
        tray_icon = pystray.Icon(
            "tdare",
            create_tray_icon(),
            "TDARE Client",
            menu=pystray.Menu(
                pystray.MenuItem("Open", unlock_from_tray),
                pystray.MenuItem("Exit", exit_from_tray)
            )
        )
        threading.Thread(target=tray_icon.run, daemon=True).start()
        tray_running = True
    update_tray_tooltip()

def lock_application():
    global app_locked
    app_locked = True
    minimize_to_tray()
    log_output("[*] Application locked and minimized to tray")

def exit_app():
    if require_auth("Exit Application"):
        if process:
            process.terminate()
        root.destroy()
        sys.exit()

# ---------------- MAIN GUI ----------------
root = tk.Tk()
root.title("TDARE ClientSide")
root.geometry("700x500")
root.config(bg="#2E3440")

# Set Main Window Icon
icon_path = resource_path("TDARE__.ico")
if os.path.exists(icon_path):
    root.iconbitmap(icon_path)
else:
    print("Icon file not found!")

root.protocol("WM_DELETE_WINDOW", minimize_to_tray)

# Login Frame
login_frame = tk.Frame(root, bg="#2E3440")
login_frame.pack(fill="both", expand=True)

tk.Label(login_frame, text="Login to TDARE", bg="#2E3440", fg="#ECEFF4", font=("Arial", 16, "bold")).pack(pady=20)
tk.Label(login_frame, text="Server IP:", bg="#2E3440", fg="#ECEFF4").pack(pady=5)
entry_server = tk.Entry(login_frame)
entry_server.pack(pady=5)
entry_server.insert(0, "127.0.0.1")

tk.Label(login_frame, text="Username:", bg="#2E3440", fg="#ECEFF4").pack(pady=5)
entry_username = tk.Entry(login_frame)
entry_username.pack(pady=5)

tk.Label(login_frame, text="Password:", bg="#2E3440", fg="#ECEFF4").pack(pady=5)
entry_password = tk.Entry(login_frame, show="*")
entry_password.pack(pady=5)

btn_login = tk.Button(login_frame, text="Login", command=attempt_login)
btn_login.pack(pady=15)
start_hover_effect(btn_login, "#88C0D0", "#4C566A")

root.mainloop()