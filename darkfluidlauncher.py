import frida
import psutil
import subprocess
import time
import sys
import os
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, ttk
import queue


# Dummy Server
class DummyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # disable default logging

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{}')



def start_dummy_server():
    server = HTTPServer(("127.0.0.1", 0), DummyHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"Dummy server running on http://127.0.0.1:{port}")
    return f"http://127.0.0.1:{port}"


# Config Handling
def get_config_path():
    exe_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(__file__)
    return os.path.join(exe_dir, "darkfluidconfig.json")


def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


def load_config():
    config_path = get_config_path()

    if not os.path.isfile(config_path):
        # create default config
        default = {
            "replacementHost": "http://127.0.0.1/",
            "dummyEndpoints": [
                "/api/FriendsV2/Block",
                "/api/Operation/Abandon",
                "/api/Monetization/Steam/RedeemStoreContent",
                "/api/Monetization/Steam/Catalog/en",
                "/api/Progression/Items/Customize",
                "/api/Stats/profile/summary",
                "/api/Stats/profile/801/summary",
                "/api/Stats/war/801/summary",
                "/api/v2/Assignment/Player",
                "/api/LeaderBoard/MiniGame/4171714171",
                "/api/lobby",
                "/api/Mail/inbox",
                "/api/Account/ReportPosition",
                "/api/Operation/Create",
                "/api/Operation/Mission/Start",
                "/api/SeasonPass/1929468580",
                "/api/StoreFront",
                "/api/StoreFront/rotation",
                "/api/Operation/Mission/SetMaxRewards",
                "/api/Progression/inventory/consume",
                "/api/Progression/Achievements",
                "/api/Account/InfoLookup",
                "/api/FriendsV2/Request"
            ]
        }
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)
        return default

    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(config):
    config_path = get_config_path()
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


# Main Script
def load_js(config, dummy_host):
    replacement_host = config["replacementHost"]
    dummy_endpoints = config["dummyEndpoints"]

    js_code = f"""
console.log = function() {{
    send({{type: "log", payload: Array.prototype.slice.call(arguments).join(" ")}});
}};

const originalHost = "https://api.live.prod.thehelldiversgame.com/";
const replacementHost = "{replacement_host}";
const dummyHost = "{dummy_host}";
const endpointsToDummy = {json.dumps(dummy_endpoints)};

const libcurlModule = Process.platform === 'windows' ? "libcurl.dll" : "libcurl.so";
const curl_easy_setopt = Module.findExportByName(libcurlModule, "curl_easy_setopt");

if (curl_easy_setopt) {{
    Interceptor.attach(curl_easy_setopt, {{
        onEnter(args) {{
            const CURLOPT_URL = 10002;
            if (args[1].toInt32() === CURLOPT_URL) {{
                const urlPtr = args[2];
                const originalUrl = Memory.readUtf8String(urlPtr);

                if (originalUrl.startsWith(originalHost)) {{
                    let newUrl = originalUrl;

                    for (const endpoint of endpointsToDummy) {{
                        if (originalUrl.includes(endpoint)) {{
                            newUrl = dummyHost;
                            console.log("[Dummy]", originalUrl);
                            Memory.writeUtf8String(urlPtr, newUrl);
                            return;
                        }}
                    }}

                    newUrl = originalUrl.replace(originalHost, replacementHost);
                    if (newUrl !== originalUrl) {{
                        console.log("[Redirect]", originalUrl);
                        Memory.writeUtf8String(urlPtr, newUrl);
                    }}
                }}
            }}
        }}
    }});
}}
"""
    return js_code


def wait_for_process(name):
    log(f"Waiting for {name} to start...")
    while True:
        for proc in psutil.process_iter(["name"]):
            if proc.info["name"] and proc.info["name"].lower() == name.lower():
                log(f"Found {name} (PID {proc.pid})")
                return proc.pid
        time.sleep(1)


def launch_game(config):
    dummy_host = start_dummy_server()

    log("Launching Helldivers 2...")
    try:
        subprocess.Popen(["cmd", "/c", "start", "steam://run/553850"], shell=True)
    except Exception as e:
        log(f"Failed to launch: {e}")
        return

    pid = wait_for_process("helldivers2.exe")

    log("Attaching to game process...")
    try:
        session = frida.attach(pid)
    except frida.ProcessNotFoundError:
        log("Game process lost.")
        return

    script = session.create_script(load_js(config, dummy_host))

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict) and payload.get("type") == "log":
                log(str(payload.get("payload", "")))
            else:
                log(str(payload))
        elif message["type"] == "error":
            log("[JS ERROR] " + message["description"])

    script.on("message", on_message)
    script.load()

    log(f"Attached! replacementHost = {config['replacementHost']}")

    try:
        while psutil.pid_exists(pid):
            time.sleep(1)
        log("Game process has exited.")
    finally:
        session.detach()


# Logs
log_queue = queue.Queue()


def log(msg):
    log_queue.put(str(msg))


def process_log_queue(text_widget):
    while not log_queue.empty():
        msg = log_queue.get_nowait()
        text_widget.configure(state="normal")
        text_widget.insert(tk.END, msg + "\n")
        text_widget.see(tk.END)
        text_widget.configure(state="disabled")
    text_widget.after(100, process_log_queue, text_widget)


# GUI
def run_gui():
    config = load_config()

    root = tk.Tk()
    root.iconbitmap(resource_path("darkfluid.ico"))
    root.title("Dark Fluid Launcher")
    root.geometry("750x550")

    bg = "#1e1b29"
    fg = "#ffffff"
    accent = "#9b59b6"

    root.configure(bg=bg)
    default_font = ("Segoe UI", 10)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", background=accent, foreground=fg, font=default_font, padding=6)
    style.configure("TLabel", background=bg, foreground=fg, font=default_font)
    style.configure("TEntry", fieldbackground="#2c2c3c", foreground=fg, insertcolor=fg)
    style.configure("TListbox", background="#2c2c3c", foreground=fg)

    # Replacement Host
    ttk.Label(root, text="Replacement Host: http(s)://example.com/, http(s)://123.456.7.89/").pack(anchor="w", pady=2)
    host_entry = ttk.Entry(root, width=50)
    host_entry.insert(0, config["replacementHost"])
    host_entry.pack(fill="x", padx=5, pady=2)

    def apply_host():
        config["replacementHost"] = host_entry.get().strip()
        save_config(config)
        log(f"Replacement host applied: {config['replacementHost']}")

    ttk.Button(root, text="Apply Host", command=apply_host).pack(pady=5)

    # Dummy Endpoints
    ttk.Label(root, text="Dummy Endpoints:").pack(anchor="w")
    listbox = tk.Listbox(root, selectmode=tk.SINGLE, height=8,
                         bg="#2c2c3c", fg=fg, selectbackground=accent,
                         font=default_font)
    for ep in config["dummyEndpoints"]:
        listbox.insert(tk.END, ep)
    listbox.pack(fill="both", expand=False, padx=5, pady=2)

    def add_endpoint():
        new_ep = simpledialog.askstring("Add Endpoint", "Enter endpoint:", parent=root)
        if new_ep:
            listbox.insert(tk.END, new_ep)
            config["dummyEndpoints"].append(new_ep)
            save_config(config)

    def remove_endpoint():
        sel = listbox.curselection()
        if sel:
            idx = sel[0]
            ep = listbox.get(idx)
            listbox.delete(idx)
            config["dummyEndpoints"].remove(ep)
            save_config(config)

    ttk.Button(root, text="Add Endpoint", command=add_endpoint).pack(pady=2)
    ttk.Button(root, text="Remove Selected", command=remove_endpoint).pack(pady=2)

    def launch():
        save_config(config)
        threading.Thread(target=launch_game, args=(config,), daemon=True).start()

    ttk.Button(root, text="Launch Game", command=launch).pack(pady=10)

    # Log output
    ttk.Label(root, text="Logs:").pack(anchor="w")
    log_box = scrolledtext.ScrolledText(root, height=12, bg="#2c2c3c", fg=fg,
                                        insertbackground=fg, font=("Consolas", 9),
                                        state="disabled")
    log_box.pack(fill="both", expand=True, padx=5, pady=5)

    process_log_queue(log_box)

    root.mainloop()


if __name__ == "__main__":
    run_gui()
