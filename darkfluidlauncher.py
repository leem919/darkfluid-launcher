import frida
import psutil
import subprocess
import time
import sys
import os
import json

def load_config():
    exe_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(__file__)
    config_path = os.path.join(exe_dir, "darkfluidconfig.json")

    if not os.path.isfile(config_path):
        print(f"darkfluidconfig.json not found at {config_path}")
        input("Press Enter to quit...")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_js(config):
    replacement_host = config['replacementHost']
    dummy_endpoints = config['dummyEndpoints']

    js_code = f"""
const originalHost = '{"https://api.live.prod.thehelldiversgame.com/"}';
const replacementHost = '{replacement_host}';
const dummyHost = '{"https://dummyjson.com/posts"}';
const endpointsToDummy = {json.dumps(dummy_endpoints)};

const libcurlModule = Process.platform === 'windows' ? "libcurl.dll" : "libcurl.so";
const curl_easy_setopt = Module.findExportByName(libcurlModule, "curl_easy_setopt");

if (curl_easy_setopt) {{
    Interceptor.attach(curl_easy_setopt, {{
        onEnter(args) {{
            const CURLOPT_URL = 10002;
            const option = args[1].toInt32();
            if (option === CURLOPT_URL) {{
                const urlPtr = args[2];
                const originalUrl = Memory.readUtf8String(urlPtr);

                if (originalUrl.startsWith(originalHost)) {{
                    let newUrl = originalUrl;

                    // Check for dummy endpoints first
                    for (const endpoint of endpointsToDummy) {{
                        if (originalUrl.includes(endpoint)) {{
                            newUrl = dummyHost + originalUrl.substring(originalHost.length);
                            break;
                        }}
                    }}

                    // If not a dummy endpoint, replace host
                    if (newUrl === originalUrl) {{
                        newUrl = originalUrl.replace(originalHost, replacementHost);
                    }}

                    Memory.writeUtf8String(urlPtr, newUrl);
                    console.log("Redirecting to", newUrl);
                }}
            }}
        }}
    }});
}}
"""
    return js_code

def wait_for_process(name):
    print(f"Waiting for {name} to start...")
    while True:
        for proc in psutil.process_iter(["name"]):
            if proc.info["name"] and proc.info["name"].lower() == name.lower():
                print(f"Found {name} (PID {proc.pid})")
                return proc.pid
        time.sleep(1)

def main():
    config = load_config()

    print("Launching Helldivers 2...")
    try:
        subprocess.Popen(["cmd", "/c", "start", "steam://run/553850"], shell=True)
    except Exception as e:
        print(f"Failed to launch: {e}")
        input("Press Enter to quit...")
        sys.exit(1)

    pid = wait_for_process("helldivers2.exe")

    print("Attaching to game process...")
    try:
        session = frida.attach(pid)
    except frida.ProcessNotFoundError:
        print("Game process lost.")
        input("Press Enter to quit...")
        sys.exit(1)

    script = session.create_script(load_js(config))
    script.on("message", lambda message, data: print("[JS]", message))
    script.load()

    print(f"Attached! replacementHost = {config['replacementHost']}")

    try:
        while psutil.pid_exists(pid):
            time.sleep(1)
        print("Game process has exited. Quitting...")
    finally:
        session.detach()

if __name__ == "__main__":
    main()
