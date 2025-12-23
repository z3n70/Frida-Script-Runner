from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_socketio import SocketIO
from colorama import Fore
from werkzeug.utils import secure_filename
import subprocess
import os
import json
import hashlib
import threading
import time
import logging
import re
import argparse
import socket
import sys
import requests
import shutil
import lzma
import wget
import subprocess

from mobile_proxy import (
    get_current_mobile_proxy,
    set_mobile_proxy,
    unset_mobile_proxy,
    get_local_proxy_ips,
)

sys.tracebacklimit = 0

parser = argparse.ArgumentParser(description='FSR Tool')
parser.add_argument('-p', '--port', type=int, default=5000, help='Port to run the server on')
parser.add_argument('-v', '--verbose', action='store_true', help='Show the Frida output')
args = parser.parse_args()

app = Flask(__name__)
socketio = SocketIO(app)
process = None
frida_output_buffer = []
current_script_path = None
SCRIPTS_DIRECTORY = f"{os.getcwd()}/scripts"

if os.path.exists("/.dockerenv"):
    CODEX_BRIDGE_URL = "http://host.docker.internal:8091"
else:
    CODEX_BRIDGE_URL = "http://localhost:8091"
TEMP_SCRIPT_PATH = "temp_generated.js"


def log_to_fsr_logs(message):
    """Send debug message to FSR Logs on web interface"""
    socketio.emit("fsr_log", {"data": message})

def get_ghidra_server_url():
    """Return configured Ghidra MCP server URL or default localhost endpoint"""
    return os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8080/")

UPLOAD_FOLDER = 'tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


if "tmp" not in os.listdir("."):
    os.mkdir("tmp")
class OsNotSupportedError(Exception):
    pass
with open("static/data/codeshare_data.json", "r", encoding="utf-8") as f:
    codeshare_snippets = json.load(f)

@app.route("/codeshare/search")
def codeshare_search():
    query = request.args.get("keyword", "").lower()
    if not query:
        return jsonify([])

    keywords = query.split()
    results = []
    for s in codeshare_snippets:
        combined = f"{s['title']} {s['preview']}".lower()
        if all(k in combined for k in keywords):
            results.append({
                "id": s["id"],
                "title": s["title"],
                "preview": s["preview"],
                "source": s["url"],
                "script": s["code"]
            })
    return jsonify(results)

@app.route("/snippet/<int:snippet_id>")
def get_snippet(snippet_id):
    for s in codeshare_snippets:
        if s["id"] == snippet_id:
            return jsonify({"code": s["code"]})
    return abort(404)

def get_device_type():
    if os.name == 'nt':
        return "Windows"
    elif os.name == 'posix':
        if os.uname().sysname == 'Darwin':
            return "macOS"
        else:
            return "Linux"
    else:
        return "Unknown"

def get_device_platform(device_info):
    """Determine if device is Android or iOS based on device info"""
    if "device_id" in device_info or "serial_number" in device_info:
        return "android"
    elif "UDID" in device_info:
        return "ios"
    else:
        return "unknown"

def check_frida_versions():
    """Check Frida client and server versions for compatibility"""
    try:
        client_result = subprocess.run(['frida', '--version'], capture_output=True, text=True, timeout=600)
        client_version = client_result.stdout.strip() if client_result.returncode == 0 else "Unknown"
        server_result = subprocess.run(['frida-ps', '-U'], capture_output=True, text=True, timeout=600)
        server_version = "Unknown"
        
        if server_result.returncode == 0 and server_result.stdout:
            for line in server_result.stdout.split('\n'):
                if 'Frida' in line and 'version' in line.lower():
                    server_version = line.strip()
                    break
        
        log_to_fsr_logs(f"[DEBUG] Frida client version: {client_version}")
        log_to_fsr_logs(f"[DEBUG] Frida server version: {server_version}")
        
        if client_version != "Unknown" and server_version != "Unknown":
            if client_version != server_version:
                log_to_fsr_logs(f"[WARNING] Version mismatch detected!")
                log_to_fsr_logs(f"[WARNING] Client: {client_version}, Server: {server_version}")
                log_to_fsr_logs(f"[WARNING] This will cause 'system_server' errors")
                
                if client_version != "Unknown":
                    log_to_fsr_logs(f"[DEBUG] Checking if version {client_version} exists on GitHub...")
                    try:
                        check_url = f'https://api.github.com/repos/frida/frida/releases/tags/{client_version}'
                        check_response = requests.get(check_url)
                        if check_response.status_code == 200:
                            log_to_fsr_logs(f"[DEBUG] Version {client_version} is available on GitHub")
                        else:
                            log_to_fsr_logs(f"[WARNING] Version {client_version} not found on GitHub, will use latest")
                    except:
                        log_to_fsr_logs(f"[WARNING] Could not check GitHub for version {client_version}")
        
        return client_version, server_version
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Error checking Frida versions: {e}")
        return "Unknown", "Unknown"

def suggest_frida_fixes(device_id, architecture):
    """Suggest fixes for common Frida issues"""
    client_version, server_version = check_frida_versions()
    
    log_to_fsr_logs(f"[TROUBLESHOOTING] Common Frida fixes to try:")
    log_to_fsr_logs(f"[TROUBLESHOOTING] 1. Restart Frida server with force download (recommended)")
    log_to_fsr_logs(f"[TROUBLESHOOTING] 2. Check if device architecture matches: {architecture}")
    
    if client_version != "Unknown" and server_version != "Unknown":
        if client_version != server_version:
            log_to_fsr_logs(f"[TROUBLESHOOTING] 3. VERSION MISMATCH: Client {client_version} vs Server {server_version}")
            log_to_fsr_logs(f"[TROUBLESHOOTING] 4. Use 'Restart Frida Server' to download matching version")
            
            log_to_fsr_logs(f"[DEBUG] Checking available Frida versions on GitHub...")
            try:
                releases_url = 'https://api.github.com/repos/frida/frida/releases'
                releases_response = requests.get(releases_url)
                if releases_response.status_code == 200:
                    releases = releases_response.json()
                    available_versions = [release['tag_name'] for release in releases[:5]] 
                    log_to_fsr_logs(f"[DEBUG] Recent available versions: {', '.join(available_versions)}")
                    
                    if client_version in available_versions:
                        log_to_fsr_logs(f"[DEBUG] [OK] Version {client_version} is available")
                    else:
                        log_to_fsr_logs(f"[WARNING] [X] Version {client_version} not found in recent releases")
                        log_to_fsr_logs(f"[DEBUG] Will use latest version instead")
            except:
                log_to_fsr_logs(f"[WARNING] Could not check available versions")
        else:
            log_to_fsr_logs(f"[TROUBLESHOOTING] 3. Versions match: {client_version}")
    
    log_to_fsr_logs(f"[TROUBLESHOOTING] 5. Ensure device is rooted and ADB is authorized")
    log_to_fsr_logs(f"[TROUBLESHOOTING] 6. Check if Frida server is running as root user (not shell)")
    log_to_fsr_logs(f"[TROUBLESHOOTING] 7. Try: adb -s {device_id} shell 'pkill -f frida-server'")
    log_to_fsr_logs(f"[TROUBLESHOOTING] 8. Then restart Frida server")
      
# adb status and connect
def run_adb_command(command, timeout=5, retries=1):
    """Run ADB command with retry mechanism and configurable timeout"""
    for attempt in range(retries + 1):
        try:
            log_to_fsr_logs(f"[DEBUG] ADB command attempt {attempt + 1}/{retries + 1}: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout)
            return result.stdout
        except subprocess.TimeoutExpired as e:
            if attempt < retries:
                log_to_fsr_logs(f"[WARNING] ADB command timed out (attempt {attempt + 1}), retrying...")
                import time
                time.sleep(2)  
            else:
                log_to_fsr_logs(f"[ERROR] ADB command timed out after {retries + 1} attempts: {' '.join(command)}")
                raise e
        except subprocess.CalledProcessError as e:
            if attempt < retries:
                log_to_fsr_logs(f"[WARNING] ADB command failed (attempt {attempt + 1}), retrying...")
                import time
                time.sleep(2) 
            else:
                log_to_fsr_logs(f"[ERROR] ADB command failed after {retries + 1} attempts: {' '.join(command)}")
                return f"Error: ADB command failed. {e}"
        except Exception as e:
            log_to_fsr_logs(f"[ERROR] Unexpected error in ADB command: {e}")
            return f"Error: ADB command failed. {e}"
    
    return f"Error: ADB command failed after {retries + 1} attempts"

def run_adb_push_command(device_id, local_path, remote_path, timeout=30, retries=2):
    """Specialized function for ADB push with longer timeout and more retries"""
    command = ["adb", "-s", device_id, "push", local_path, remote_path]
    
    for attempt in range(retries + 1):
        try:
            log_to_fsr_logs(f"[DEBUG] ADB push attempt {attempt + 1}/{retries + 1}: {local_path} -> {remote_path}")
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout)
            log_to_fsr_logs(f"[DEBUG] ADB push successful: {result.stdout.strip()}")
            return result.stdout
        except subprocess.TimeoutExpired as e:
            if attempt < retries:
                log_to_fsr_logs(f"[WARNING] ADB push timed out (attempt {attempt + 1}), retrying in 5 seconds...")
                import time
                time.sleep(5)  # Longer wait for push operations
            else:
                log_to_fsr_logs(f"[ERROR] ADB push timed out after {retries + 1} attempts")
                raise e
        except subprocess.CalledProcessError as e:
            if attempt < retries:
                log_to_fsr_logs(f"[WARNING] ADB push failed (attempt {attempt + 1}), retrying in 5 seconds...")
                import time
                time.sleep(5)
            else:
                log_to_fsr_logs(f"[ERROR] ADB push failed after {retries + 1} attempts: {e.stderr}")
                raise e
        except Exception as e:
            log_to_fsr_logs(f"[ERROR] Unexpected error in ADB push: {e}")
            raise e
    
    raise Exception(f"ADB push failed after {retries + 1} attempts")
    

def run_ideviceinfo(timeout=5):
    try:
        result = subprocess.run(["ideviceinfo"], capture_output=True, text=True, check=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Error: ideviceinfo command timed out."

def get_frida_server_url(architecture, version=None):
    if version:
        url = f'https://api.github.com/repos/frida/frida/releases/tags/{version}'
        log_to_fsr_logs(f"[DEBUG] Requesting specific version: {version}")
    else:
        url = 'https://api.github.com/repos/frida/frida/releases/latest'
        log_to_fsr_logs(f"[DEBUG] Requesting latest version")
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        release_data = response.json()
        
        if version:
            log_to_fsr_logs(f"[DEBUG] Using release: {release_data.get('tag_name', 'Unknown')}")
        else:
            log_to_fsr_logs(f"[DEBUG] Using latest release: {release_data.get('tag_name', 'Unknown')}")
        
        clean_arch = architecture.strip().split('-')[0]
        log_to_fsr_logs(f"[DEBUG] Original architecture: {architecture}")
        log_to_fsr_logs(f"[DEBUG] Cleaned architecture: {clean_arch}")
        
        log_to_fsr_logs(f"[DEBUG] Available frida-server assets:")
        frida_assets = []
        for asset in release_data['assets']:
            if 'frida-server' in asset['name'] and 'android' in asset['name']:
                frida_assets.append(asset['name'])
                log_to_fsr_logs(f"[DEBUG]   - {asset['name']}")
        
        for asset in release_data['assets']:
            if 'frida-server' in asset['name'] and f'android-{clean_arch}' in asset['name']:
                log_to_fsr_logs(f"[+] Found frida-server: {asset['browser_download_url']}")
                return asset['browser_download_url']
        
        log_to_fsr_logs(f"[-] Frida server not found for architecture: {clean_arch}")
        log_to_fsr_logs(f"[-] Available architectures: {', '.join([asset.split('android-')[1].split('-')[0] for asset in frida_assets if 'android-' in asset])}")
        return None
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            log_to_fsr_logs(f"[ERROR] Version {version} not found on GitHub")
            log_to_fsr_logs(f"[DEBUG] Falling back to latest version")
            return get_frida_server_url(architecture, None)
        else:
            log_to_fsr_logs(f"[ERROR] GitHub API error: {e}")
            return None
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Error getting Frida server URL: {e}")
        return None

def frida_server_installed(device_id):
    try:
        timeout = 15 if "emulator" in device_id else 5
        result = run_adb_command(["adb", "-s", device_id, "shell", "ls", "/data/local/tmp/"], timeout=timeout)
        frida_files = [line for line in result.split('\n') if 'frida-server' in line]
        if frida_files:
            log_to_fsr_logs(f"[DEBUG] Found Frida server files on device: {frida_files}")
            return frida_files[0].strip()  
        return False
    except subprocess.CalledProcessError:
        return False

def clean_frida_server_files(device_id):
    """Remove all Frida server files from device"""
    try:
        log_to_fsr_logs(f"[DEBUG] Cleaning all Frida server files from device...")
        
        timeout = 15 if "emulator" in device_id else 5
        result = run_adb_command(["adb", "-s", device_id, "shell", "ls", "/data/local/tmp/"], timeout=timeout)
        frida_files = [line.strip() for line in result.split('\n') if 'frida-server' in line]
        
        if frida_files:
            log_to_fsr_logs(f"[DEBUG] Found {len(frida_files)} Frida server files to remove: {frida_files}")
            
            for file in frida_files:
                try:
                    run_adb_command(["adb", "-s", device_id, "shell", "rm", f"/data/local/tmp/{file}"])
                    log_to_fsr_logs(f"[DEBUG] Removed: {file}")
                except Exception as e:
                    log_to_fsr_logs(f"[WARNING] Failed to remove {file}: {e}")
            
            verify_result = run_adb_command(["adb", "-s", device_id, "shell", "ls", "/data/local/tmp/"])
            remaining_files = [line.strip() for line in verify_result.split('\n') if 'frida-server' in line]
            
            if remaining_files:
                log_to_fsr_logs(f"[WARNING] Some files still remain: {remaining_files}")
            else:
                log_to_fsr_logs(f"[DEBUG] All Frida server files removed successfully")
        else:
            log_to_fsr_logs(f"[DEBUG] No Frida server files found to remove")
            
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Error cleaning Frida server files: {e}")

def is_frida_server_running(device_id):
    try:
        log_to_fsr_logs(f"[DEBUG] Checking if Frida server is running on device: {device_id}")
        
        timeout = 15 if "emulator" in device_id else 5
        
        result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-A"], timeout=timeout)
        if "frida-server" in result:
            log_to_fsr_logs(f"[DEBUG] [OK] Frida server found in process list")
            
            try:
                ps_result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-A"])
                if ps_result:
                    lines = ps_result.strip().split('\n')
                    for line in lines:
                        if 'frida-server' in line and 'frida-server' in line.split()[-1]: 
                            parts = line.split()
                            if len(parts) >= 2:
                                pid = parts[1]
                                if pid.isdigit():
                                    user_result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-o", "user=", "-p", pid])
                                    user = user_result.strip()
                                    log_to_fsr_logs(f"[DEBUG] Frida server PID {pid} running as user: {user}")
                                    if user == "root":
                                        log_to_fsr_logs(f"[DEBUG] [OK] Frida server running as root (correct)")
                                        return True
                                    elif user == "shell":
                                        log_to_fsr_logs(f"[WARNING] [WARN] Frida server running as shell (not ideal but functional)")
                                        return True
                                    else:
                                        log_to_fsr_logs(f"[WARNING] [X] Frida server running as {user} (should be root)")
                                        return False
                                else:
                                    log_to_fsr_logs(f"[WARNING] Invalid PID format: {pid}")
                                    return True  
            except Exception as e:
                log_to_fsr_logs(f"[DEBUG] Could not verify user: {e}, assuming running")
                return True
        else:
            log_to_fsr_logs(f"[DEBUG] [X] Frida server not found in process list")
        
        port_check_commands = [
            ["adb", "-s", device_id, "shell", "netstat", "-tunlp"],
            ["adb", "-s", device_id, "shell", "ss", "-tunlp"],
            ["adb", "-s", device_id, "shell", "cat", "/proc/net/tcp"],
            ["adb", "-s", device_id, "shell", "cat", "/proc/net/tcp6"]
        ]
        
        for cmd in port_check_commands:
            try:
                result = run_adb_command(cmd, timeout=timeout)
                if "27042" in result and "frida" in result:
                    log_to_fsr_logs(f"[DEBUG] [OK] Frida server found listening on port 27042 using {cmd[-1]}")
                    return True
            except:
                continue
        
        log_to_fsr_logs(f"[DEBUG] [X] Frida server not listening on port 27042")
        
        log_to_fsr_logs(f"[DEBUG] [X] Frida server not detected by process list or port check")
        log_to_fsr_logs(f"[DEBUG] [X] Server is NOT running (ignoring frida-ps results)")
        return False
        
    except subprocess.CalledProcessError as e:
        log_to_fsr_logs(f"[ERROR] Error checking Frida server status: {e}")
        return False
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Unexpected error checking Frida server status: {e}")
        return False

def download_and_push_frida(architecture, os_type, version=None):
    frida_server_path = os.path.join(f"./frida-server/{os_type}", "frida-server")
    
    should_download = True
    if os.path.isfile(frida_server_path) and version is None:
        try:
            latest_url = get_frida_server_url(architecture, None)
            if latest_url:
                import re
                version_match = re.search(r'frida-server-(\d+\.\d+\.\d+)', latest_url)
                if version_match:
                    latest_version = version_match.group(1)
                    print(f"[i] Latest Frida version available: {latest_version}")
                    
                    import time
                    file_age = time.time() - os.path.getmtime(frida_server_path)
                    if file_age < 86400:  
                        print(f"[=] Frida server for {os_type} exists and is recent (< 24h), skipping download.")
                        print(f"[i] To force download latest version, use: --runw {os_type} {latest_version} or --runw {os_type} --force-download")
                        should_download = False
                    else:
                        print(f"[i] Frida server for {os_type} is older than 24h, downloading latest version...")
        except Exception as e:
            print(f"[w] Could not check latest version: {e}")
            should_download = True
    
    if should_download:
        os.makedirs(f"./frida-server/{os_type}", exist_ok=True)
        frida_url = get_frida_server_url(architecture, version)
        
        if frida_url is None:
            print(f"Error: No Frida server URL found for architecture: {architecture}")
            return

        download_path = os.path.join(f"frida-server/{os_type}", "frida-server-download.xz")
        print(f"[+] Downloading Frida server from: {frida_url}")
        wget.download(frida_url, download_path)
        
        with lzma.open(download_path) as src, open(frida_server_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)
        
        if os.path.exists(download_path):
            os.remove(download_path)
        
        print(f"\n[+] Downloaded and extracted frida-server for {os_type}")
    else:
        print(f"[=] Using existing Frida server for {os_type}")

    adb_check = there_is_adb_and_devices()
    if adb_check["is_true"]:
        device_id = f"{adb_check['available_devices'][0].get('device_id')}" 

        if not frida_server_installed(device_id):
            rootboot = run_adb_command(["adb", "-s", device_id, "root"])
            run_adb_command(["adb", "-s", device_id, "push", frida_server_path, "/data/local/tmp"])
            run_adb_command(["adb", "-s", device_id, "shell", "chmod", "755", "/data/local/tmp/frida-server"])
        
        if not is_frida_server_running(device_id):
            rootboot = run_adb_command(["adb", "-s", device_id, "root"])
            run_adb_command(["adb", "-s", device_id, "shell", "/data/local/tmp/frida-server", "&"])
        
        print(f"Started frida-server for {os_type}")

def export_address_port_win(version=None):
    current_ip = os.getenv('ANDROID_ADB_SERVER_ADDRESS')
    current_port = os.getenv('ANDROID_ADB_SERVER_PORT')

    if current_ip and current_port:
        print(f"Environment variables already set:\n"
              f"ANDROID_ADB_SERVER_ADDRESS: {current_ip}\n"
              f"ANDROID_ADB_SERVER_PORT: {current_port}")
        return

    print(f"\n[WARNING] You are running in WSL, setting up ADB over network...\n")

    ip = input("Enter the IP address: ")
    port = input("Enter the port number: ")

    os.environ['ANDROID_ADB_SERVER_PORT'] = port
    os.environ['ANDROID_ADB_SERVER_ADDRESS'] = ip

    print(f"\nANDROID_ADB_SERVER_PORT: {os.getenv('ANDROID_ADB_SERVER_PORT')}")
    print(f"ANDROID_ADB_SERVER_ADDRESS: {os.getenv('ANDROID_ADB_SERVER_ADDRESS')}")

    verify_command = 'echo $ANDROID_ADB_SERVER_PORT && echo $ANDROID_ADB_SERVER_ADDRESS'
    result = subprocess.run(verify_command, shell=True, text=True, capture_output=True)
    print("\nVerification Output:\n", result.stdout)

    result2 = run_adb_command(["adb", "devices"])
    print("\nVerification Output:\n", result2)

    adb_check = there_is_adb_and_devices()
    if adb_check["is_true"] and adb_check['available_devices']:
        device_id = adb_check['available_devices'][0].get('device_id') 
        if device_id:
            architecture = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"])
            download_and_push_frida(architecture, "wsl", version)
        else:
            print(f"[-] No device ID found for WSL")
    else:
        print(f"[-] No Android devices connected for WSL")

def push_and_run_fs(runw_args):
    os_type = runw_args[0]
    version = None
    
    if len(runw_args) > 1:
        if runw_args[1] == "--force-download":
            version = None  
        else:
            version = runw_args[1]

    if os_type == "wsl":
        export_address_port_win(version)
    else:
        adb_check = there_is_adb_and_devices()
        if adb_check["is_true"] and adb_check['available_devices']:
            device_id = adb_check['available_devices'][0].get('device_id') 
            if device_id:
                architecture = run_adb_command(["adb","-s", device_id, "shell", "getprop", "ro.product.cpu.abi"])
                download_and_push_frida(architecture, os_type, version)
            else:
                print(f"[-] No device ID found for {os_type}")
        else:
            print(f"[-] No Android devices connected for {os_type}")
    
def there_is_adb_and_devices():
    adb_is_active = False
    available_devices = []
    message = ""

    try:
        result = run_adb_command(["adb", "devices"])
        connected_devices = result.strip().split('\n')[1:]
        device_ids = [line.split('\t')[0] for line in connected_devices if line.strip()]

        if device_ids:
            for device_id in device_ids:
                model = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.model"])
                serial_number = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.serialno"])
                versi_andro = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"])
                available_devices.append({"device_id": device_id, "model": model, "serial_number": serial_number, "versi_andro": versi_andro})
            adb_is_active = True
            message = "Device is available"
    except Exception as e:
        message = f"Error checking Android device connectivity: {e}"
    else:
        try:
            ideviceinfo_output = run_ideviceinfo()
            if ideviceinfo_output:
                adb_is_active = True

                deviceId = re.search(r'UniqueDeviceID:\s*([a-zA-Z0-9]+)', ideviceinfo_output)
                model = re.search(r'ProductType:\s*([\w\d,]+)', ideviceinfo_output)
                if deviceId and model:
                    available_devices.append({"model": model.group(1).strip(),  "UDID": deviceId.group(1).strip()})
                    message = "iOS device is available"
        except Exception as e:
            message = f"Error checking iOS device connectivity: {e}"

    return {"is_true": adb_is_active, "available_devices": available_devices, "message": message}

def get_package_identifiers():
    try:
        log_to_fsr_logs(f"[DEBUG] Getting package identifiers using frida-ps...")
        result = subprocess.run(['frida-ps', '-Uai'], capture_output=True, text=True, timeout=10)
        
        if result.stderr:
            log_to_fsr_logs(f"[DEBUG] frida-ps stderr: {result.stderr.strip()}")
        
        if result.stderr and "system_server" in result.stderr:
            log_to_fsr_logs(f"[ERROR] Frida system_server error: {result.stderr.strip()}")
            log_to_fsr_logs(f"[DEBUG] This usually indicates version mismatch or architecture issues")
            return []
        
        if result.stderr and "Failed to enumerate" in result.stderr:
            log_to_fsr_logs(f"[ERROR] Frida enumeration failed: {result.stderr.strip()}")
            return []
        
        if result.returncode != 0:
            log_to_fsr_logs(f"[ERROR] frida-ps failed with return code {result.returncode}")
            if result.stderr:
                log_to_fsr_logs(f"[ERROR] Full stderr: {result.stderr}")
            return []
        
        lines = result.stdout.strip().split('\n')[1:]
        identifiers = [line.split()[1] + " - " + line.split()[-1]  for line in lines if len(line.split()) >= 3]
        log_to_fsr_logs(f"[DEBUG] Found {len(identifiers)} packages")
        return identifiers
    except subprocess.TimeoutExpired:
        log_to_fsr_logs(f"[ERROR] frida-ps command timed out")
        return []
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Error getting package identifiers: {e}")
        return []

def get_bypass_scripts():
    list_script = json.load(open("static/data/script.json","r"))["scripts"]
    IOS = []
    ANDROID = []
    for item in list_script:
        k = [i for i in item.keys()][0]
        if item[k]["category"] == "IOS":
            IOS.append(item[k])
        else:
            ANDROID.append(item[k])
    return ANDROID, IOS


def get_script_content(script_path):
    try:
        with open(script_path, 'r') as file:
            content = file.read()
        return content
    except Exception as e:
        return str(e), 500

@app.route('/get-script-content')
def get_script_content_route():
    script_name = request.args.get('script')
    script_path = os.path.join(SCRIPTS_DIRECTORY, script_name)
    content = get_script_content(script_path)
    return content


@app.route('/')
def index():
    device_type = get_device_type()
    adb_check = there_is_adb_and_devices()
    if adb_check["is_true"]:
        try:
            bypass_scripts_1, bypass_scripts_2 = get_bypass_scripts()
            
            frida_status = {}
            if adb_check["available_devices"]:
                for device in adb_check["available_devices"]:
                    if "device_id" in device: 
                        device_id = device["device_id"]
                        installed_status = frida_server_installed(device_id)
                        frida_status[device_id] = {
                            "installed": bool(installed_status),
                            "frida_server_name": installed_status if installed_status else None,
                            "running": is_frida_server_running(device_id),
                            "device_info": device
                        }
                    elif "UDID" in device:  # iOS device
                        frida_status[device["UDID"]] = {
                            "installed": True,  
                            "frida_server_name": None,
                            "running": True,    
                            "device_info": device
                        }
            
            return render_template('index.html', 
                                identifiers=[], 
                                bypass_scripts_android=bypass_scripts_1, 
                                bypass_scripts_ios=bypass_scripts_2,
                                devices=adb_check,
                                connected_device=adb_check["available_devices"],
                                frida_status=frida_status)

        except Exception as e:
            return render_template('index.html', error=f"Error: {e}")
    else:
        return render_template('no-usb.html')

@app.route('/features', methods=['GET'])
def features():
    search_query = request.args.get('search', '').strip().lower()
    device_info = there_is_adb_and_devices()
    packages = []
    identifiers = []
    message = None

    if not device_info['is_true']:
        return render_template('no-usb.html', message=device_info['message'])

    if device_info['available_devices'] and any('versi_andro' in dev for dev in device_info['available_devices']):
        try:
            packages_output = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages']).decode('utf-8')
            packages = [pkg.split(':')[1].strip() for pkg in packages_output.split('\n') if pkg]
        except subprocess.CalledProcessError as e:
            message = f"Failed to get Android packages: {e}"
            
    if device_info['available_devices'] and any('UDID' in dev for dev in device_info['available_devices']):
        try:
            identifiers = get_package_identifiers()
        except Exception as e:
            message = f"Error getting iOS packages: {e}"

    if search_query:
        packages = [pkg for pkg in packages if search_query in pkg.lower()]
        identifiers = [idf for idf in identifiers if search_query in idf.lower()]

    return render_template('features.html',packages=packages,identifiers=identifiers,message=message,devices=device_info['available_devices'])

#mobile fucking proxyyyyyyyyyyyyyyyyy
@app.route('/mobile-proxy', methods=['GET'])
def mobile_proxy_page():
    """
    Render Mobile Proxy page for managing Android global HTTP proxy.
    """
    current_proxy = get_current_mobile_proxy()
    return render_template('mobile-proxy.html', current_proxy=current_proxy)


@app.route('/mobile-proxy/set', methods=['POST'])
def mobile_proxy_set():
    """
    Set Android global HTTP proxy using provided IP and port.
    """
    data = request.get_json(silent=True) or request.form
    ip = (data.get('ip') or '').strip()
    port = (str(data.get('port') or '')).strip()

    if not ip or not port:
        return jsonify({'success': False, 'error': 'IP and Port are required'}), 400

    try:
        port_int = int(port)
        if port_int < 1 or port_int > 65535:
            raise ValueError()
    except ValueError:
        return jsonify({'success': False, 'error': 'Port must be a number between 1 and 65535'}), 400

    result = set_mobile_proxy(ip, port)
    if result.get('success'):
        return jsonify({'success': True,'proxy': result.get('proxy'),'message': f"Proxy set to {result.get('proxy')}",})
    else:
        return jsonify({'success': False,'error': result.get('error') or 'Failed to set proxy',
}), 500


@app.route('/mobile-proxy/unset', methods=['POST'])
def mobile_proxy_unset():
    """
    Clear Android global HTTP proxy (sets it to :0).
    """
    result = unset_mobile_proxy()
    if result.get('success'):
        return jsonify({'success': True,'proxy': result.get('proxy'),'message': "Proxy unset (set to :0)",})
    else:
        return jsonify({'success': False,'error': result.get('error') or 'Failed to unset proxy',}), 500


@app.route('/mobile-proxy/ips', methods=['GET'])
def mobile_proxy_ips():
    """
    Return list of local IP addresses (from ifconfig/ipconfig) for proxy selection.
    """
    result = get_local_proxy_ips()
    status = 200 if result.get("success") else 500
    return jsonify(result), status

#apk downloader
@app.route('/apk-download', methods=['POST'])
def apk_download():
    package_name = request.form.get('package')
    custom_name = request.form.get('custom_name', '').strip()
    
    if not package_name:
        return "No package selected", 400

    try:
        os.makedirs('tmp', exist_ok=True)
        
        apk_paths = subprocess.check_output(
            f"adb shell pm path {package_name}",
            shell=True,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        if not apk_paths:
            return "Failed to get APK path", 500

        apk_path = apk_paths.strip().split('\n')[0].split(':')[1]
        safe_package = re.sub(r'[^a-zA-Z0-9_.-]', '_', package_name) 
        
        if custom_name:
            custom_name = re.sub(r'\.apk$', '', custom_name, flags=re.IGNORECASE)
            apk_filename = f"{custom_name}.apk"
        else:
            apk_filename = f"{safe_package}.apk"
            
        temp_apk = os.path.join('tmp', apk_filename)
        
        pull_result = subprocess.run(
            f"adb pull {apk_path} {temp_apk}",
            shell=True,
            capture_output=True,
            text=True
        )

        if pull_result.returncode != 0:
            return f"Failed to pull APK: {pull_result.stderr}", 500

        return send_file(
            temp_apk,
            as_attachment=True,
            download_name=apk_filename
        )

    except Exception as e:
        return f"Error: {str(e)}", 500
    finally:
        if 'temp_apk' in locals() and os.path.exists(temp_apk):
            os.remove(temp_apk)
            
# install apk
@app.route('/install-apk', methods=['POST'])
def install_apk():
    if 'apkFile' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['apkFile']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not file.filename.endswith('.apk'):
        return jsonify({'error': 'Only APK files are allowed'}), 400
    
    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        try:
            subprocess.run(['adb', 'version'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return jsonify({'error': 'ADB is not available or not working'}), 500
        
        result = subprocess.run(
            ['adb', 'install', '-r', filepath],
            capture_output=True,
            text=True,
            timeout=300 
        )
        
        if 'Success' in result.stdout:
            return jsonify({
                'success': True,
                'message': 'Installation successful',
                'output': result.stdout
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Installation failed',
                'error': result.stderr or result.stdout
            }), 500
            
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500
    finally:
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)

@app.route('/dump-ipa', methods=['POST'])
def dump_ipa():
    ipa_name = request.form.get('ipa_name')
    password = request.form.get('password')
    host = request.form.get('host')
    port = request.form.get('port')
    package = request.form.get('package')

    if not all([ipa_name, password, host, port, package]):
        return "Missing required fields!", 400

    try:
        tmp_dir = f"{os.getcwd()}/tmp"
        os.makedirs(tmp_dir, exist_ok=True)

        command = [
            "python3", "dump.py",
            "-o", f"{os.getcwd()}/tmp/{ipa_name}.ipa",
            "-P", password,
            "-H", host,
            "-p", port, package
        ]
        print(f"Running command: {' '.join(command)}")
        subprocess.run(command, check=True)

        ipa_file_path = f"{ipa_name}.ipa"

        if os.path.exists(ipa_file_path):
            return send_file(ipa_file_path, as_attachment=True)
        else:
            sukses = f"IPA berhasil diunduh di path: {os.getcwd()}/tmp/{ipa_file_path}"
            return jsonify({"message": sukses}), 200

    except subprocess.CalledProcessError as e:
        return f"Dump process failed: {e}", 500
    except Exception as e:
        return f"Unexpected error: {e}", 500

@app.route('/get-device-packages')
def get_device_packages():
    devices = there_is_adb_and_devices()
    android_packages = []
    ios_identifiers = []
    
    if devices["is_true"]:
        for device in devices["available_devices"]:
            if "serial_number" in device:
                android_packages = subprocess.check_output(
                    ['adb', 'shell', 'pm', 'list', 'packages']
                ).decode('utf-8').splitlines()
                android_packages = [pkg.split(':')[1] for pkg in android_packages]
            else: 
                ios_identifiers = get_package_identifiers()
    
    return jsonify({
        "android_packages": android_packages,
        "ios_identifiers": ios_identifiers,
        "connected_devices": devices["available_devices"]
    })

@app.route('/get-packages')
def get_packages():
    """Get packages when Frida server is running"""
    try:
        adb_check = there_is_adb_and_devices()
        if not adb_check["is_true"]:
            return jsonify({"error": "No devices connected"}), 400
        
        client_version, server_version = check_frida_versions()
        
        log_to_fsr_logs(f"[DEBUG] Attempting to get packages...")
        identifiers = get_package_identifiers()
        
        if identifiers and len(identifiers) > 0:
            return jsonify({
                "success": True,
                "packages": identifiers
            })
        else:
            frida_running = False
            device_type = "unknown"
            
            for device in adb_check["available_devices"]:
                if "device_id" in device:  # Android device
                    device_type = "android"
                    if is_frida_server_running(device["device_id"]):
                        frida_running = True
                        break
                elif "UDID" in device:  # iOS device
                    device_type = "ios"
                    frida_running = True
                    break
            
            if not frida_running:
                if device_type == "android":
                    return jsonify({"error": "Frida server is not running. Please start Frida server first."}), 400
                else:
                    return jsonify({"error": "Unable to connect to device. Please check device connection."}), 400
            else:
                if device_type == "android":
                    device_info = adb_check["available_devices"][0]
                    if "device_id" in device_info:
                        architecture = run_adb_command(["adb", "-s", device_info["device_id"], "shell", "getprop", "ro.product.cpu.abi"])
                        clean_arch = architecture.strip().split('-')[0]
                        suggest_frida_fixes(device_info["device_id"], clean_arch)
                    return jsonify({"error": "Frida server is running but no packages found. Check FSR Logs for troubleshooting tips."}), 400
                else:
                    return jsonify({"error": "iOS device connected but no packages found. Make sure device is properly connected."}), 400
        
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Exception in get_packages: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/run-frida', methods=['POST'])
def run_frida():
    global process, current_script_path

    try:
        package = request.form['package']
        if not 'use_custom_script' in request.form.keys():
            use_custom_script = False
        else:
                use_custom_script = int(request.form['use_custom_script']) == 1

        selected_script = request.form['selected_script']
        script_content = request.form['script_content']

        is_auto_generated = (selected_script == "auto_generate")
        
        if use_custom_script or is_auto_generated:
            script_name = hashlib.sha256(script_content.encode()).hexdigest() + ".js"
            script_path = os.path.join("tmp", script_name)
            
            with open(script_path, 'w') as file:
                file.write(script_content)
            
            if is_auto_generated:
                log_to_fsr_logs(f"[DEBUG] Using AI-generated script: {script_name}")
                selected_script = f"AI-Generated-{script_name}"
            else:
                log_to_fsr_logs(f"[DEBUG] Using custom script: {script_name}")
                selected_script = script_name
        else:
            script_path = os.path.join(SCRIPTS_DIRECTORY, selected_script)

        current_script_path = os.path.abspath(script_path)

        if process and process.poll() is None:
            process.terminate()

        socketio.start_background_task(run_frida_with_socketio, script_path, package)


        return jsonify({"result": f'Successfully started Frida on {package} using {selected_script}'}), 200
    except KeyboardInterrupt:
        return jsonify({"error": "Frida process interrupted by user."}), 500
    except Exception as e:
        return jsonify({"error": f"Error: {e}"}), 500

    
def run_frida_with_socketio(script_path, package):
    global process, frida_output_buffer

    try:
        frida_output_buffer = []
        
        command = ["frida", "-l", script_path, "-U", "-f", package]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
        
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                output_clean = output.replace('\n','')
                frida_output_buffer.append(output_clean)
                
                if len(frida_output_buffer) > 100:
                    frida_output_buffer = frida_output_buffer[-100:]
                
                if args.verbose:
                    print(output_clean)
                socketio.emit("output", {"data": output})
                time.sleep(0.010)

        socketio.emit("output", {"data": "Frida process finished."})
    except KeyboardInterrupt:
        socketio.emit("output", {"data": "Frida process interrupted by user."})
    except Exception as e:
        socketio.emit("output", {"data": f"Error: {e}"})

@socketio.on("connect")
def handle_connect():
    socketio.emit('connected', 'connected')

@app.route('/stop-frida')
def stop_frida():
    global process

    if process and process.poll() is None:
        process.kill()
        process.wait() 
        return 'Frida process stopped', 200
    else:
        return 'Frida process is not running', 200

@app.route('/fix-script', methods=['POST'])
def fix_script():
    """Manually fix the currently running script using AI"""
    global process, frida_output_buffer, current_script_path
    
    try:
        if current_script_path and os.path.exists(current_script_path):
            script_path_to_fix = current_script_path
        elif os.path.exists(TEMP_SCRIPT_PATH):
            script_path_to_fix = os.path.abspath(TEMP_SCRIPT_PATH)
        else:
            return jsonify({"error": "No script available to fix. Generate a script first."}), 400

        if not process or process.poll() is not None:
            log_to_fsr_logs("[MANUAL-FIX] No active Frida process detected; proceeding with offline fix using saved script.")
        else:
            log_to_fsr_logs("[MANUAL-FIX] Active Frida process detected; will terminate after fix.")

        log_to_fsr_logs("[MANUAL-FIX] Manual script fix requested")
        socketio.emit("output", {"data": "\n[MANUAL-FIX] Manual script fix requested, analyzing errors...\n"})

        error_messages = []
        for line in frida_output_buffer:
            if any(error_keyword in line.lower() for error_keyword in [
                'error:', 'exception', 'failed', 'invalid instruction', 'segmentation fault',
                'rpc error', 'unable to load script', 'syntax error', 'reference error',
                'type error', 'range error'
            ]):
                error_messages.append(line)
        
        if not error_messages:
            error_messages = ["No specific errors detected - general script fixing requested"]
        
        fixed_script = attempt_script_autofix(script_path_to_fix, error_messages, frida_output_buffer[-20:])
        
        if fixed_script:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

            with open(script_path_to_fix, 'w', encoding='utf-8') as f:
                f.write(fixed_script)

            if script_path_to_fix == os.path.abspath(TEMP_SCRIPT_PATH):
                current_script_path = script_path_to_fix

            write_temp_generated_script(fixed_script)

            socketio.emit("output", {"data": "[MANUAL-FIX] Generated fixed script, updating UI...\n"})
            log_to_fsr_logs("[MANUAL-FIX] Successfully generated and applied fixed script")

            return jsonify({
                "success": True, 
                "message": "Script fixed successfully. Updated script content - please restart manually.",
                "fixed_script": fixed_script
            }), 200
        else:
            socketio.emit("output", {"data": "[MANUAL-FIX] Could not generate fixed script. Please check manually.\n"})
            return jsonify({"error": "Could not generate fixed script"}), 500
            
    except Exception as e:
        log_to_fsr_logs(f"[MANUAL-FIX] Exception in manual fix: {str(e)}")
        return jsonify({"error": f"Fix failed: {str(e)}"}), 500

@app.route('/frida-server-status')
def frida_server_status():
    """Get Frida server status for all connected devices"""
    try:
        adb_check = there_is_adb_and_devices()
        if not adb_check["is_true"]:
            return jsonify({"error": "No devices connected"}), 400
        
        status_info = {}
        for device in adb_check["available_devices"]:
            if "device_id" in device:  # Android device
                device_id = device["device_id"]
                log_to_fsr_logs(f"[DEBUG] Checking status for Android device: {device_id}")
                installed_status = frida_server_installed(device_id)
                running_status = is_frida_server_running(device_id)
                
                status_info[device_id] = {
                    "installed": bool(installed_status),  
                    "frida_server_name": installed_status if installed_status else None,
                    "running": running_status,
                    "device_info": device
                }
                
                log_to_fsr_logs(f"[DEBUG] Device {device_id} status - Installed: {bool(installed_status)}, Running: {running_status}")
                
            elif "UDID" in device:  # iOS device
                log_to_fsr_logs(f"[DEBUG] Checking status for iOS device: {device['UDID']}")
                status_info[device["UDID"]] = {
                    "installed": True,
                    "frida_server_name": None,
                    "running": True,
                    "device_info": device
                }
        
        log_to_fsr_logs(f"[DEBUG] Final status info: {status_info}")
        return jsonify(status_info)
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Exception in frida_server_status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/force-refresh-status', methods=['POST'])
def force_refresh_status():
    """Force refresh Frida server status"""
    try:
        log_to_fsr_logs(f"[DEBUG] Force refresh status requested")
        return frida_server_status()
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Exception in force_refresh_status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/check-device-status')
def check_device_status():
    """Check USB/device connection status for dynamic scanning"""
    try:
        adb_check = there_is_adb_and_devices()
        devices_info = []
        
        if adb_check["is_true"] and adb_check["available_devices"]:
            for device in adb_check["available_devices"]:
                device_info = {
                    "connected": True,
                    "type": "Android" if "device_id" in device else "iOS"
                }
                
                if "device_id" in device:
                    device_info.update({
                        "model": device.get("model", "Unknown"),
                        "serial_number": device.get("serial_number", "N/A"),
                        "android_version": device.get("versi_andro", "N/A"),
                        "device_id": device.get("device_id", "")
                    })
                elif "UDID" in device:
                    device_info.update({
                        "model": device.get("model", "Unknown"),
                        "udid": device.get("UDID", ""),
                    })
                
                devices_info.append(device_info)
        
        return jsonify({
            "connected": adb_check["is_true"],
            "device_count": len(devices_info),
            "devices": devices_info,
            "message": adb_check.get("message", "")
        })
    except Exception as e:
        return jsonify({
            "connected": False,
            "device_count": 0,
            "devices": [],
            "message": f"Error checking device status: {str(e)}"
        }), 500

@app.route('/start-frida-server', methods=['POST'])
def start_frida_server():
    """Start Frida server on connected devices"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        force_download = data.get('force_download', False)
        
        log_to_fsr_logs(f"[DEBUG] Starting Frida server for device: {device_id}")
        log_to_fsr_logs(f"[DEBUG] Force download: {force_download}")
        
        if not device_id:
            return jsonify({"error": "Device ID is required"}), 400
        
        adb_check = there_is_adb_and_devices()
        if not adb_check["is_true"]:
            return jsonify({"error": "No devices connected"}), 400
        
        target_device = None
        for device in adb_check["available_devices"]:
            if device.get("device_id") == device_id or device.get("UDID") == device_id:
                target_device = device
                break
        
        if not target_device:
            return jsonify({"error": "Device not found"}), 400
        
        log_to_fsr_logs(f"[DEBUG] Target device: {target_device}")
        
        platform = get_device_platform(target_device)
        log_to_fsr_logs(f"[DEBUG] Device platform: {platform}")

        if "device_id" in target_device:
            device_id = target_device["device_id"]
            architecture = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"])
            
            clean_arch = architecture.strip().split('-')[0]
            log_to_fsr_logs(f"[DEBUG] Device architecture: {architecture}")
            log_to_fsr_logs(f"[DEBUG] Cleaned architecture: {clean_arch}")
            
            log_to_fsr_logs(f"[DEBUG] Checking for existing Frida server on device...")
            existing_frida = frida_server_installed(device_id)
            
            if existing_frida:
                log_to_fsr_logs(f"[DEBUG] Found existing Frida server: {existing_frida}")
                frida_server_name = existing_frida
                should_download = False
            else:
                log_to_fsr_logs(f"[DEBUG] No existing Frida server found on device, will download")
                frida_server_name = "frida-server"
                should_download = True
                
                frida_server_path = os.path.join(f"./frida-server/android", "frida-server")
                if os.path.isfile(frida_server_path) and not force_download:
                    try:
                        latest_url = get_frida_server_url(clean_arch, None)
                        if latest_url:
                            import re
                            version_match = re.search(r'frida-server-(\d+\.\d+\.\d+)', latest_url)
                            if version_match:
                                latest_version = version_match.group(1)
                                import time
                                file_age = time.time() - os.path.getmtime(frida_server_path)
                                if file_age < 86400:  
                                    should_download = False
                                    log_to_fsr_logs(f"[DEBUG] Using existing local Frida server (less than 24h old)")
                    except Exception as e:
                        should_download = True
            
            if should_download:
                log_to_fsr_logs(f"[DEBUG] Downloading Frida server for architecture: {clean_arch}")
                os.makedirs(f"./frida-server/android", exist_ok=True)
                frida_url = get_frida_server_url(clean_arch, None)
                
                if frida_url is None:
                    return jsonify({"error": f"No Frida server URL found for architecture: {clean_arch}"}), 500

                download_path = os.path.join(f"frida-server/android", "frida-server-download.xz")
                log_to_fsr_logs(f"[DEBUG] Downloading from: {frida_url}")
                log_to_fsr_logs(f"[DEBUG] Saving to: {download_path}")
                wget.download(frida_url, download_path)
                
                with lzma.open(download_path) as src, open(frida_server_path, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                
                if os.path.exists(download_path):
                    os.remove(download_path)
                
                log_to_fsr_logs(f"[DEBUG] Pushing Frida server to device...")
                run_adb_command(["adb", "-s", device_id, "root"])
                
                try:
                    run_adb_push_command(device_id, frida_server_path, f"/data/local/tmp/{frida_server_name}")
                    run_adb_command(["adb", "-s", device_id, "shell", "chmod", "755", f"/data/local/tmp/{frida_server_name}"])
                    log_to_fsr_logs(f"[DEBUG] Frida server pushed and chmod successfully")
                except Exception as e:
                    log_to_fsr_logs(f"[ERROR] Failed to push Frida server: {e}")
                    return jsonify({"error": f"Failed to push Frida server to device: {str(e)}"}), 500
            else:
                log_to_fsr_logs(f"[DEBUG] Using existing Frida server: {frida_server_name}")
            
            log_to_fsr_logs(f"[DEBUG] Checking if Frida server is running...")
            server_running = is_frida_server_running(device_id)
            
            if server_running:
                try:
                    ps_result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-A"])
                    if ps_result:
                        lines = ps_result.strip().split('\n')
                        for line in lines:
                            if 'frida-server' in line and 'frida-server' in line.split()[-1]:
                                parts = line.split()
                                if len(parts) >= 2:
                                    pid = parts[1]
                                    if pid.isdigit():
                                        user_result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-o", "user=", "-p", pid])
                                        user = user_result.strip()
                                        if user == "shell":
                                            log_to_fsr_logs(f"[DEBUG] Server running as shell, restarting as root...")
                                            run_adb_command(["adb", "-s", device_id, "shell", "kill", pid])
                                            time.sleep(2)
                                            server_running = False
                                            break
                except:
                    pass
            
            if not server_running:
                log_to_fsr_logs(f"[DEBUG] Starting Frida server in root shell...")
                run_adb_command(["adb", "-s", device_id, "root"])
                
                try:
                    log_to_fsr_logs(f"[DEBUG] Method 1: Starting with su command...")
                    subprocess.run(["adb", "-s", device_id, "shell", "su", "-c", f"/data/local/tmp/{frida_server_name} &"], 
                                 timeout=10, capture_output=True)
                    log_to_fsr_logs(f"[DEBUG] su command executed")
                    
                    import time
                    time.sleep(3)
                    
                    if is_frida_server_running(device_id):
                        log_to_fsr_logs(f"[DEBUG] [OK] Frida server started successfully as root")
                    else:
                        log_to_fsr_logs(f"[DEBUG] su method failed, trying alternative...")
                        
                        try:
                            log_to_fsr_logs(f"[DEBUG] Method 2: Starting with direct root shell...")
                            subprocess.run(["adb", "-s", device_id, "shell", "su", "root", f"/data/local/tmp/{frida_server_name} &"], 
                                         timeout=10, capture_output=True)
                            log_to_fsr_logs(f"[DEBUG] su root command executed")
                            time.sleep(3)
                            
                            if is_frida_server_running(device_id):
                                log_to_fsr_logs(f"[DEBUG] [OK] Frida server started successfully with su root")
                            else:
                                log_to_fsr_logs(f"[DEBUG] su root method failed, trying basic method...")
                                
                                subprocess.run(["adb", "-s", device_id, "shell", f"/data/local/tmp/{frida_server_name} &"], 
                                             timeout=10, capture_output=True)
                                log_to_fsr_logs(f"[DEBUG] Basic method executed")
                                time.sleep(3)
                                
                                if is_frida_server_running(device_id):
                                    log_to_fsr_logs(f"[DEBUG] [OK] Frida server started with basic method")
                                else:
                                    log_to_fsr_logs(f"[WARNING] All start methods failed")
                                    
                        except subprocess.TimeoutExpired:
                            log_to_fsr_logs(f"[DEBUG] su root method timed out")
                        except Exception as e:
                            log_to_fsr_logs(f"[ERROR] Error with su root method: {e}")
                        
                except subprocess.TimeoutExpired:
                    log_to_fsr_logs(f"[DEBUG] su method timed out")
                except Exception as e:
                    log_to_fsr_logs(f"[ERROR] Error with su method: {e}")
            else:
                log_to_fsr_logs(f"[DEBUG] Frida server already running")
            
            return jsonify({
                "success": True,
                "message": f"Frida server started successfully on {target_device.get('model', 'Android device')}",
                "device_id": device_id,
                "frida_server_name": frida_server_name,
                "platform": "android"
            })
        
        else:
            log_to_fsr_logs(f"[DEBUG] iOS device detected - no Frida server installation needed")
            return jsonify({
                "success": True,
                "message": "iOS devices don't require Frida server installation",
                "device_id": device_id,
                "platform": "ios"
            })
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/stop-frida-server', methods=['POST'])
def stop_frida_server():
    """Stop Frida server on connected devices"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        
        if not device_id:
            return jsonify({"error": "Device ID is required"}), 400
        
        log_to_fsr_logs(f"[DEBUG] Stopping Frida server for device: {device_id}")
        
        try:
            run_adb_command(["adb", "-s", device_id, "shell", "pkill", "-f", "frida-server"])
            log_to_fsr_logs(f"[DEBUG] pkill command executed")
            
            import time
            time.sleep(2)
            
            if is_frida_server_running(device_id):
                log_to_fsr_logs(f"[DEBUG] Server still running, trying killall")
                run_adb_command(["adb", "-s", device_id, "shell", "killall", "frida-server"])
                time.sleep(1)
            
            if is_frida_server_running(device_id):
                log_to_fsr_logs(f"[DEBUG] Frida server still running, trying PID-based kill in root shell")
                ps_result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-A"])
                if ps_result:
                    lines = ps_result.strip().split('\n')
                    for line in lines:
                        if 'frida-server' in line and 'frida-server' in line.split()[-1]:  
                            parts = line.split()
                            if len(parts) >= 2:
                                pid = parts[1]
                                if pid.isdigit():
                                    log_to_fsr_logs(f"[DEBUG] Found frida-server PID: {pid}, killing in root shell")
                                    run_adb_command(["adb", "-s", device_id, "root"])
                                    run_adb_command(["adb", "-s", device_id, "shell", "su", "-c", f"kill -9 {pid}"])
                                    log_to_fsr_logs(f"[DEBUG] Sent kill -9 {pid} to frida-server in root shell")
                                    break
            
            if is_frida_server_running(device_id):
                log_to_fsr_logs(f"[WARNING] Frida server may still be running")
                return jsonify({
                    "success": False,
                    "message": "Frida server may still be running",
                    "device_id": device_id
                }), 500
            else:
                log_to_fsr_logs(f"[DEBUG] Frida server stopped successfully")
                return jsonify({
                    "success": True,
                    "message": "Frida server stopped successfully",
                    "device_id": device_id
                })
                
        except Exception as e:
            log_to_fsr_logs(f"[ERROR] Error stopping Frida server: {e}")
            return jsonify({"error": f"Failed to stop Frida server: {str(e)}"}), 500
            
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Exception in stop_frida_server: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/restart-frida-server', methods=['POST'])
def restart_frida_server():
    """Restart Frida server with force download"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        
        if not device_id:
            return jsonify({"error": "Device ID is required"}), 400
        
        log_to_fsr_logs(f"[DEBUG] Restarting Frida server with force download for device: {device_id}")
        
        try:
            run_adb_command(["adb", "-s", device_id, "shell", "pkill", "-f", "frida-server"])
            run_adb_command(["adb", "-s", device_id, "shell", "pkill", "-f", "frida"])
            log_to_fsr_logs(f"[DEBUG] Stopped existing Frida server processes")
        except:
            pass
        
        import time
        time.sleep(3)
        
        if is_frida_server_running(device_id):
            log_to_fsr_logs(f"[WARNING] Frida server still running, checking user...")
            try:
                ps_result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-A", "|", "grep", "frida-server"])
                if ps_result:
                    lines = ps_result.strip().split('\n')
                    for line in lines:
                        if 'frida-server' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                pid = parts[1]
                                user_result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-o", "user=", "-p", pid])
                                user = user_result.strip()
                                log_to_fsr_logs(f"[DEBUG] Found Frida server PID {pid} running as {user}")
                                
                                if user != "root":
                                    log_to_fsr_logs(f"[DEBUG] Killing non-root Frida server PID {pid}")
                                    run_adb_command(["adb", "-s", device_id, "shell", "kill", "-9", pid])
                                else:
                                    log_to_fsr_logs(f"[DEBUG] Root Frida server PID {pid} will be killed normally")
                                    run_adb_command(["adb", "-s", device_id, "shell", "kill", pid])
            except:
                log_to_fsr_logs(f"[WARNING] Could not check process users, using force kill")
                try:
                    run_adb_command(["adb", "-s", device_id, "shell", "killall", "frida-server"])
                    time.sleep(2)
                except:
                    pass
        
            clean_frida_server_files(device_id)
        
        return start_frida_server_with_force_download(device_id)
        
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Exception in restart_frida_server: {str(e)}")
        return jsonify({"error": str(e)}), 500

def start_frida_server_with_force_download(device_id):
    """Internal function to start Frida server with force download"""
    try:
        adb_check = there_is_adb_and_devices()
        if not adb_check["is_true"]:
            return jsonify({"error": "No devices connected"}), 400
        
        target_device = None
        for device in adb_check["available_devices"]:
            if device.get("device_id") == device_id:
                target_device = device
                break
        
        if not target_device:
            return jsonify({"error": "Device not found"}), 400
        
        if "device_id" in target_device:
            device_id = target_device["device_id"]
            architecture = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"])
            clean_arch = architecture.strip().split('-')[0]
            
            client_version, _ = check_frida_versions()
            if client_version == "Unknown":
                log_to_fsr_logs(f"[WARNING] Could not determine client version, using latest")
                target_version = None
            else:
                target_version = client_version
                log_to_fsr_logs(f"[DEBUG] Downloading Frida server version {target_version} to match client")
            
            log_to_fsr_logs(f"[DEBUG] Force downloading Frida server for architecture: {clean_arch}")
            
            os.makedirs(f"./frida-server/android", exist_ok=True)
            frida_url = get_frida_server_url(clean_arch, target_version)
            
            if frida_url is None:
                return jsonify({"error": f"No Frida server URL found for architecture: {clean_arch} and version: {target_version}"}), 500

            frida_server_path = os.path.join(f"./frida-server/android", "frida-server")
            download_path = os.path.join(f"frida-server/android", "frida-server-download.xz")
            
            log_to_fsr_logs(f"[DEBUG] Force downloading from: {frida_url}")
            wget.download(frida_url, download_path)
            
            with lzma.open(download_path) as src, open(frida_server_path, 'wb') as dst:
                shutil.copyfileobj(src, dst)
            
            if os.path.exists(download_path):
                os.remove(download_path)
            
            log_to_fsr_logs(f"[DEBUG] Pushing new Frida server to device...")
            run_adb_command(["adb", "-s", device_id, "root"])
            
            try:
                run_adb_push_command(device_id, frida_server_path, "/data/local/tmp/frida-server")
                run_adb_command(["adb", "-s", device_id, "shell", "chmod", "755", "/data/local/tmp/frida-server"])
                log_to_fsr_logs(f"[DEBUG] New Frida server pushed and chmod successfully")
            except Exception as e:
                log_to_fsr_logs(f"[ERROR] Failed to push new Frida server: {e}")
                return jsonify({"error": f"Failed to push Frida server to device: {str(e)}"}), 500
            
            log_to_fsr_logs(f"[DEBUG] Starting new Frida server in root shell...")
            run_adb_command(["adb", "-s", device_id, "root"])
            
            try:
                subprocess.run(["adb", "-s", device_id, "shell", "su", "-c", "/data/local/tmp/frida-server &"], 
                             timeout=10, capture_output=True)
                log_to_fsr_logs(f"[DEBUG] Started Frida server with su command")
            except subprocess.TimeoutExpired:
                log_to_fsr_logs(f"[DEBUG] su command timed out, trying alternative method")
                try:
                    subprocess.run(["adb", "-s", device_id, "shell", "su", "root", "/data/local/tmp/frida-server &"], 
                                 timeout=10, capture_output=True)
                    log_to_fsr_logs(f"[DEBUG] Started Frida server with su root command")
                except subprocess.TimeoutExpired:
                    log_to_fsr_logs(f"[DEBUG] Alternative method timed out, trying basic method")
                    subprocess.run(["adb", "-s", device_id, "shell", "/data/local/tmp/frida-server &"], 
                                 timeout=10, capture_output=True)
                    log_to_fsr_logs(f"[DEBUG] Started Frida server with basic method")
            
            time.sleep(3)
            
            if is_frida_server_running(device_id):
                log_to_fsr_logs(f"[DEBUG] Frida server started successfully")
                
                try:
                    server_result = subprocess.run(['frida-ps', '-U'], capture_output=True, text=True, timeout=600)
                    if server_result.returncode == 0:
                        log_to_fsr_logs(f"[DEBUG] Server is responding to frida-ps")
                    else:
                        log_to_fsr_logs(f"[WARNING] Server started but not responding to frida-ps")
                except:
                    log_to_fsr_logs(f"[WARNING] Could not verify server response")
            else:
                log_to_fsr_logs(f"[WARNING] Frida server may not have started properly")
            
            return jsonify({
                "success": True,
                "message": f"Frida server restarted with version {target_version or 'latest'}",
                "device_id": device_id,
                "platform": "android"
            })
        
        return jsonify({"error": "Unsupported device type"}), 400
        
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Exception in start_frida_server_with_force_download: {str(e)}")
        return jsonify({"error": str(e)}), 500

def check_port(port):
    """Check if a port is available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) != 0

def find_available_port(start_port=5000, max_attempts=100):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        if check_port(port):
            return port
    return None

def display_banner():
    """Display the application banner with help information"""
    banner = Fore.GREEN + r"""
                       ^
                      _)\.-.
     .-.__,___,_.-=-. )\`  -`\_
 .-.__\__,__,__.-=-. `/  \     `\\
 {~,-~-,-~.-~,-,;;;;\ |   '--;`)/
  \-,~_-~_-,~-,(_(_(;\/   ,;/
   ",-.~_,-~,-~,)_)_)'.  ;;(
     `~-,_-~,-~(_(_(_(_\  `;\\ 
,          `"~~--,)_)_)_)\_   \\
|\              (_(_/_(_,   \  ;  
\ '-.       _.--'  /_/_/_)   | |  FSR v1.0.0       
'--.\    .'          /_/    | |
    ))  /       \      |   /.'
   //  /,        | __.'|  ||
  //   ||        /`    (  ||
 ||    ||      .'       \ \\
 ||    ||    .'_         \ \\
  \\   //   / _ `\         \ \\__
   \\'-'/(   _  `\,;        \ '--:,
    `"`  `"` `-,,;         `"`",,;
    """ + Fore.RESET

    print(banner)
    print(Fore.CYAN)
    parser.print_help()
    print(Fore.RESET)


def main():
    display_banner()
    try:
        port = args.port
        
        if not check_port(port):
            print(Fore.YELLOW + f"Port {port} is already in use!" + Fore.RESET)
            available_port = find_available_port(port if port != 5000 else 5001)
            if available_port:
                print(Fore.GREEN + f"Automatically using available port {available_port}" + Fore.RESET)
                port = available_port
            else:
                print(Fore.RED + "Could not find any available port. Please specify a different port using -p option." + Fore.RESET)
                sys.exit(1)
        
        print(Fore.GREEN + f"Please Access http://127.0.0.1:{port}" + Fore.RESET)
        print("Press CTRL+C to stop this program.")
        
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        socketio.run(app, port=port, debug=False if get_device_type() not in ['Windows','Linux'] else False, allow_unsafe_werkzeug=True, host='0.0.0.0')
    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Fore.RESET)
    print(Fore.CYAN + "\nThanks For Using This Tools <3" + Fore.RESET)

@app.route('/generate-frida-script', methods=['POST'])
def generate_frida_script():
    """Generate Frida script using Codex bridge with Ghidra MCP integration"""
    try:
        data = request.json
        if not data or 'prompt' not in data:
            return jsonify({'error': 'No prompt provided'}), 400
        
        prompt = data['prompt'].strip()
        if not prompt:
            return jsonify({'error': 'Empty prompt provided'}), 400
            
        log_to_fsr_logs(f"[DEBUG] Generating AI-powered Frida script for prompt: {prompt}")
        
        # Generate Frida script using Codex bridge
        generated_script = generate_frida_script_from_prompt(prompt)
        
        log_to_fsr_logs(f"[DEBUG] Successfully generated AI-powered Frida script")
        
        return jsonify({
            'success': True,
            'script': generated_script,
            'powered_by': 'Codex Bridge + Ghidra MCP'
        })
        
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Failed to generate Frida script: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to generate script: {str(e)}'
        }), 500

def write_temp_generated_script(content: str) -> bool:
    """Persist provided script content to temp_generated.js."""
    if not content:
        return False
    try:
        with open(TEMP_SCRIPT_PATH, 'w', encoding='utf-8') as temp_file:
            temp_file.write(content if content.endswith('\n') else f"{content}\n")
        log_to_fsr_logs(f"[DEBUG] Wrote {TEMP_SCRIPT_PATH} ({len(content)} chars)")
        return True
    except Exception as exc:
        log_to_fsr_logs(f"[ERROR] Failed to write {TEMP_SCRIPT_PATH}: {exc}")
        return False


def read_temp_generated_script() -> str:
    """Read the generated script from temp_generated.js when available."""
    try:
        if os.path.exists(TEMP_SCRIPT_PATH):
            with open(TEMP_SCRIPT_PATH, 'r', encoding='utf-8') as temp_file:
                content = temp_file.read().strip()
                if content:
                    return content
    except Exception as exc:
        log_to_fsr_logs(f"[ERROR] Failed to read {TEMP_SCRIPT_PATH}: {exc}")
    return ''


def generate_frida_script_from_prompt(prompt):
    """Generate Frida script using Codex bridge with Ghidra MCP integration"""

    try:
        if not is_codex_bridge_available():
            log_to_fsr_logs("[WARNING] Codex bridge not available, using fallback templates")
            fallback_script = generate_fallback_script(prompt)
            write_temp_generated_script(fallback_script)
            return fallback_script

        log_to_fsr_logs("[DEBUG] Calling Codex bridge for script generation...")

        response = call_codex_via_bridge(prompt)

        if response.get("success"):
            log_to_fsr_logs("[DEBUG] Codex bridge returned Frida script successfully")

            raw_script = (response.get("script") or "").strip()
            cleaned_script = clean_codex_output(raw_script) if raw_script else ""

            if cleaned_script:
                stored = write_temp_generated_script(cleaned_script)
                if stored:
                    script_from_file = read_temp_generated_script()
                    if script_from_file:
                        return script_from_file

                    log_to_fsr_logs("[WARNING] temp_generated.js missing or empty after write; returning cleaned Codex output")
                else:
                    log_to_fsr_logs("[WARNING] Failed to persist cleaned Codex output; returning in-memory copy")
                return cleaned_script

            log_to_fsr_logs("[ERROR] Codex response did not yield a usable script block")
            fallback_script = generate_fallback_script(prompt)
            write_temp_generated_script(fallback_script)
            return fallback_script

        error_msg = response.get("error", "Unknown bridge error")
        log_to_fsr_logs(f"[ERROR] Codex bridge returned no script: {error_msg}")
        fallback_script = generate_fallback_script(prompt)
        write_temp_generated_script(fallback_script)
        return fallback_script

    except Exception as exc:
        log_to_fsr_logs(f"[ERROR] Codex bridge generation failed: {exc}")
        log_to_fsr_logs("[DEBUG] Falling back to template-based generation")
        fallback_script = generate_fallback_script(prompt)
        write_temp_generated_script(fallback_script)
        return fallback_script


def is_codex_bridge_available():
    """Check if Codex bridge is available on the system"""
    try:
        response = requests.get(f"{CODEX_BRIDGE_URL}/health", timeout=5)
        if response.status_code != 200:
            return False
        data = response.json()
        return data.get("status") == "healthy"
    except Exception:
        return False


def clean_codex_output(output):
    """Clean Codex bridge output to extract just the JavaScript code"""
    lines = output.splitlines()

    cleaned_lines = []
    in_code_block = False
    javascript_started = False

    for line in lines:
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            continue

        if not javascript_started:
            if any(indicator in line for indicator in ["Java.perform", "setTimeout", "console.log", "Interceptor.", "Module.", "Process.", "Java.use"]):
                javascript_started = True
            elif line.strip().startswith("//") or line.strip().startswith("/*"):
                javascript_started = True
            elif line.strip() and not any(skip_word in line.lower() for skip_word in ["perfect", "here", "script", "analysis", "findings", "features", "usage", "based on"]):
                javascript_started = True

        if javascript_started:
            if any(skip_phrase in line.lower() for skip_phrase in [
                "perfect!", "here's what", "script does:", "key findings", "script features:",
                "usage:", "## ", "# ", "frida -u", "the script will", "based on"
            ]):
                continue

            if not cleaned_lines and not line.strip():
                continue

            cleaned_lines.append(line)

    while cleaned_lines and not cleaned_lines[-1].strip():
        cleaned_lines.pop()

    result = "\n".join(cleaned_lines).strip()
    if not result:
        return None

    allowed_markers = ("Java.perform", "setImmediate(", "setTimeout(", "void function", "(function", "Interceptor.attach", "Module.", "rpc.exports")

    start_index = None
    for marker in allowed_markers:
        idx = result.find(marker)
        if idx != -1 and (start_index is None or idx < start_index):
            start_index = idx

    if start_index is not None:
        trimmed = result[start_index:].strip()
        return trimmed if trimmed else None

    return None


def call_codex_via_bridge(prompt):
    """Call Codex bridge for Frida script generation"""
    try:
        response = requests.post(
            f"{CODEX_BRIDGE_URL}/generate-script",
            json={"prompt": prompt},
            timeout=600
        )
        if response.status_code == 200:
            result_data = response.json()
            return {
                "success": result_data.get("success", False),
                "script": result_data.get("script", ""),
                "error": result_data.get("error", "")
            }
        return {
            "success": False,
            "script": "",
            "error": f"Bridge failed with status {response.status_code}"
        }
    except Exception as exc:
        return {
            "success": False,
            "script": "",
            "error": f"Bridge request failed: {exc}"
        }

def attempt_script_autofix(script_path, error_messages, output_log):
    """Attempt to fix Frida script errors using Codex Bridge and temp_generated.js"""

    try:
        log_to_fsr_logs("[AUTO-FIX] Attempting to fix script using AI via Codex bridge...")

        temp_script_path = "temp_generated.js"
        original_script = ""

        if os.path.exists(temp_script_path):
            with open(temp_script_path, 'r') as f:
                original_script = f.read()
            log_to_fsr_logs(f"[AUTO-FIX] Reading from temp_generated.js ({len(original_script)} chars)")
        else:
            with open(script_path, 'r') as f:
                original_script = f.read()
            log_to_fsr_logs(f"[AUTO-FIX] Fallback reading from {script_path}")

        error_summary = "\n".join(error_messages) if error_messages else "No specific errors detected"
        output_summary = "\n".join(output_log) if output_log else "No additional output"

        fix_prompt = f"""Fix the Frida script errors in temp_generated.js based on these error logs:

Error Messages: {error_summary}

Recent Output: {output_summary}

Please read the current script from temp_generated.js, fix the errors, and update the file with the corrected version."""

        try:
            response = call_codex_via_bridge(fix_prompt)

            if response and response.get('success'):
                script_from_file = read_temp_generated_script()
                if script_from_file:
                    write_temp_generated_script(script_from_file)
                    log_to_fsr_logs(f"[AUTO-FIX] Successfully updated {temp_script_path}")
                    log_to_fsr_logs(f"[AUTO-FIX] Fixed script length: {len(script_from_file)} chars")
                    return script_from_file

                fallback_script = response.get('script', '').strip()
                if fallback_script:
                    write_temp_generated_script(fallback_script)
                    log_to_fsr_logs("[AUTO-FIX] temp_generated.js missing; using Codex response body")
                    return fallback_script

                log_to_fsr_logs("[AUTO-FIX] Codex bridge returned success but no script found")
                return None
            else:
                error_msg = response.get('error', 'Unknown bridge error') if response else 'No response from bridge'
                log_to_fsr_logs(f"[AUTO-FIX] Codex bridge failed: {error_msg}")
                return None

        except Exception as e:
            log_to_fsr_logs(f"[AUTO-FIX] Exception during Codex bridge call: {str(e)}")
            return None

    except Exception as e:
        log_to_fsr_logs(f"[AUTO-FIX] Exception in script autofix: {str(e)}")
        return None

def get_ghidra_analysis_context():
    """Get real analysis context by executing Ghidra MCP commands directly against HTTP server"""
    
    try:
        import requests
        from urllib.parse import urljoin
        
        log_to_fsr_logs("[DEBUG] Connecting to Ghidra server to get real analysis context...")
        
        base_url = get_ghidra_server_url()
        context_parts = []
        
        try:
            strings_url = urljoin(base_url, "list_strings")
            params = {"limit": 100}  
            response = requests.get(strings_url, params=params, timeout=10)
            if response.ok:
                strings_data = response.text.strip().split('\n')
                
                library_names = []
                jni_functions = []
                interesting_strings = []
                
                for string_line in strings_data:
                    if string_line.strip():
                        if '.so' in string_line and 'lib' in string_line:
                            parts = string_line.split(': ')
                            if len(parts) > 1:
                                lib_name = parts[1].strip('"')
                                if lib_name.endswith('.so') and lib_name not in library_names:
                                    library_names.append(lib_name)
                        elif 'Java_' in string_line:
                            parts = string_line.split(': ')
                            if len(parts) > 1:
                                jni_func = parts[1].strip('"')
                                if jni_func not in jni_functions:
                                    jni_functions.append(jni_func)
                        elif any(keyword in string_line.lower() for keyword in ['password', 'key', 'secret', 'token', 'flag']):
                            parts = string_line.split(': ')
                            if len(parts) > 1:
                                interesting_strings.append(parts[1].strip('"'))
                
                if library_names:
                    context_parts.append(f"Native Libraries Found:\n" + '\n'.join(f"- {lib}" for lib in library_names))
                
                if jni_functions:
                    context_parts.append(f"JNI Functions Found:\n" + '\n'.join(f"- {func}" for func in jni_functions))
                
                if interesting_strings:
                    context_parts.append(f"Interesting Strings:\n" + '\n'.join(f"- {s}" for s in interesting_strings[:10]))
                
                log_to_fsr_logs(f"[DEBUG] Found {len(library_names)} libraries, {len(jni_functions)} JNI functions")
                
        except Exception as e:
            log_to_fsr_logs(f"[WARNING] Error getting strings: {str(e)}")
        
        try:
            functions_url = urljoin(base_url, "list_functions")
            response = requests.get(functions_url, timeout=10)
            if response.ok:
                functions = response.text.strip().split('\n')
                if functions and functions[0]:
                    native_functions = []
                    for func in functions[:20]:  
                        if func.strip() and not any(sys_func in func.lower() for sys_func in ['__', '_init', '_fini', 'frame_dummy']):
                            native_functions.append(func.strip())
                    
                    if native_functions:
                        context_parts.append(f"Native Functions Found:\n" + '\n'.join(f"- {func}" for func in native_functions[:10]))
                    log_to_fsr_logs(f"[DEBUG] Found {len(native_functions)} interesting native functions")
        except Exception as e:
            log_to_fsr_logs(f"[WARNING] Error getting functions: {str(e)}")
        
        try:
            current_func_url = urljoin(base_url, "get_current_function")
            response = requests.get(current_func_url, timeout=5)
            if response.ok:
                current_func = response.text.strip()
                if current_func and "Error" not in current_func and current_func != "No function selected":
                    context_parts.append(f"Currently Selected Function:\n{current_func}")
                    
                    addr_response = requests.get(urljoin(base_url, "get_current_address"), timeout=5)
                    if addr_response.ok:
                        current_addr = addr_response.text.strip()
                        if current_addr and "Error" not in current_addr:
                            decompile_url = urljoin(base_url, "decompile_function")
                            decompile_response = requests.get(decompile_url, 
                                                            params={"address": current_addr}, 
                                                            timeout=10)
                            if decompile_response.ok:
                                decompiled = decompile_response.text.strip()
                                if decompiled and "Error" not in decompiled:
                                    context_parts.append(f"Decompiled Code at {current_addr}:\n```c\n{decompiled[:800]}{'...(truncated)' if len(decompiled) > 800 else ''}\n```")
                                    log_to_fsr_logs("[DEBUG] Retrieved decompiled code from current selection")
        except Exception as e:
            log_to_fsr_logs(f"[WARNING] Error getting current function: {str(e)}")
        
        try:
            imports_url = urljoin(base_url, "list_imports")
            response = requests.get(imports_url, timeout=5)
            if response.ok:
                imports_data = response.text.strip().split('\n')
                if imports_data and imports_data[0]:
                    interesting_imports = [imp.strip() for imp in imports_data[:15] if imp.strip()]
                    if interesting_imports:
                        context_parts.append(f"Imported Functions (potential hook points):\n" + '\n'.join(f"- {imp}" for imp in interesting_imports))
                        log_to_fsr_logs(f"[DEBUG] Found {len(interesting_imports)} imported functions")
        except Exception as e:
            log_to_fsr_logs(f"[WARNING] Error getting imports: {str(e)}")
        
        if context_parts:
            full_context = "=== REAL GHIDRA ANALYSIS CONTEXT ===\n\n" + "\n\n".join(context_parts)
            full_context += "\n\n=== INSTRUCTIONS ===\nUse the above REAL data from Ghidra analysis. Hook the actual library names, function names, and addresses found above."
            log_to_fsr_logs("[DEBUG] Successfully retrieved comprehensive Ghidra analysis context")
            return full_context
        else:
            log_to_fsr_logs("[WARNING] No analysis data retrieved from Ghidra")
            return "Ghidra server is accessible but no meaningful binary analysis data was retrieved. Please ensure a binary is open and analyzed in Ghidra."
            
    except ImportError:
        log_to_fsr_logs("[ERROR] requests library not available for Ghidra integration")
        return "Cannot connect to Ghidra server - requests library not available."
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Failed to get real Ghidra context: {str(e)}")
        server_url = get_ghidra_server_url()
        return f"Failed to connect to Ghidra server at {server_url}. Error: {str(e)}\nEnsure Ghidra server is running and a binary is loaded."

def generate_fallback_script(prompt):
    """Fallback template-based generation when Codex AI is unavailable"""
    prompt_lower = prompt.lower()
    
    if any(keyword in prompt_lower for keyword in ['ssl', 'pinning', 'certificate', 'okhttp']):
        return generate_ssl_bypass_script_template()
    elif any(keyword in prompt_lower for keyword in ['root', 'detection', 'rootbeer']):
        return generate_root_bypass_script_template()
    elif any(keyword in prompt_lower for keyword in ['oncreate', 'activity', 'mainactivity']):
        return generate_activity_hook_script_template(prompt)
    elif any(keyword in prompt_lower for keyword in ['native', 'strcmp', 'libc', '.so']):
        return generate_native_hook_script_template(prompt)
    else:
        return generate_generic_hook_script_template(prompt)

def generate_ssl_bypass_script_template():
    """Generate SSL pinning bypass script template"""
    return """Java.perform(function() {
    console.log("[+] SSL Pinning Bypass Script Loaded (Template)");
    
    // OkHttp3 SSL Pinning Bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] SSL Pinning bypassed for: " + hostname);
            return;
        };
        console.log("[+] OkHttp3 CertificatePinner bypass enabled");
    } catch (e) {
        console.log("[!] OkHttp3 not found: " + e.message);
    }
    
    // Android SSL Pinning Bypass
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] X509TrustManager checkServerTrusted bypassed");
            return;
        };
        console.log("[+] X509TrustManager bypass enabled");
    } catch (e) {
        console.log("[!] X509TrustManager bypass failed: " + e.message);
    }
    
    console.log("[+] SSL Pinning bypass complete");
});"""

def generate_root_bypass_script_template():
    """Generate root detection bypass script template"""
    return """Java.perform(function() {
    console.log("[+] Root Detection Bypass Script Loaded (Template)");
    
    // RootBeer library bypass
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[+] RootBeer.isRooted() bypassed");
            return false;
        };
        console.log("[+] RootBeer bypass enabled");
    } catch (e) {
        console.log("[!] RootBeer not found: " + e.message);
    }
    
    // Generic root detection bypass
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var filename = this.getAbsolutePath();
            if (filename.indexOf("/system/bin/su") !== -1 ||
                filename.indexOf("/system/xbin/su") !== -1 ||
                filename.indexOf("/sbin/su") !== -1 ||
                filename.indexOf("/system/app/Superuser.apk") !== -1) {
                console.log("[+] File.exists() bypassed for: " + filename);
                return false;
            }
            return this.exists();
        };
        console.log("[+] Generic root file detection bypass enabled");
    } catch (e) {
        console.log("[!] File bypass failed: " + e.message);
    }
    
    console.log("[+] Root detection bypass complete");
});"""

def generate_activity_hook_script_template(prompt):
    """Generate Activity lifecycle hook script"""
    class_name = "MainActivity"
    if "." in prompt:
        words = prompt.split()
        for word in words:
            if "." in word and ("activity" in word.lower() or "Activity" in word):
                class_name = word.split(".")[0] + "." + word.split(".")[1]
                break
    
    return f"""Java.perform(function() {{
    console.log("[+] Activity Hook Script Loaded");
    
    try {{
        var {class_name.split('.')[-1]} = Java.use("{class_name}");
        
        {class_name.split('.')[-1]}.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {{
            console.log("[+] {class_name}.onCreate() called");
            console.log("[+] SavedInstanceState: " + savedInstanceState);
            
            // Call original onCreate
            var result = this.onCreate(savedInstanceState);
            
            console.log("[+] {class_name}.onCreate() completed");
            return result;
        }};
        
        {class_name.split('.')[-1]}.onResume.implementation = function() {{
            console.log("[+] {class_name}.onResume() called");
            return this.onResume();
        }};
        
        {class_name.split('.')[-1]}.onPause.implementation = function() {{
            console.log("[+] {class_name}.onPause() called");
            return this.onPause();
        }};
        
        console.log("[+] {class_name} hooks installed successfully");
    }} catch (e) {{
        console.log("[!] Failed to hook {class_name}: " + e.message);
    }}
}});"""

def generate_native_hook_script_template(prompt):
    """Generate native function hook script"""
    func_name = "strcmp"
    lib_name = "libc.so"
    
    if "strcmp" in prompt.lower():
        func_name = "strcmp"
    elif "strncmp" in prompt.lower():
        func_name = "strncmp"
    elif "memcmp" in prompt.lower():
        func_name = "memcmp"
    
    if ".so" in prompt:
        words = prompt.split()
        for word in words:
            if ".so" in word:
                lib_name = word
                break
                
    return f"""Java.perform(function() {{
    console.log("[+] Native Hook Script Loaded");
    
    try {{
        var {func_name}_ptr = Module.findExportByName("{lib_name}", "{func_name}");
        if ({func_name}_ptr) {{
            console.log("[+] Found {func_name} at: " + {func_name}_ptr);
            
            Interceptor.attach({func_name}_ptr, {{
                onEnter: function(args) {{
                    console.log("[+] {func_name} called");
                    console.log("[+] arg0: " + Memory.readUtf8String(args[0]));
                    console.log("[+] arg1: " + Memory.readUtf8String(args[1]));
                    this.arg0 = Memory.readUtf8String(args[0]);
                    this.arg1 = Memory.readUtf8String(args[1]);
                }},
                onLeave: function(retval) {{
                    console.log("[+] {func_name} returned: " + retval);
                    console.log("[+] Comparing: '" + this.arg0 + "' vs '" + this.arg1 + "'");
                    
                    // retval.replace(0);
                }}
            }});
            console.log("[+] {func_name} hook installed successfully");
        }} else {{
            console.log("[!] {func_name} not found in {lib_name}");
        }}
    }} catch (e) {{
        console.log("[!] Failed to hook {func_name}: " + e.message);
    }}
}});"""


def generate_generic_hook_script_template(prompt):
    """Generate generic hook script based on prompt"""
    return f"""Java.perform(function() {{
    console.log("[+] Generic Hook Script Loaded");
    console.log("[+] Based on prompt: {prompt}");
    
    // TODO: Implement specific hooks based on your requirements
    // This is a template script - customize it for your needs
    
    try {{
        // Example: Hook a specific class method
        // var TargetClass = Java.use("com.example.TargetClass");
        // TargetClass.targetMethod.implementation = function() {{
        //     console.log("[+] targetMethod called");
        //     var result = this.targetMethod();
        //     console.log("[+] Result: " + result);
        //     return result;
        // }};
        
        console.log("[+] Please customize this script for your specific needs");
        console.log("[+] Refer to Frida documentation for more examples");
        
    }} catch (e) {{
        console.log("[!] Hook failed: " + e.message);
    }}
    
    console.log("[+] Generic hook script loaded - customize as needed");
}});"""

@app.route('/sslpindec', methods=['GET'])
def sslpindetect_page():
    """Render SSL Pinning Detection page"""
    return render_template('sslpindetect.html')

@app.route('/sslpindec/analyze', methods=['POST'])
def sslpindetect_analyze():
    """Analyze APK for SSL pinning"""
    try:
        from sslpindetect import SSLPinDetector
        
        if 'apkFile' not in request.files:
            return jsonify({'success': False, 'error': 'No APK file uploaded'}), 400
        
        file = request.files['apkFile']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.apk'):
            return jsonify({'success': False, 'error': 'Only APK files are allowed'}), 400
        
        apktool_path = request.form.get('apktool_path', '').strip()
        if not apktool_path:
            from sslpindetect import SSLPinDetector
            detector_temp = SSLPinDetector()
            apktool_path = detector_temp._find_apktool()
        
        if not apktool_path or not os.path.exists(apktool_path):
            return jsonify({
                'success': False, 
                'error': 'Apktool not found. Please specify the path to apktool (supports .jar, .exe, or binary).\n\nCommon locations:\n- apktool.jar (requires Java)\n- apktool.exe (Windows)\n- apktool (Linux/Mac binary)\n\nYou can download apktool from: https://ibotpeaches.github.io/Apktool/'
            }), 400
        
        filename = secure_filename(file.filename)
        apk_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(apk_path)
        
        try:
            detector = SSLPinDetector(apktool_path=apktool_path)
            
            verbose = request.form.get('verbose', 'false').lower() == 'true'
            result = detector.detect_ssl_pinning(apk_path, verbose=verbose)
            
            if os.path.exists(apk_path):
                os.remove(apk_path)
            
            return jsonify(result)
            
        except Exception as e:
            if os.path.exists(apk_path):
                os.remove(apk_path)
            return jsonify({
                'success': False,
                'error': f'Analysis failed: {str(e)}'
            }), 500
            
    except ImportError as e:
        return jsonify({
            'success': False,
            'error': f'Module import error: {str(e)}'
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Unexpected error: {str(e)}'
        }), 500

if __name__ == "__main__":
    main()
