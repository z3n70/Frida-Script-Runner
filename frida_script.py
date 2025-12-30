from flask import Flask, render_template, request, jsonify, send_file, abort, after_this_request
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
import xml.etree.ElementTree as ET
import tempfile

from mobile_proxy import (
    get_current_mobile_proxy,
    set_mobile_proxy,
    unset_mobile_proxy,
    get_local_proxy_ips,
)

from adb_gui import (
    connect_adb,
    get_devices,
    get_device_info,
    get_packages as get_adb_packages,
    clear_package_data,
    uninstall_package,
    force_stop_package,
    install_package,
    get_running_processes,
    get_app_memory_info,
    get_system_memory_info,
    get_disk_space,
    get_screen_info,
    send_touch_event,
    send_swipe_event,
    send_key_event,
    send_text,
    launch_app,
    get_package_activity,
    check_device_responsive,
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
GADGET_CACHE_DIR = os.path.join(os.getcwd(), 'frida-gadget', 'android')
process_input_lock = threading.Lock()
last_frida_command = None

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

# -------------------- Frida Server Manager: Views & APIs --------------------
@app.route('/frida-server-manager')
def frida_server_manager_page():
    """Render the Frida Server Manager page."""
    try:
        devices = there_is_adb_and_devices()
        return render_template('frida_server_manager.html', devices=devices.get('available_devices', []))
    except Exception as e:
        return render_template('frida_server_manager.html', devices=[], error=str(e))


@app.route('/api/adb/devices')
def api_adb_devices():
    """Return connected devices with Android architecture info where applicable."""
    try:
        info = there_is_adb_and_devices()
        devices = []
        for dev in info.get('available_devices', []):
            dev_copy = dict(dev)
            if 'device_id' in dev_copy:
                try:
                    arch = run_adb_command(["adb", "-s", dev_copy['device_id'], "shell", "getprop", "ro.product.cpu.abi"]) or ''
                    dev_copy['architecture'] = arch.strip()
                except Exception:
                    dev_copy['architecture'] = 'unknown'
            devices.append(dev_copy)
        return jsonify({
            'success': True,
            'devices': devices,
            'message': info.get('message', '')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/frida/releases')
def api_frida_releases():
    """Fetch Frida releases from GitHub and return a list of tag names."""
    try:
        releases_url = 'https://api.github.com/repos/frida/frida/releases'
        resp = requests.get(releases_url, timeout=30)
        tags = []
        if resp.status_code == 200:
            data = resp.json()
            tags = [r.get('tag_name') for r in data if r.get('tag_name')]
        else:
            tags_url = 'https://api.github.com/repos/frida/frida/tags'
            r2 = requests.get(tags_url, timeout=30)
            if r2.status_code == 200:
                data = r2.json()
                tags = [t.get('name') for t in data if t.get('name')]
        tags = [t.replace('refs/tags/', '') for t in tags]
        return jsonify({'success': True, 'releases': tags[:50]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/frida/local')
def api_frida_local():
    """Return local Frida client and tools versions inside the environment."""
    try:
        client_version = 'Unknown'
        tools_version = 'Unknown'
        py_core_version = 'Unknown'

        try:
            r = subprocess.run(['frida', '--version'], capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                client_version = r.stdout.strip()
        except Exception:
            pass

        try:
            r = subprocess.run([sys.executable, '-c', 'import pkgutil, pkg_resources;import sys;print(pkg_resources.get_distribution("frida-tools").version) if pkgutil.find_loader("pkg_resources") else sys.stdout.write("")'],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                tools_version = r.stdout.strip()
        except Exception:
            pass

        try:
            r = subprocess.run([sys.executable, '-c', 'import frida,sys;sys.stdout.write(frida.__version__)'],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                py_core_version = r.stdout.strip()
        except Exception:
            pass

        return jsonify({
            'success': True,
            'client_version': client_version,
            'frida_tools_version': tools_version,
            'frida_py_version': py_core_version,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/frida/set-client-version', methods=['POST'])
def api_set_frida_client_version():
    """Install a specific Frida client (Python frida) version and upgrade frida-tools."""
    try:
        data = request.get_json(force=True)
        version = (data.get('version') or '').strip()
        if not version:
            return jsonify({'success': False, 'error': 'version is required'}), 400

        cmd1 = [sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '--upgrade', f'frida=={version}']
        r1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=600)
        if r1.returncode != 0:
            return jsonify({'success': False, 'error': f'pip error (frida=={version}): {r1.stderr or r1.stdout}'}), 500

        cmd2 = [sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '--upgrade', 'frida-tools']
        r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=600)
        if r2.returncode != 0:
            log_to_fsr_logs(f"[FSM] Warning: upgrading frida-tools failed: {r2.stderr or r2.stdout}")

        r3 = subprocess.run(['frida', '--version'], capture_output=True, text=True, timeout=60)
        ver = r3.stdout.strip() if r3.returncode == 0 else 'Unknown'
        return jsonify({'success': True, 'client_version': ver})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/start-frida-server-version', methods=['POST'])
def start_frida_server_version():
    """Start Frida server on a device using a specific version tag."""
    try:
        data = request.get_json(force=True)
        device_id = data.get('device_id')
        version = data.get('version')
        if not device_id or not version:
            return jsonify({'success': False, 'error': 'device_id and version are required'}), 400

        adb_check = there_is_adb_and_devices()
        if not adb_check.get('is_true'):
            return jsonify({'success': False, 'error': 'No devices connected'}), 400

        target = None
        for d in adb_check.get('available_devices', []):
            if d.get('device_id') == device_id:
                target = d
                break
        if not target:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        if 'device_id' not in target:
            return jsonify({'success': False, 'error': 'Only Android devices require frida-server binary'}), 400

        arch_raw = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"]) or ''
        clean_arch = arch_raw.strip().split('-')[0]
        log_to_fsr_logs(f"[FSM] Device {device_id} arch: {arch_raw} -> {clean_arch}")

        os.makedirs('./frida-server/android', exist_ok=True)
        frida_server_path = os.path.join('./frida-server/android', 'frida-server')
        download_path = os.path.join('frida-server/android', 'frida-server-download.xz')

        url = get_frida_server_url(clean_arch, version)
        if not url:
            return jsonify({'success': False, 'error': f'No asset found for version {version} arch {clean_arch}'}), 404

        log_to_fsr_logs(f"[FSM] Downloading frida-server {version} for {clean_arch}")
        wget.download(url, download_path)
        with lzma.open(download_path) as src, open(frida_server_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)
        if os.path.exists(download_path):
            os.remove(download_path)

        run_adb_command(["adb", "-s", device_id, "root"])
        run_adb_push_command(device_id, frida_server_path, "/data/local/tmp/frida-server")
        run_adb_command(["adb", "-s", device_id, "shell", "chmod", "755", "/data/local/tmp/frida-server"]) 

        try:
            run_adb_command(["adb", "-s", device_id, "shell", "pkill", "-f", "frida-server"])
        except Exception:
            pass

        try:
            subprocess.run(["adb", "-s", device_id, "shell", "su", "-c", "/data/local/tmp/frida-server &"], timeout=10, capture_output=True)
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(["adb", "-s", device_id, "shell", "su", "root", "/data/local/tmp/frida-server &"], timeout=10, capture_output=True)
            except subprocess.TimeoutExpired:
                subprocess.run(["adb", "-s", device_id, "shell", "/data/local/tmp/frida-server &"], timeout=10, capture_output=True)

        time.sleep(3)
        running = is_frida_server_running(device_id)
        return jsonify({'success': True, 'running': running, 'device_id': device_id, 'version': version})
    except Exception as e:
        log_to_fsr_logs(f"[FSM] Error starting frida-server with version: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# -------------------- Frida Gadget Injector (Android) --------------------
def get_frida_gadget_url(architecture: str, version: str = None) -> str:
    """Find the frida-gadget asset URL for the given arch and version.

    architecture examples: arm64-v8a, armeabi-v7a, x86_64, x86
    """
    if version:
        url = f'https://api.github.com/repos/frida/frida/releases/tags/{version}'
        log_to_fsr_logs(f"[GADGET] Requesting gadget for version: {version}")
    else:
        url = 'https://api.github.com/repos/frida/frida/releases/latest'
        log_to_fsr_logs(f"[GADGET] Requesting gadget for latest version")

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        release_data = response.json()

        clean_arch = architecture.strip()
        arch_map = {
            'arm64-v8a': 'arm64',
            'armeabi-v7a': 'arm',
            'x86_64': 'x86_64',
            'x86': 'x86'
        }
        frida_arch = arch_map.get(clean_arch, clean_arch)

        for asset in release_data.get('assets', []):
            name = asset.get('name', '')
            if 'frida-gadget' in name and 'android' in name and f'-{frida_arch}.so' in name and name.endswith('.xz'):
                return asset['browser_download_url']
        return None
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Failed to resolve gadget URL: {e}")
        return None


@app.route('/frida-gadget-injector')
def frida_gadget_injector_page():
    return render_template('frida_gadget_injector.html')


def _list_cached_gadgets():
    items = []
    base = GADGET_CACHE_DIR
    if not os.path.isdir(base):
        return items
    for ver in sorted(os.listdir(base)):
        vdir = os.path.join(base, ver)
        if not os.path.isdir(vdir):
            continue
        for arch in sorted(os.listdir(vdir)):
            adir = os.path.join(vdir, arch)
            so_path = os.path.join(adir, 'libfrida-gadget.so')
            if os.path.isfile(so_path):
                try:
                    size = os.path.getsize(so_path)
                except Exception:
                    size = -1
                items.append({'version': ver, 'arch': arch, 'path': so_path, 'size': size})
    return items


def _ensure_cached_gadget(architecture: str, version: str) -> str:
    os.makedirs(GADGET_CACHE_DIR, exist_ok=True)
    ver_dir = os.path.join(GADGET_CACHE_DIR, version)
    arch_dir = os.path.join(ver_dir, architecture)
    so_path = os.path.join(arch_dir, 'libfrida-gadget.so')
    if os.path.isfile(so_path):
        return so_path
    # Download and cache
    url = get_frida_gadget_url(architecture, version)
    if not url:
        raise RuntimeError(f'No frida-gadget asset found for version {version} arch {architecture}')
    os.makedirs(arch_dir, exist_ok=True)
    xz_tmp = os.path.join(arch_dir, 'libfrida-gadget.so.xz')
    log_to_fsr_logs(f"[GADGET][CACHE] Downloading gadget {version} {architecture}")
    wget.download(url, xz_tmp)
    with lzma.open(xz_tmp) as src, open(so_path, 'wb') as dst:
        shutil.copyfileobj(src, dst)
    try:
        os.remove(xz_tmp)
    except Exception:
        pass
    return so_path


@app.route('/frida-gadget-manager')
def frida_gadget_manager_page():
    return render_template('frida_gadget_manager.html')


@app.route('/api/gadget/local')
def api_gadget_local():
    try:
        return jsonify({'success': True, 'items': _list_cached_gadgets()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/gadget/download', methods=['POST'])
def api_gadget_download():
    try:
        data = request.get_json(force=True)
        version = (data.get('version') or '').strip()
        arch = (data.get('arch') or '').strip() or 'arm64-v8a'
        if not version:
            return jsonify({'success': False, 'error': 'version is required'}), 400
        path = _ensure_cached_gadget(arch, version)
        size = os.path.getsize(path)
        return jsonify({'success': True, 'path': path, 'size': size})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/gadget/delete', methods=['POST'])
def api_gadget_delete():
    try:
        data = request.get_json(force=True)
        version = (data.get('version') or '').strip()
        arch = (data.get('arch') or '').strip()
        if not version or not arch:
            return jsonify({'success': False, 'error': 'version and arch are required'}), 400
        dir_path = os.path.join(GADGET_CACHE_DIR, version, arch)
        if os.path.isdir(dir_path):
            shutil.rmtree(dir_path, ignore_errors=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def _determine_smali_dir(workdir: str) -> str:
    # Prefer 'smali' then any 'smali*'
    primary = os.path.join(workdir, 'smali')
    if os.path.isdir(primary):
        return primary
    for name in os.listdir(workdir):
        if name.startswith('smali') and os.path.isdir(os.path.join(workdir, name)):
            return os.path.join(workdir, name)
    return None


def _modify_manifest_add_application(manifest_path: str, app_class: str) -> bool:
    try:
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        android_ns = '{http://schemas.android.com/apk/res/android}'
        app = root.find('application')
        if app is None:
            return False
        name_attr = app.get(android_ns + 'name')
        if name_attr and name_attr.strip():
            return False
        app.set(android_ns + 'name', app_class)
        tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
        return True
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Manifest modify failed: {e}")
        return False


def _write_application_smali(smali_dir: str, app_class: str) -> bool:
    # app_class like 'com.fsr.FSRApp'
    try:
        parts = app_class.split('.')
        class_name = parts[-1]
        package_dirs = os.path.join(smali_dir, *parts[:-1])
        os.makedirs(package_dirs, exist_ok=True)
        dest = os.path.join(package_dirs, f"{class_name}.smali")
        internal_name = 'L' + '/'.join(parts) + ';'
        content = f"""
.class public {internal_name}
.super Landroid/app/Application;
.source "{class_name}.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method public onCreate()V
    .locals 1
    const-string v0, "frida-gadget"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    invoke-super {{p0}}, Landroid/app/Application;->onCreate()V
    return-void
.end method
""".strip()
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content + "\n")
        return True
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Write smali failed: {e}")
        return False


def _get_manifest_application_name(manifest_path: str) -> str:
    try:
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        android_ns = '{http://schemas.android.com/apk/res/android}'
        for child in root.iter():
            if child.tag.endswith('application'):
                name = child.get(android_ns + 'name', '') or child.get('name', '')
                return name or ''
    except Exception:
        pass
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            txt = f.read()
        import re
        m = re.search(r'<application[^>]*android:name="([^"]+)"', txt, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ''


def _write_app_wrapper_smali(smali_dir: str, wrapper_class: str, base_class: str) -> bool:
    try:
        # wrapper_class like 'com.fsr.AppWrapper', base_class like 'com.aminivan.applications.BaseApplication'
        w_parts = wrapper_class.split('.')
        b_parts = base_class.split('.')
        w_class_name = w_parts[-1]
        w_pkg_dirs = os.path.join(smali_dir, *w_parts[:-1])
        os.makedirs(w_pkg_dirs, exist_ok=True)
        dest = os.path.join(w_pkg_dirs, f"{w_class_name}.smali")
        w_internal = 'L' + '/'.join(w_parts) + ';'
        b_internal = 'L' + '/'.join(b_parts) + ';'
        content = f"""
.class public {w_internal}
.super {b_internal}
.source "{w_class_name}.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, {b_internal}-><init>()V
    return-void
.end method

.method public onCreate()V
    .locals 1
    const-string v0, "frida-gadget"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    invoke-super {{p0}}, {b_internal}->onCreate()V
    return-void
.end method
""".strip()
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content + "\n")
        return True
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Write app wrapper smali failed: {e}")
        return False


def _modify_manifest_set_application(manifest_path: str, new_app_class: str) -> bool:
    try:
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        android_ns = '{http://schemas.android.com/apk/res/android}'
        app = None
        for child in root.iter():
            if child.tag.endswith('application'):
                app = child
                break
        if app is None:
            raise RuntimeError('application tag not found')
        app.set(android_ns + 'name', new_app_class)
        tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
        return True
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Manifest set application failed: {e}")
        # Fallback text replace
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            import re
            if re.search(r'android:name="[^"]+"', txt):
                new_txt = re.sub(r'(android:name=")([^"]+)(")', rf'\1{new_app_class}\3', txt, count=1)
            else:
                # Insert name attr in <application ...>
                m = re.search(r'<application\b', txt, re.IGNORECASE)
                if not m:
                    raise RuntimeError('cannot find <application> to set name')
                pos = m.end()
                new_txt = txt[:pos] + f' android:name="{new_app_class}"' + txt[pos:]
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(new_txt)
            return True
        except Exception as e2:
            log_to_fsr_logs(f"[GADGET] Text set application failed: {e2}")
            return False


def _get_manifest_component_factory(manifest_path: str) -> str:
    try:
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        android_ns = '{http://schemas.android.com/apk/res/android}'
        for child in root.iter():
            if child.tag.endswith('application'):
                val = child.get(android_ns + 'appComponentFactory', '') or child.get('appComponentFactory', '')
                return val or ''
    except Exception:
        pass
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            txt = f.read()
        import re
        m = re.search(r'appComponentFactory\s*=\s*"([^"]+)"', txt, re.IGNORECASE)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ''


def _write_component_factory_wrapper_smali(smali_dir: str, wrapper_class: str, base_factory_class: str) -> bool:
    try:
        w_parts = wrapper_class.split('.')
        b_parts = (base_factory_class or 'android.app.AppComponentFactory').split('.')
        w_class_name = w_parts[-1]
        w_pkg_dirs = os.path.join(smali_dir, *w_parts[:-1])
        os.makedirs(w_pkg_dirs, exist_ok=True)
        dest = os.path.join(w_pkg_dirs, f"{w_class_name}.smali")
        w_internal = 'L' + '/'.join(w_parts) + ';'
        b_internal = 'L' + '/'.join(b_parts) + ';'
        content = f"""
.class public {w_internal}
.super {b_internal}
.source "{w_class_name}.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, {b_internal}-><init>()V
    return-void
.end method

.method public instantiateApplication(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;
    .locals 1
    const-string v0, "frida-gadget"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    invoke-super {{p0, p1, p2}}, {b_internal}->instantiateApplication(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;
    move-result-object v0
    return-object v0
.end method
""".strip()
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content + "\n")
        return True
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Write component factory wrapper failed: {e}")
        return False


def _modify_manifest_set_component_factory(manifest_path: str, new_factory_class: str) -> bool:
    try:
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        android_ns = '{http://schemas.android.com/apk/res/android}'
        app = None
        for child in root.iter():
            if child.tag.endswith('application'):
                app = child
                break
        if app is None:
            raise RuntimeError('application tag not found')
        app.set(android_ns + 'appComponentFactory', new_factory_class)
        tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
        return True
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Manifest set component factory failed: {e}")
        # Text fallback
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            import re
            if re.search(r'appComponentFactory\s*=\s*"[^"]+"', txt, re.IGNORECASE):
                new_txt = re.sub(r'(appComponentFactory\s*=\s*")([^"]+)(")', rf'\1{new_factory_class}\3', txt, count=1, flags=re.IGNORECASE)
            else:
                m = re.search(r'<application\b', txt, re.IGNORECASE)
                if not m:
                    raise RuntimeError('cannot find <application> to set appComponentFactory')
                pos = m.end()
                new_txt = txt[:pos] + f' android:appComponentFactory="{new_factory_class}"' + txt[pos:]
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(new_txt)
            return True
        except Exception as e2:
            log_to_fsr_logs(f"[GADGET] Text set component factory failed: {e2}")
            return False


def _debug_log_manifest(manifest_path: str):
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            txt = f.read()
        head = txt[:400].replace('\n', ' ')
        flags = []
        for token in ['<application', '</application', '<activity', '<provider', 'android:name=']:
            if token.lower() in txt.lower():
                flags.append(token)
        log_to_fsr_logs(f"[GADGET][MANIFEST] path={manifest_path}, size={len(txt)} flags={','.join(flags)}")
        log_to_fsr_logs(f"[GADGET][MANIFEST][HEAD] {head}")
    except Exception as e:
        log_to_fsr_logs(f"[GADGET][MANIFEST] failed to read: {e}")


def _find_manifest_file(workdir: str) -> str:
    # Prefer root AndroidManifest.xml, but search recursively as fallback
    root_path = os.path.join(workdir, 'AndroidManifest.xml')
    if os.path.isfile(root_path):
        return root_path
    for dirpath, dirnames, filenames in os.walk(workdir):
        for fn in filenames:
            if fn == 'AndroidManifest.xml':
                return os.path.join(dirpath, fn)
    return root_path  # default expected path


def _is_text_xml(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            head = f.read(16)
        return head.startswith(b'<?xml') or head.lstrip().startswith(b'<?xml')
    except Exception:
        return False


def _run_apktool_decode_full(apktool_path: str, apk_path: str, out_dir: str):
    apktool_lower = apktool_path.lower()
    if apktool_lower.endswith('.jar'):
        cmd = ['java', '-jar', apktool_path, 'd', apk_path, '-o', out_dir, '-f', '--use-aapt2']
    elif apktool_lower.endswith(('.exe', '.bat')):
        cmd = [apktool_path, 'd', apk_path, '-o', out_dir, '-f', '--use-aapt2']
    else:
        cmd = [apktool_path, 'd', apk_path, '-o', out_dir, '-f', '--use-aapt2']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)


def _sanitize_aapt_invalid_resources(workdir: str) -> int:
    """Sanitize resource file names and references to satisfy aapt/aapt2 rules.

    - Renames files under res/* whose basenames contain characters outside [a-z0-9_.]
      (e.g., names starting with '$' like $avd_hide_password__0.xml).
    - Ensures the first character is a letter by prefixing 'x' if needed.
    - Updates references in XML files (res/**/* and AndroidManifest.xml) from
      @type/old_name to @type/new_name.
    - Updates res/values/public.xml <public name="..."> entries accordingly.

    Returns the number of renamed files.
    """
    res_dir = os.path.join(workdir, 'res')
    if not os.path.isdir(res_dir):
        return 0

    def res_type_from_dir(dname: str) -> str:
        return dname.split('-')[0] if dname else dname

    changes = {}  # (res_type, old_base) -> new_base
    renamed_count = 0
    for entry in os.listdir(res_dir):
        full = os.path.join(res_dir, entry)
        if not os.path.isdir(full):
            continue
        rtype = res_type_from_dir(entry.lower())
        for root, _, files in os.walk(full):
            for fn in files:
                base, ext = os.path.splitext(fn)
                old_base = base
                new_base = re.sub(r'[^a-z0-9_.]', '_', old_base.lower())
                if not new_base or not new_base[0].isalpha():
                    new_base = 'x' + new_base
                if new_base == old_base:
                    continue
                src = os.path.join(root, fn)
                dst = os.path.join(root, new_base + ext)
                if os.path.exists(dst):
                    suffix = 2
                    while os.path.exists(os.path.join(root, f"{new_base}_{suffix}{ext}")):
                        suffix += 1
                    dst = os.path.join(root, f"{new_base}_{suffix}{ext}")
                    new_base = f"{new_base}_{suffix}"
                try:
                    os.rename(src, dst)
                    changes[(rtype, old_base)] = new_base
                    renamed_count += 1
                except Exception as e:
                    log_to_fsr_logs(f"[GADGET][SANITIZE] rename failed {src} -> {dst}: {e}")

    if not changes:
        return 0

    def _rewrite_file(path: str):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            orig = txt
            for (rtype, old), new in changes.items():
                txt = txt.replace(f"@{rtype}/{old}", f"@{rtype}/{new}")
            if txt != orig:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(txt)
        except Exception as e:
            log_to_fsr_logs(f"[GADGET][SANITIZE] ref update failed for {path}: {e}")

    for root, _, files in os.walk(res_dir):
        for fn in files:
            if fn.lower().endswith('.xml'):
                _rewrite_file(os.path.join(root, fn))

    manifest_path = _find_manifest_file(workdir)
    if os.path.exists(manifest_path):
        _rewrite_file(manifest_path)

    public_xml = os.path.join(res_dir, 'values', 'public.xml')
    if os.path.exists(public_xml):
        try:
            ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
            tree = ET.parse(public_xml)
            root = tree.getroot()
            for (rtype, old), new in changes.items():
                for node in root.findall('public'):
                    t = node.get('type')
                    n = node.get('name')
                    if t == rtype and n == old:
                        node.set('name', new)
            tree.write(public_xml, encoding='utf-8', xml_declaration=True)
        except Exception as e:
            log_to_fsr_logs(f"[GADGET][SANITIZE] public.xml update failed: {e}")

    log_to_fsr_logs(f"[GADGET] Sanitized {renamed_count} resource name(s) for aapt compliance")
    return renamed_count

def _ensure_text_manifest(apktool_path: str, apk_path: str, workdir: str) -> str:
    manifest_path = _find_manifest_file(workdir)
    if not os.path.exists(manifest_path):
        return manifest_path
    if _is_text_xml(manifest_path):
        return manifest_path
    try:
        apkanalyzer = shutil.which('apkanalyzer') or '/opt/android-sdk/cmdline-tools/latest/bin/apkanalyzer'
        if apkanalyzer and os.path.exists(apkanalyzer):
            pr = subprocess.run([apkanalyzer, 'manifest', 'print', apk_path], capture_output=True, text=True, timeout=120)
            if pr.returncode == 0 and pr.stdout.strip().startswith('<?xml'):
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    f.write(pr.stdout)
                log_to_fsr_logs(f"[GADGET] Replaced binary manifest with text via apkanalyzer")
                return manifest_path
            else:
                log_to_fsr_logs(f"[GADGET] apkanalyzer failed: {pr.stderr or pr.stdout}")
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] apkanalyzer manifest print failed: {e}")
    try:
        tmp_dir = tempfile.mkdtemp(prefix='manifest_only_')
        _run_apktool_decode_full(apktool_path, apk_path, tmp_dir)
        tmp_manifest = _find_manifest_file(tmp_dir)
        if os.path.exists(tmp_manifest) and _is_text_xml(tmp_manifest):
            shutil.copyfile(tmp_manifest, manifest_path)
            log_to_fsr_logs(f"[GADGET] Replaced binary manifest with text manifest from secondary decode")
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] ensure_text_manifest fallback failed: {e}")
    return manifest_path


def _find_apktool_from_resources() -> str:
    try:
        candidates = []
        base = os.path.join('tools', 'resources')
        if os.path.isdir(base):
            for name in [
                'apktool_2.12.1.jar',
                'apktool_2.12.0.jar',
                'apktool_2.11.0.jar',
                'apktool.jar',
            ]:
                p = os.path.join(base, name)
                if os.path.isfile(p):
                    candidates.append(p)
            for name in ['apktool', 'apktool.exe']:
                p = os.path.join(base, name)
                if os.path.isfile(p):
                    candidates.append(p)
        for p in candidates:
            return p
    except Exception:
        pass
    return ''
def _read_manifest_package(manifest_path: str) -> str:
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        pkg = root.get('package', '') or ''
        if pkg:
            return pkg
    except Exception:
        pass
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
        import re
        m = re.search(r'package\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ''


def _detect_split_apk(manifest_path: str):
    """Return (is_split, details) by scanning manifest attributes and structure."""
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        attrs = root.attrib.copy()
        split_attrs = []
        for k, v in attrs.items():
            lk = k.lower()
            if 'split' in lk or 'config' in lk:
                split_attrs.append(f"{k}={v}")
        has_app = False
        for child in root.iter():
            if child.tag.endswith('application'):
                has_app = True
                break
        main_act = _find_main_activity(manifest_path)
        if not has_app or not main_act:
            if split_attrs:
                return True, f"split-like manifest ({', '.join(split_attrs)}), has_app={has_app}, main_activity={bool(main_act)}"
            return False, f"has_app={has_app}, main_activity={bool(main_act)}"
        return False, 'looks like base/universal'
    except Exception as e:
        return False, f"manifest parse error: {e}"


def _write_provider_smali(smali_dir: str, provider_class: str) -> bool:
    try:
        parts = provider_class.split('.')
        class_name = parts[-1]
        package_dirs = os.path.join(smali_dir, *parts[:-1])
        os.makedirs(package_dirs, exist_ok=True)
        dest = os.path.join(package_dirs, f"{class_name}.smali")
        internal = 'L' + '/'.join(parts) + ';'
        content = f"""
.class public {internal}
.super Landroid/content/ContentProvider;
.source "{class_name}.java"

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Landroid/content/ContentProvider;-><init>()V
    return-void
.end method

.method public onCreate()Z
    .locals 8
    const-string v0, "FSR"
    invoke-virtual {{p0}}, Landroid/content/ContentProvider;->getContext()Landroid/content/Context;
    move-result-object v1
    invoke-virtual {{v1}}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v2
    new-instance v3, Ljava/lang/StringBuilder;
    invoke-direct {{v3}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v4, "FSRInit ContentProvider onCreate() pkg="
    invoke-virtual {{v3, v4}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    invoke-virtual {{v3, v2}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    invoke-virtual {{v3}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v3
    invoke-static {{v0, v3}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    # Log nativeLibraryDir and config existence
    invoke-virtual {{p0}}, Landroid/content/ContentProvider;->getContext()Landroid/content/Context;
    move-result-object v1
    invoke-virtual {{v1}}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;
    move-result-object v1
    iget-object v2, v1, Landroid/content/pm/ApplicationInfo;->nativeLibraryDir:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;
    invoke-direct {{v3}}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {{v3, v2}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    const-string v4, "/libfrida-gadget.config.so"
    invoke-virtual {{v3, v4}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v3
    invoke-virtual {{v3}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v3

    new-instance v4, Ljava/io/File;
    invoke-direct {{v4, v3}}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {{v4}}, Ljava/io/File;->exists()Z
    move-result v5

    new-instance v6, Ljava/lang/StringBuilder;
    invoke-direct {{v6}}, Ljava/lang/StringBuilder;-><init>()V
    const-string v7, "Gadget config: "
    invoke-virtual {{v6, v7}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v6
    invoke-virtual {{v6, v3}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v6
    const-string v7, " exists="
    invoke-virtual {{v6, v7}}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v6
    invoke-virtual {{v6, v5}}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;
    move-result-object v6
    invoke-virtual {{v6}}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v6
    invoke-static {{v0, v6}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    const-string v0, "frida-gadget"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
""".strip()
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(content + "\n")
        return True
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] Write provider smali failed: {e}")
        return False


def _inject_provider_manifest(manifest_path: str, provider_class: str, authorities: str):
    try:
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        android_ns = '{http://schemas.android.com/apk/res/android}'
        app = None
        for child in root.iter():
            if child.tag.endswith('application'):
                app = child
                break
        if app is None:
            raise RuntimeError('application tag not found')
        for prov in app.iter():
            if not getattr(prov, 'tag', '').endswith('provider'):
                continue
            name = prov.get(android_ns + 'name', '') or prov.get('android:name', '') or prov.get('name', '')
            if name == provider_class:
                return True, 'provider already present'
        prov = ET.SubElement(app, 'provider')
        prov.set(android_ns + 'name', provider_class)
        prov.set(android_ns + 'authorities', authorities)
        prov.set(android_ns + 'exported', 'false')
        prov.set(android_ns + 'initOrder', '199999')
        tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
        return True, 'xml injection ok'
    except Exception as e:
        log_to_fsr_logs(f"[GADGET] XML inject provider failed: {e}. Trying text fallback")
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            if provider_class in txt:
                return True, 'provider found by text search'
            import re
            snippet = (
                f'    <provider android:name="{provider_class}" '
                f'android:authorities="{authorities}" '
                f'android:exported="false" android:initOrder="199999" />\n'
            )
            m = re.search(r'</application\s*>', txt, re.IGNORECASE)
            if m:
                pos = m.start()
                new_txt = txt[:pos] + snippet + txt[pos:]
                method = 'inserted before </application>'
            else:
                m2 = re.search(r'<application[^>]*>', txt, re.IGNORECASE | re.DOTALL)
                if m2:
                    pos = m2.end()
                    new_txt = txt[:pos] + '\n' + snippet + txt[pos:]
                    method = 'inserted after <application>'
                else:
                    mp = re.search(r'<provider\b', txt, re.IGNORECASE)
                    if mp:
                        pos = mp.start()
                        new_txt = txt[:pos] + snippet + txt[pos:]
                        method = 'inserted before first <provider>'
                    else:
                        ma = re.search(r'<activity\b', txt, re.IGNORECASE)
                        if ma:
                            pos = ma.start()
                            new_txt = txt[:pos] + snippet + txt[pos:]
                            method = 'inserted before first <activity>'
                        else:
                            raise RuntimeError('application tags not found for text injection (no <application>, <provider>, or <activity>)')
            if 'xmlns:android' not in new_txt:
                new_txt = new_txt.replace('<manifest', '<manifest xmlns:android="http://schemas.android.com/apk/res/android"', 1)
            with open(manifest_path, 'w', encoding='utf-8') as f:
                f.write(new_txt)
            return True, f'text injection ok ({method})'
        except Exception as e2:
            log_to_fsr_logs(f"[GADGET] Text inject provider failed: {e2}")
            return False, f'text injection failed: {e2}'


def _list_smali_roots(workdir: str):
    roots = []
    try:
        for name in os.listdir(workdir):
            p = os.path.join(workdir, name)
            if os.path.isdir(p) and name.startswith('smali'):
                roots.append(p)
    except Exception:
        pass
    roots.sort(key=lambda d: (0 if os.path.basename(d) == 'smali' else 1, d))
    return roots


def _find_main_activity(manifest_path: str) -> str:
    try:
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        android_ns = '{http://schemas.android.com/apk/res/android}'
        package_name = root.get('package', '') or _read_manifest_package(manifest_path) or ''
        app = None
        for child in root.iter():
            if child.tag.endswith('application'):
                app = child
                break
        if app is None:
            raise RuntimeError('application not found while resolving main activity')
        for act in app.iter():
            if not getattr(act, 'tag', '').endswith('activity'):
                continue
            has_main = False
            has_launcher = False
            for ifil in act.iter():
                if not getattr(ifil, 'tag', '').endswith('intent-filter'):
                    continue
                for a in ifil.iter():
                    if getattr(a, 'tag', '').endswith('action'):
                        nm = a.get(android_ns + 'name', '') or a.get('name', '')
                        if nm == 'android.intent.action.MAIN':
                            has_main = True
                    if getattr(a, 'tag', '').endswith('category'):
                        nm = a.get(android_ns + 'name', '') or a.get('name', '')
                        if nm == 'android.intent.category.LAUNCHER':
                            has_launcher = True
            if has_main and has_launcher:
                name = act.get(android_ns + 'name', '') or act.get('name', '')
                if not name:
                    continue
                if name.startswith('.'):
                    return (package_name + name)
                if '.' not in name and package_name:
                    return package_name + '.' + name
                return name
    except Exception:
        pass
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            txt = f.read()
        import re
        pkg = _read_manifest_package(manifest_path) or ''
        m = re.search(r'<activity[^>]*android:name="([^"]+)"', txt)
        if m:
            name = m.group(1)
            if name.startswith('.'):
                return pkg + name
            if '.' not in name and pkg:
                return pkg + '.' + name
            return name
    except Exception:
        pass
    return ''


def _resolve_class_to_smali_path(smali_roots, class_name: str) -> str:
    if not class_name:
        return None
    rel = os.path.join(*class_name.split('.')) + '.smali'
    for root in smali_roots:
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            return p
    return None


def _inject_oncreate_load_gadget(smali_file: str):
    try:
        with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        start_idx = -1
        end_idx = -1
        locals_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('.method') and ' onCreate(' in line and ')V' in line:
                start_idx = i
                for j in range(i + 1, len(lines)):
                    if lines[j].strip().startswith('.end method'):
                        end_idx = j
                        break
                for j in range(i + 1, end_idx if end_idx != -1 else len(lines)):
                    if lines[j].strip().startswith('.locals'):
                        locals_idx = j
                        break
                break
        load_snippet = [
            '    const-string v0, "frida-gadget"\n',
            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
        ]
        if start_idx != -1 and end_idx != -1:
            if locals_idx != -1:
                try:
                    parts = lines[locals_idx].strip().split()
                    n = int(parts[-1])
                except Exception:
                    n = 1
                if n < 1:
                    lines[locals_idx] = lines[locals_idx].replace(str(n), '1')
            else:
                lines.insert(start_idx + 1, '    .locals 1\n')
            insert_at = end_idx
            for k in range(end_idx - 1, start_idx, -1):
                if lines[k].strip().startswith('return-void'):
                    insert_at = k
                    break
            lines[insert_at:insert_at] = load_snippet
            with open(smali_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, 'patched existing onCreate'
        else:
            new_method = (
                '\n.method protected onCreate(Landroid/os/Bundle;)V\n'
                '    .locals 1\n'
                '    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n'
                '    const-string v0, "frida-gadget"\n'
                '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                '    return-void\n'
                '.end method\n'
            )
            lines.append(new_method)
            with open(smali_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, 'added new onCreate'
    except Exception as e:
        return False, f'smali injection failed: {e}'


def _inject_application_oncreate(smali_file: str):
    try:
        with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        start_idx = -1
        end_idx = -1
        locals_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('.method') and ' onCreate(' in line and ')V' in line and 'static' not in line:
                start_idx = i
                for j in range(i + 1, len(lines)):
                    if lines[j].strip().startswith('.end method'):
                        end_idx = j
                        break
                for j in range(i + 1, end_idx if end_idx != -1 else len(lines)):
                    if lines[j].strip().startswith('.locals'):
                        locals_idx = j
                        break
                break
        load_snippet = [
            '    const-string v0, "frida-gadget"\n',
            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
        ]
        if start_idx != -1 and end_idx != -1:
            if locals_idx != -1:
                try:
                    parts = lines[locals_idx].strip().split()
                    n = int(parts[-1])
                except Exception:
                    n = 1
                if n < 1:
                    lines[locals_idx] = lines[locals_idx].replace(str(n), '1')
            else:
                lines.insert(start_idx + 1, '    .locals 1\n')
            insert_at = end_idx
            for k in range(end_idx - 1, start_idx, -1):
                if lines[k].strip().startswith('return-void'):
                    insert_at = k
                    break
            lines[insert_at:insert_at] = load_snippet
            with open(smali_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, 'patched Application.onCreate'
        else:
            new_method = (
                '\n.method public onCreate()V\n'
                '    .locals 1\n'
                '    const-string v0, "frida-gadget"\n'
                '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                '    invoke-super {p0}, Landroid/app/Application;->onCreate()V\n'
                '    return-void\n'
                '.end method\n'
            )
            lines.append(new_method)
            with open(smali_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, 'added Application.onCreate'
    except Exception as e:
        return False, f'application smali injection failed: {e}'


def _inject_component_factory_instantiate(smali_file: str):
    try:
        with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        start_idx = -1
        end_idx = -1
        locals_idx = -1
        sig = ' instantiateApplication(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;'
        for i, line in enumerate(lines):
            if line.strip().startswith('.method') and sig in line:
                start_idx = i
                for j in range(i + 1, len(lines)):
                    if lines[j].strip().startswith('.end method'):
                        end_idx = j
                        break
                for j in range(i + 1, end_idx if end_idx != -1 else len(lines)):
                    if lines[j].strip().startswith('.locals'):
                        locals_idx = j
                        break
                break
        load_snippet = [
            '    const-string v0, "frida-gadget"\n',
            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
        ]
        if start_idx != -1 and end_idx != -1:
            if locals_idx != -1:
                try:
                    parts = lines[locals_idx].strip().split()
                    n = int(parts[-1])
                except Exception:
                    n = 1
                if n < 1:
                    lines[locals_idx] = lines[locals_idx].replace(str(n), '1')
            else:
                lines.insert(start_idx + 1, '    .locals 1\n')
            insert_at = start_idx + 1
            lines[insert_at:insert_at] = load_snippet
            with open(smali_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, 'patched ComponentFactory.instantiateApplication'
        else:
            return False, 'instantiateApplication not found'
    except Exception as e:
        return False, f'component factory injection failed: {e}'


def _fallback_activity_autoload(workdir: str, manifest_path: str):
    try:
        smali_roots = _list_smali_roots(workdir)
        if not smali_roots:
            return False, 'no smali roots found'
        main_cls = _find_main_activity(manifest_path)
        if not main_cls:
            return False, 'main activity not found'
        smali_path = _resolve_class_to_smali_path(smali_roots, main_cls)
        if not smali_path:
            return False, f'smali for {main_cls} not found'
        ok, info = _inject_oncreate_load_gadget(smali_path)
        return ok, f'{main_cls}: {info}'
    except Exception as e:
        return False, f'activity autoload failed: {e}'

def _is_smali_class_final(smali_roots, class_name: str) -> bool:
    try:
        p = _resolve_class_to_smali_path(smali_roots, class_name)
        if not p or not os.path.exists(p):
            return False
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                s = line.strip()
                if s.startswith('.class'):
                    # e.g., ".class public final Lcom/example/App;"
                    parts = s.split()
                    return 'final' in parts
                if s and not s.startswith('.'):
                    # stop early once class header passed
                    break
    except Exception:
        pass
    return False

def _run_apktool_build(apktool_path: str, workdir: str, out_apk: str):
    """Build APK with apktool. Try aapt2 first, then fall back to aapt1 if needed."""
    def _cmd(use_aapt2: bool):
        apktool_lower = apktool_path.lower()
        base = ['java', '-jar', apktool_path, 'b', workdir, '-o', out_apk, '-f'] if apktool_lower.endswith('.jar') else [apktool_path, 'b', workdir, '-o', out_apk, '-f']
        return base + (['--use-aapt2'] if use_aapt2 else [])

    cmd_aapt2 = _cmd(True)
    result = subprocess.run(cmd_aapt2, capture_output=True, text=True, timeout=900)
    if result.returncode == 0:
        return

    out = (result.stderr or '') + ("\n" + result.stdout if result.stdout else '')
    log_to_fsr_logs(f"[GADGET][apktool] aapt2 build failed, will try aapt1 fallback: {out[:4000]}")

    cmd_aapt1 = _cmd(False)
    result2 = subprocess.run(cmd_aapt1, capture_output=True, text=True, timeout=900)
    if result2.returncode != 0:
        out2 = (result2.stderr or '') + ("\n" + result2.stdout if result2.stdout else '')
        raise RuntimeError(out2 or out)


def _run_apktool_decode(apktool_path: str, apk_path: str, out_dir: str):
    apktool_lower = apktool_path.lower()
    if apktool_lower.endswith('.jar'):
        cmd = ['java', '-jar', apktool_path, 'd', apk_path, '-o', out_dir, '-f', '-r', '--use-aapt2']
    elif apktool_lower.endswith(('.exe', '.bat')):
        cmd = [apktool_path, 'd', apk_path, '-o', out_dir, '-f', '-r', '--use-aapt2']
    else:
        cmd = [apktool_path, 'd', apk_path, '-o', out_dir, '-f', '-r', '--use-aapt2']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)


@app.route('/api/gadget/inject', methods=['POST'])
def api_gadget_inject():
    try:
        if 'apkFile' not in request.files:
            return jsonify({'success': False, 'error': 'No APK file uploaded'}), 400

        file = request.files['apkFile']
        if not file.filename.endswith('.apk'):
            return jsonify({'success': False, 'error': 'Only APK files are supported for gadget injection'}), 400

        log_to_fsr_logs(f"[GADGET] Upload received: {file.filename}")

        arch = (request.form.get('arch') or 'arm64-v8a').strip()
        version = (request.form.get('version') or '').strip() or None
        script_choice = (request.form.get('script_choice') or '').strip()
        script_text = (request.form.get('script_text') or '').strip()
        autoload_raw = (request.form.get('autoload') or '').strip().lower()
        autoload = autoload_raw in ('1', 'true', 'on', 'yes')

        # Save upload
        filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(upload_path)
        try:
            fsize = os.path.getsize(upload_path)
        except Exception:
            fsize = -1
        log_to_fsr_logs(f"[GADGET] Saved to {upload_path} (size={fsize} bytes)")

        apktool_path = _find_apktool_from_resources()
        if apktool_path:
            log_to_fsr_logs(f"[GADGET] Using bundled apktool: {apktool_path}")
        else:
            try:
                from sslpindetect import SSLPinDetector
                detector_temp = SSLPinDetector()
                apktool_path = detector_temp.apktool_path or detector_temp._find_apktool()
            except Exception:
                apktool_path = None

        if not apktool_path or not os.path.exists(apktool_path):
            apktool_path = shutil.which('apktool')
        if not apktool_path:
            try:
                if os.path.exists(upload_path):
                    os.remove(upload_path)
            except Exception:
                pass
            return jsonify({'success': False, 'error': 'Apktool not found in environment. Use the provided Docker image or install apktool on host.'}), 400
        log_to_fsr_logs(f"[GADGET] Using apktool at: {apktool_path}")

        workdir = tempfile.mkdtemp(prefix='gadget_inject_')
        out_unsigned = os.path.join(workdir, 'gadget-injected-unsigned.apk')
        out_aligned = os.path.join(workdir, 'gadget-injected-aligned.apk')

        @after_this_request
        def _cleanup_files(response):
            try:
                if os.path.exists(upload_path):
                    os.remove(upload_path)
            except Exception:
                pass
            try:
                if os.path.isdir(workdir):
                    shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass
            return response

        try:
            _run_apktool_decode_full(apktool_path, upload_path, workdir)
        except Exception as e:
            raise RuntimeError(f'decompile failed: {e}')
        log_to_fsr_logs(f"[GADGET] Decompile OK -> {workdir}")

        manifest_path = _find_manifest_file(workdir)
        if not os.path.exists(manifest_path):
            raise RuntimeError('AndroidManifest.xml not found after decompile')
        _debug_log_manifest(manifest_path)
        is_split, details = _detect_split_apk(manifest_path)
        if is_split:
            raise RuntimeError(f'APK appears to be a split (no base Application/Launcher). Details: {details}. Please use a base/universal APK.')

        lib_dir = os.path.join(workdir, 'lib', arch)
        os.makedirs(lib_dir, exist_ok=True)
        gadget_out = os.path.join(lib_dir, 'libfrida-gadget.so')
        if version:
            try:
                cached = _ensure_cached_gadget(arch, version)
                shutil.copyfile(cached, gadget_out)
                log_to_fsr_logs(f"[GADGET] Using cached gadget {version} for {arch}")
            except Exception as e:
                raise RuntimeError(f'Failed to obtain cached gadget {version} {arch}: {e}')
        else:
            gadget_url = get_frida_gadget_url(arch, version)
            if not gadget_url:
                raise RuntimeError(f'No frida-gadget asset found for arch {arch} version latest')
            log_to_fsr_logs(f"[GADGET] Gadget target arch={arch} version=latest url={gadget_url}")
            download_path = os.path.join(workdir, 'frida-gadget.so.xz')
            log_to_fsr_logs(f"[GADGET] Downloading: {gadget_url}")
            wget.download(gadget_url, download_path)
            with lzma.open(download_path) as src, open(gadget_out, 'wb') as dst:
                shutil.copyfileobj(src, dst)
            if os.path.exists(download_path):
                os.remove(download_path)
        try:
            gsize = os.path.getsize(gadget_out)
        except Exception:
            gsize = -1
        log_to_fsr_logs(f"[GADGET] Saved gadget to {gadget_out} (size={gsize} bytes)")

        chosen_script_content = None
        if 'script_file' in request.files and request.files['script_file'] and request.files['script_file'].filename:
            sf = request.files['script_file']
            chosen_script_content = sf.read().decode('utf-8', errors='ignore')
            log_to_fsr_logs(f"[GADGET] Script source: upload ({len(chosen_script_content)} bytes)")
        elif script_text:
            chosen_script_content = script_text
            log_to_fsr_logs(f"[GADGET] Script source: pasted ({len(chosen_script_content)} bytes)")
        elif script_choice:
            try:
                repo_script_path = os.path.join('scripts', script_choice)
                with open(repo_script_path, 'r', encoding='utf-8', errors='ignore') as rf:
                    chosen_script_content = rf.read()
                log_to_fsr_logs(f"[GADGET] Script source: repo {script_choice} ({len(chosen_script_content)} bytes)")
            except Exception:
                chosen_script_content = None
                log_to_fsr_logs(f"[GADGET] Script source: repo {script_choice} not found")

        script_relname = None
        wrapped_source = None
        if chosen_script_content:
            try:
                wrapped_source = (
                    "(function(){\n"
                    "  var __src = " + json.dumps(chosen_script_content) + ";\n"
                    "  try {\n"
                    "    Java.perform(function() {\n"
                    "      try {\n"
                    "        eval(__src + '\\n//# sourceURL=fsr-uploaded-script.js');\n"
                    "        try {\n"
                    "          var Log = Java.use('android.util.Log');\n"
                    "          var At = Java.use('android.app.ActivityThread');\n"
                    "          var pkg = '';\n"
                    "          try { pkg = At.currentPackageName(); } catch(e) {}\n"
                    "          Log.i('FSR', 'Gadget script loaded' + (pkg ? ' pkg=' + pkg : ''));\n"
                    "        } catch (e) {}\n"
                    "      } catch (e) {\n"
                    "        try {\n"
                    "          var Log = Java.use('android.util.Log');\n"
                    "          Log.e('FSR', 'Script error: ' + e);\n"
                    "          Log.e('FSR', String(e.stack || e));\n"
                    "        } catch (ie) {}\n"
                    "        console.log('[FSR] Script error: ' + e + '\\n' + (e.stack||''));\n"
                    "      }\n"
                    "    });\n"
                    "  } catch (e) {\n"
                    "    try { eval(__src + '\\n//# sourceURL=fsr-uploaded-script.js'); } catch (ee) {}\n"
                    "  }\n"
                    "})();\n"
                )
            except Exception:
                wrapped_source = chosen_script_content

            script_relname = 'libfsr-gadget-script.js.so'
            script_abs = os.path.join(lib_dir, script_relname)
            with open(script_abs, 'w', encoding='utf-8') as sf:
                sf.write(wrapped_source if wrapped_source.endswith('\n') else wrapped_source + '\n')
            log_to_fsr_logs(f"[GADGET] Wrote script to {script_abs}")

        config_path = os.path.join(lib_dir, 'libfrida-gadget.config.so')
        cfg = {}
        if chosen_script_content:
            try:
                wrapped_source = (
                    "(function(){\n"
                    "  var __src = " + json.dumps(chosen_script_content) + ";\n"
                    "  try {\n"
                    "    Java.perform(function() {\n"
                    "      try {\n"
                    "        eval(__src + '\\n//# sourceURL=fsr-uploaded-script.js');\n"
                    "        try {\n"
                    "          var Log = Java.use('android.util.Log');\n"
                    "          var At = Java.use('android.app.ActivityThread');\n"
                    "          var pkg = '';\n"
                    "          try { pkg = At.currentPackageName(); } catch(e) {}\n"
                    "          Log.i('FSR', 'Gadget script loaded' + (pkg ? ' pkg=' + pkg : ''));\n"
                    "        } catch (e) {}\n"
                    "      } catch (e) {\n"
                    "        try {\n"
                    "          var Log = Java.use('android.util.Log');\n"
                    "          Log.e('FSR', 'Script error: ' + e);\n"
                    "          Log.e('FSR', String(e.stack || e));\n"
                    "        } catch (ie) {}\n"
                    "        console.log('[FSR] Script error: ' + e + '\\n' + (e.stack||''));\n"
                    "      }\n"
                    "    });\n"
                    "  } catch (e) {\n"
                    "    try { eval(__src + '\\n//# sourceURL=fsr-uploaded-script.js'); } catch (ee) {}\n"
                    "  }\n"
                    "})();\n"
                )
            except Exception:
                wrapped_source = chosen_script_content

            cfg['interaction'] = {
                'type': 'script',
                'path': script_relname
            }
        else:
            cfg['interaction'] = {
                'type': 'listen',
                'address': '127.0.0.1',
                'port': 27042
            }
        with open(config_path, 'w', encoding='utf-8') as cf:
            cf.write(json.dumps(cfg, indent=2))
        log_to_fsr_logs(f"[GADGET] Wrote gadget config to {config_path} (mode={'script' if chosen_script_content else 'listen'})")

        if autoload:
            smali_dir = _determine_smali_dir(workdir)
            if not smali_dir:
                raise RuntimeError('Could not find smali directory in decompiled APK')

            app_class = 'com.fsr.FSRApp'
            manifest_ok = _modify_manifest_add_application(manifest_path, app_class)
            if manifest_ok:
                smali_ok = _write_application_smali(smali_dir, app_class)
                if not smali_ok:
                    raise RuntimeError('Failed to write Application smali')
                log_to_fsr_logs("[GADGET] Autoload via new Application (no existing android:name)")
            else:
                base_app = _get_manifest_application_name(manifest_path)
                log_to_fsr_logs(f"[GADGET] Existing Application detected: {base_app or '(none)'}")
                if base_app:
                    is_final = _is_smali_class_final(_list_smali_roots(workdir), base_app)
                    if is_final:
                        log_to_fsr_logs(f"[GADGET] Base Application '{base_app}' is final; skipping wrapper and using alternatives")
                        base_cf = _get_manifest_component_factory(manifest_path)
                        cf_wrapper = 'com.fsr.AppCF'
                        cf_ok = _write_component_factory_wrapper_smali(smali_dir, cf_wrapper, base_cf or 'android.app.AppComponentFactory')
                        if cf_ok and _modify_manifest_set_component_factory(manifest_path, cf_wrapper):
                            log_to_fsr_logs(f"[GADGET] Autoload via ComponentFactory wrapper: {cf_wrapper} extends {base_cf or 'android.app.AppComponentFactory'}")
                        else:
                            log_to_fsr_logs("[GADGET] ComponentFactory wrapper failed; trying provider/Activity fallbacks")
                            package_name = _read_manifest_package(manifest_path) or 'com.fsr'
                            provider_class = 'com.fsr.FSRInit'
                            authorities = f"{package_name}.fsrinit"
                            prov_smali_ok = _write_provider_smali(smali_dir, provider_class)
                            if not prov_smali_ok:
                                raise RuntimeError('Failed to write ContentProvider smali')
                            prov_manifest_ok, prov_info = _inject_provider_manifest(manifest_path, provider_class, authorities)
                            if not prov_manifest_ok:
                                log_to_fsr_logs(f"[GADGET] Provider injection failed: {prov_info}. Trying activity fallback autoload")
                                act_ok, act_info = _fallback_activity_autoload(workdir, manifest_path)
                                if not act_ok:
                                    raise RuntimeError(f'Failed to inject ContentProvider into manifest: {prov_info}; Activity fallback failed: {act_info}')
                                else:
                                    log_to_fsr_logs(f"[GADGET] Activity autoload details: {act_info}")
                            else:
                                log_to_fsr_logs(f"[GADGET] Autoload via provider: {prov_info}")
                    else:
                        wrapper_class = 'com.fsr.AppWrapper'
                        w_ok = _write_app_wrapper_smali(smali_dir, wrapper_class, base_app)
                        if w_ok and _modify_manifest_set_application(manifest_path, wrapper_class):
                            log_to_fsr_logs(f"[GADGET] Autoload via Application wrapper: {wrapper_class} extends {base_app}")
                        else:
                            log_to_fsr_logs("[GADGET] App wrapper failed; trying ComponentFactory wrapper")
                            base_cf = _get_manifest_component_factory(manifest_path)
                            cf_wrapper = 'com.fsr.AppCF'
                            cf_ok = _write_component_factory_wrapper_smali(smali_dir, cf_wrapper, base_cf or 'android.app.AppComponentFactory')
                            if cf_ok and _modify_manifest_set_component_factory(manifest_path, cf_wrapper):
                                log_to_fsr_logs(f"[GADGET] Autoload via ComponentFactory wrapper: {cf_wrapper} extends {base_cf or 'android.app.AppComponentFactory'}")
                            else:
                                log_to_fsr_logs("[GADGET] ComponentFactory wrapper failed; trying provider/Activity fallbacks")
                                package_name = _read_manifest_package(manifest_path) or 'com.fsr'
                                provider_class = 'com.fsr.FSRInit'
                                authorities = f"{package_name}.fsrinit"
                                prov_smali_ok = _write_provider_smali(smali_dir, provider_class)
                                if not prov_smali_ok:
                                    raise RuntimeError('Failed to write ContentProvider smali')
                                prov_manifest_ok, prov_info = _inject_provider_manifest(manifest_path, provider_class, authorities)
                                if not prov_manifest_ok:
                                    log_to_fsr_logs(f"[GADGET] Provider injection failed: {prov_info}. Trying activity fallback autoload")
                                    act_ok, act_info = _fallback_activity_autoload(workdir, manifest_path)
                                    if not act_ok:
                                        raise RuntimeError(f'Failed to inject ContentProvider into manifest: {prov_info}; Activity fallback failed: {act_info}')
                                    else:
                                        log_to_fsr_logs(f"[GADGET] Activity autoload details: {act_info}")
                                else:
                                    log_to_fsr_logs(f"[GADGET] Autoload via provider: {prov_info}")
                else:
                    # No android:name present; try ComponentFactory wrapper directly
                    log_to_fsr_logs("[GADGET] No Application name; trying ComponentFactory wrapper first")
                    base_cf = _get_manifest_component_factory(manifest_path)
                    cf_wrapper = 'com.fsr.AppCF'
                    cf_ok = _write_component_factory_wrapper_smali(smali_dir, cf_wrapper, base_cf or 'android.app.AppComponentFactory')
                    if cf_ok and _modify_manifest_set_component_factory(manifest_path, cf_wrapper):
                        log_to_fsr_logs(f"[GADGET] Autoload via ComponentFactory wrapper: {cf_wrapper} extends {base_cf or 'android.app.AppComponentFactory'}")
                    else:
                        # Fall back to provider/activity
                        package_name = _read_manifest_package(manifest_path) or 'com.fsr'
                        provider_class = 'com.fsr.FSRInit'
                        authorities = f"{package_name}.fsrinit"
                        prov_smali_ok = _write_provider_smali(smali_dir, provider_class)
                        if not prov_smali_ok:
                            raise RuntimeError('Failed to write ContentProvider smali')
                        prov_manifest_ok, prov_info = _inject_provider_manifest(manifest_path, provider_class, authorities)
                        if not prov_manifest_ok:
                            log_to_fsr_logs(f"[GADGET] Provider injection failed: {prov_info}. Trying activity fallback autoload")
                            act_ok, act_info = _fallback_activity_autoload(workdir, manifest_path)
                            if not act_ok:
                                raise RuntimeError(f'Failed to inject ContentProvider into manifest: {prov_info}; Activity fallback failed: {act_info}')
                            else:
                                log_to_fsr_logs(f"[GADGET] Activity autoload details: {act_info}")
                        else:
                            log_to_fsr_logs(f"[GADGET] Autoload via provider: {prov_info}")

            # As a final safety net, also patch MainActivity.onCreate to load the gadget
            try:
                ok, info = _fallback_activity_autoload(workdir, manifest_path)
                log_to_fsr_logs(f"[GADGET] Additional activity autoload attempt: {info}")
            except Exception as e:
                log_to_fsr_logs(f"[GADGET] Additional activity autoload skipped: {e}")

            # Best-effort: also register a ContentProvider autoload to increase reliability across OEMs/OS versions
            try:
                package_name = _read_manifest_package(manifest_path) or 'com.fsr'
                provider_class = 'com.fsr.FSRInit'
                authorities = f"{package_name}.fsrinit"
                prov_smali_ok = _write_provider_smali(smali_dir, provider_class)
                if prov_smali_ok:
                    prov_manifest_ok, prov_info = _inject_provider_manifest(manifest_path, provider_class, authorities)
                    log_to_fsr_logs(f"[GADGET] Additional provider autoload attempt: {prov_info}")
            except Exception as e:
                log_to_fsr_logs(f"[GADGET] Additional provider autoload skipped: {e}")

        # As some apps include invalid resource file names (e.g., $avd_*), sanitize first
        try:
            _sanitize_aapt_invalid_resources(workdir)
        except Exception as e:
            log_to_fsr_logs(f"[GADGET] Resource sanitize skipped: {e}")

        # Build unsigned APK
        log_to_fsr_logs("[GADGET] Building APK (apktool b)...")
        _run_apktool_build(apktool_path, workdir, out_unsigned)
        log_to_fsr_logs(f"[GADGET] Build OK -> {out_unsigned}")

        # Align + sign using Android build-tools (zipalign + apksigner)
        signed_path = None
        try:
            log_to_fsr_logs('[GADGET] Aligning and signing APK using Android build-tools')
            final_path = _fallback_align_and_sign(out_unsigned, workdir)
            signed_path = final_path
        except Exception as e:
            log_to_fsr_logs(f"[GADGET] Align/sign failed: {e}")

        # Fallback: return unsigned if signing still failed
        final_path = signed_path or out_unsigned
        dl_name = os.path.basename(final_path)
        if not dl_name.endswith('.apk'):
            dl_name += '.apk'
        try:
            fsz = os.path.getsize(final_path)
        except Exception:
            fsz = -1
        log_to_fsr_logs(f"[GADGET] Final APK: {final_path} (size={fsz} bytes)")
        # Sanity: ensure AndroidManifest.xml is compiled (binary), not text
        try:
            import zipfile
            with zipfile.ZipFile(final_path, 'r') as zf:
                with zf.open('AndroidManifest.xml') as mf:
                    head = mf.read(16)
                    if head.startswith(b'<?xml'):
                        log_to_fsr_logs('[GADGET] Warning: Manifest appears to be text, not compiled binary XML. Install may fail.')
        except Exception as _e:
            log_to_fsr_logs(f"[GADGET] Manifest sanity check skipped: {_e}")
        return send_file(final_path, as_attachment=True, download_name=dl_name, mimetype='application/vnd.android.package-archive')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scripts/list')
def api_list_scripts():
    try:
        items = []
        for name in os.listdir('scripts'):
            p = os.path.join('scripts', name)
            if os.path.isfile(p) and name.lower().endswith('.js'):
                items.append(name)
        items.sort()
        return jsonify({'success': True, 'files': items})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'files': []}), 500


def _find_build_tools_path():
    try:
        if os.name == 'nt':
            base = os.path.expandvars(r"%LOCALAPPDATA%\\Android\\Sdk\\build-tools")
            if os.path.isdir(base):
                versions = sorted(os.listdir(base), reverse=True)
                for v in versions:
                    p = os.path.join(base, v)
                    if os.path.isdir(p):
                        return p
        else:
            for env in ['ANDROID_HOME', 'ANDROID_SDK_ROOT']:
                root = os.environ.get(env)
                if not root:
                    continue
                bt = os.path.join(root, 'build-tools')
                if os.path.isdir(bt):
                    versions = sorted(os.listdir(bt), reverse=True)
                    for v in versions:
                        p = os.path.join(bt, v)
                        if os.path.isdir(p):
                            return p
    except Exception:
        pass
    return None


def _find_exe(names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _fallback_align_and_sign(unsigned_apk: str, workdir: str) -> str:
    bt = _find_build_tools_path()
    zipalign = None
    apksigner = None
    if bt:
        zipalign = os.path.join(bt, 'zipalign.exe' if os.name == 'nt' else 'zipalign')
        apksigner = os.path.join(bt, 'apksigner.bat' if os.name == 'nt' else 'apksigner')
    if not zipalign or not os.path.exists(zipalign):
        zipalign = _find_exe(['zipalign'])
    if not apksigner or not os.path.exists(apksigner):
        apksigner = _find_exe(['apksigner'])

    if not zipalign or not apksigner:
        raise RuntimeError('zipalign/apksigner not found in Android SDK build-tools or PATH')

    aligned = os.path.join(workdir, 'gadget-injected-aligned.apk')
    try:
        if os.path.exists(aligned):
            os.remove(aligned)
    except Exception:
        pass
    zr = subprocess.run([zipalign, '-v', '-p', '4', unsigned_apk, aligned], capture_output=True, text=True)
    if zr.returncode != 0:
        raise RuntimeError(f"zipalign failed: {zr.stderr or zr.stdout}")

    # Generate debug keystore if missing
    debug_keystore = os.path.join(workdir, 'debug.keystore')
    if not os.path.exists(debug_keystore):
        keytool = _find_exe(['keytool.exe', 'keytool'])
        if not keytool:
            raise RuntimeError('Java keytool not found to generate debug keystore')
        subprocess.run([
            keytool, '-genkey', '-v',
            '-keystore', debug_keystore,
            '-alias', 'androiddebugkey',
            '-storepass', 'android',
            '-keypass', 'android',
            '-keyalg', 'RSA',
            '-keysize', '2048',
            '-validity', '10000',
            '-dname', 'CN=Android Debug,O=Android,C=US'
        ], check=True, capture_output=True, text=True)

    signed = os.path.join(workdir, 'gadget-injected-signed.apk')
    cmd = [
        apksigner, 'sign',
        '--min-sdk-version', '27',
        '--ks', debug_keystore,
        '--ks-pass', 'pass:android',
        '--key-pass', 'pass:android',
        '--ks-key-alias', 'androiddebugkey',
        '--out', signed,
        aligned
    ]
    sr = subprocess.run(cmd, capture_output=True, text=True)
    if sr.returncode != 0:
        raise RuntimeError(f"apksigner failed: {sr.stderr or sr.stdout}")
    return signed

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
    

def run_ideviceinfo(timeout=2, udid=None):
    try:
        cmd = ["ideviceinfo"]
        if udid:
            cmd.extend(["-u", udid])
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""

def get_ios_devices():
    """Get list of connected iOS devices using idevice_id"""
    ios_devices = []
    try:
        result = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            udids = result.stdout.strip().split('\n')
            for udid in udids:
                if udid.strip():
                    device_info_output = run_ideviceinfo(timeout=3, udid=udid.strip())
                    if device_info_output:
                        deviceId = re.search(r'UniqueDeviceID:\s*([a-zA-Z0-9-]+)', device_info_output)
                        model = re.search(r'ProductType:\s*([\w\d,]+)', device_info_output)
                        device_name = re.search(r'DeviceName:\s*(.+)', device_info_output)
                        ios_version = re.search(r'ProductVersion:\s*([\d.]+)', device_info_output)
                        
                        device_data = {
                            "UDID": udid.strip(),
                            "type": "iOS"
                        }
                        
                        if model:
                            device_data["model"] = model.group(1).strip()
                        if device_name:
                            device_data["device_name"] = device_name.group(1).strip()
                        if ios_version:
                            device_data["ios_version"] = ios_version.group(1).strip()
                        
                        ios_devices.append(device_data)
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    
    return ios_devices

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
        result = run_adb_command(["adb", "devices"], timeout=5)
        
        if result and result.strip().startswith("Error:"):
            log_to_fsr_logs(f"[DEBUG] ADB devices command returned error: {result}")
            message = f"ADB command failed: {result}"
        else:
            lines = result.strip().split('\n') if result else []
            connected_devices = lines[1:] if len(lines) > 1 else []
            device_ids = []
            
            for line in connected_devices:
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        device_id = parts[0].strip()
                        state = parts[1].strip()
                        if state == "device":
                            device_ids.append(device_id)

            if device_ids:
                for device_id in device_ids:
                    device_added = False
                    try:
                        quick_check = run_adb_command(["adb", "-s", device_id, "shell", "echo", "test"], timeout=5)
                        if quick_check and not quick_check.strip().startswith("Error:") and "test" in quick_check:
                            try:
                                model = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.model"], timeout=5)
                            except:
                                model = None
                            
                            try:
                                serial_number = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.serialno"], timeout=5)
                            except:
                                serial_number = None
                            
                            try:
                                versi_andro = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"], timeout=5)
                            except:
                                versi_andro = None
                            
                            model_val = model.strip() if model and not model.strip().startswith("Error:") else "Unknown"
                            serial_val = serial_number.strip() if serial_number and not serial_number.strip().startswith("Error:") else device_id
                            versi_val = versi_andro.strip() if versi_andro and not versi_andro.strip().startswith("Error:") else "N/A"
                            
                            available_devices.append({
                                "device_id": device_id, 
                                "model": model_val, 
                                "serial_number": serial_val, 
                                "versi_andro": versi_val
                            })
                            device_added = True
                        else:
                            log_to_fsr_logs(f"[DEBUG] Device {device_id} quick check failed, but adding with minimal info")
                            available_devices.append({
                                "device_id": device_id, 
                                "model": "Unknown", 
                                "serial_number": device_id, 
                                "versi_andro": "N/A"
                            })
                            device_added = True
                    except Exception as e:
                        log_to_fsr_logs(f"[DEBUG] Error processing device {device_id}: {e}, adding with minimal info")
                        if not device_added:
                            available_devices.append({
                                "device_id": device_id, 
                                "model": "Unknown", 
                                "serial_number": device_id, 
                                "versi_andro": "N/A"
                            })
                
                if available_devices:
                    adb_is_active = True
                    message = f"{len(available_devices)} device(s) available"
                else:
                    message = "Devices detected but failed to get device info"
            else:
                message = "No devices in 'device' state found"
    except Exception as e:
        log_to_fsr_logs(f"[ERROR] Exception in there_is_adb_and_devices: {e}")
        message = f"Error checking Android device connectivity: {e}"
    
    if not adb_is_active:
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
    try:
        adb_check = there_is_adb_and_devices()
    except Exception as e:
        return render_template('no-usb.html')
    
    if adb_check["is_true"] and adb_check.get("available_devices"):
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

# adb gui
@app.route('/adb-gui', methods=['GET'])
def adb_gui_page():
    """
    Render ADB GUI page for managing Android devices and packages.
    """
    return render_template('adb-gui.html')


@app.route('/adb-gui/connect', methods=['POST'])
def adb_gui_connect():
    """
    Connect to ADB device via TCP/IP.
    """
    data = request.get_json(silent=True) or request.form
    ip = (data.get('ip') or '').strip()
    port = (str(data.get('port') or '')).strip()
    
    result = connect_adb(ip, port)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/devices', methods=['GET'])
def adb_gui_devices():
    """
    Get list of connected ADB devices.
    """
    result = get_devices()
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/device-info', methods=['GET'])
def adb_gui_device_info():
    """
    Get device information.
    """
    serial = request.args.get('serial', None)
    result = get_device_info(serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/packages', methods=['GET'])
def adb_gui_packages():
    """
    Get list of installed packages.
    """
    serial = request.args.get('serial', None)
    result = get_adb_packages(serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/package/clear', methods=['POST'])
def adb_gui_clear_package():
    """
    Clear data for a package.
    """
    data = request.get_json(silent=True) or request.form
    package_name = (data.get('package') or '').strip()
    serial = data.get('serial', None)
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name is required'}), 400
    
    result = clear_package_data(package_name, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/package/uninstall', methods=['POST'])
def adb_gui_uninstall_package():
    """
    Uninstall a package.
    """
    data = request.get_json(silent=True) or request.form
    package_name = (data.get('package') or '').strip()
    serial = data.get('serial', None)
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name is required'}), 400
    
    result = uninstall_package(package_name, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/package/force-stop', methods=['POST'])
def adb_gui_force_stop_package():
    """
    Force stop a package.
    """
    data = request.get_json(silent=True) or request.form
    package_name = (data.get('package') or '').strip()
    serial = data.get('serial', None)
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name is required'}), 400
    
    result = force_stop_package(package_name, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/package/install', methods=['POST'])
def adb_gui_install_package():
    """
    Install an APK package.
    """
    data = request.get_json(silent=True) or request.form
    apk_path = (data.get('apk_path') or '').strip()
    serial = data.get('serial', None)
    
    if not apk_path:
        return jsonify({'success': False, 'error': 'APK path is required'}), 400
    
    result = install_package(apk_path, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/processes', methods=['GET'])
def adb_gui_processes():
    """
    Get running processes.
    """
    serial = request.args.get('serial', None)
    result = get_running_processes(serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/memory-info', methods=['GET'])
def adb_gui_memory_info():
    """
    Get memory information for an app.
    """
    package_name = request.args.get('package', None)
    serial = request.args.get('serial', None)
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name is required'}), 400
    
    result = get_app_memory_info(package_name, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/system-memory', methods=['GET'])
def adb_gui_system_memory():
    """
    Get system memory information from /proc/meminfo.
    """
    serial = request.args.get('serial', None)
    result = get_system_memory_info(serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/disk-space', methods=['GET'])
def adb_gui_disk_space():
    """
    Get disk space information.
    """
    serial = request.args.get('serial', None)
    result = get_disk_space(serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/screen-info', methods=['GET'])
def adb_gui_screen_info():
    """
    Get screen information.
    """
    serial = request.args.get('serial', None)
    result = get_screen_info(serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/touch', methods=['POST'])
def adb_gui_touch():
    """
    Send touch event.
    """
    data = request.get_json(silent=True) or request.form
    x = int(data.get('x', 0))
    y = int(data.get('y', 0))
    serial = data.get('serial', None)
    
    result = send_touch_event(x, y, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/swipe', methods=['POST'])
def adb_gui_swipe():
    """
    Send swipe event.
    """
    data = request.get_json(silent=True) or request.form
    x1 = int(data.get('x1', 0))
    y1 = int(data.get('y1', 0))
    x2 = int(data.get('x2', 0))
    y2 = int(data.get('y2', 0))
    duration = int(data.get('duration', 300))
    serial = data.get('serial', None)
    
    result = send_swipe_event(x1, y1, x2, y2, duration, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/keyevent', methods=['POST'])
def adb_gui_keyevent():
    """
    Send key event.
    """
    data = request.get_json(silent=True) or request.form
    keycode = (data.get('keycode') or '').strip()
    serial = data.get('serial', None)
    
    if not keycode:
        return jsonify({'success': False, 'error': 'Keycode is required'}), 400
    
    result = send_key_event(keycode, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/text', methods=['POST'])
def adb_gui_text():
    """
    Send text input.
    """
    data = request.get_json(silent=True) or request.form
    text = (data.get('text') or '').strip()
    serial = data.get('serial', None)
    
    if not text:
        return jsonify({'success': False, 'error': 'Text is required'}), 400
    
    result = send_text(text, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/launch-app', methods=['POST'])
def adb_gui_launch_app():
    """
    Launch an app.
    """
    data = request.get_json(silent=True) or request.form
    package_name = (data.get('package') or '').strip()
    activity = data.get('activity', None)
    serial = data.get('serial', None)
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name is required'}), 400
    
    result = launch_app(package_name, activity, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/package-activity', methods=['GET'])
def adb_gui_package_activity():
    """
    Get main activity of a package.
    """
    package_name = request.args.get('package', None)
    serial = request.args.get('serial', None)
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name is required'}), 400
    
    result = get_package_activity(package_name, serial)
    status = 200 if result.get("success") else 500
    return jsonify(result), status


@app.route('/adb-gui/check-responsive', methods=['GET'])
def adb_gui_check_responsive():
    """
    Check if device is responsive.
    """
    serial = request.args.get('serial', None)
    result = check_device_responsive(serial)
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

        raw_output = subprocess.check_output(
            f"adb shell pm path {package_name}",
            shell=True,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        lines = [ln.strip() for ln in (raw_output or '').split('\n') if ln.strip()]
        apk_remote_paths = []
        for ln in lines:
            if ':' in ln:
                path = ln.split(':', 1)[1].strip()
                if path:
                    apk_remote_paths.append(path)

        if not apk_remote_paths:
            return "Failed to get APK path(s)", 500

        safe_package = re.sub(r'[^a-zA-Z0-9_.-]', '_', package_name)

        if len(apk_remote_paths) == 1:
            apk_path = apk_remote_paths[0]
            if custom_name:
                base_name = re.sub(r'\.apk$', '', custom_name, flags=re.IGNORECASE)
                apk_filename = f"{base_name}.apk"
            else:
                apk_filename = f"{safe_package}.apk"

            local_apk = os.path.join('tmp', apk_filename)

            pr = subprocess.run(
                f"adb pull \"{apk_path}\" \"{local_apk}\"",
                shell=True,
                capture_output=True,
                text=True
            )
            if pr.returncode != 0:
                return f"Failed to pull APK: {pr.stderr or pr.stdout}", 500
            try:
                if not os.path.exists(local_apk) or os.path.getsize(local_apk) == 0:
                    return "Pulled APK is empty or missing", 500
            except Exception:
                pass

            resp = send_file(
                local_apk,
                as_attachment=True,
                download_name=apk_filename
            )
            def _cleanup_single():
                try:
                    if os.path.exists(local_apk):
                        os.remove(local_apk)
                except Exception:
                    pass
            try:
                resp.call_on_close(_cleanup_single)
            except Exception:
                _cleanup_single()
            return resp

        timestamp = int(time.time())
        work_dir = os.path.join('tmp', f"{safe_package}_{timestamp}")
        os.makedirs(work_dir, exist_ok=True)

        pulled_files = []
        for remote in apk_remote_paths:
            name = os.path.basename(remote) or 'unknown.apk'
            local_path = os.path.join(work_dir, name)
            pr = subprocess.run(
                f"adb pull \"{remote}\" \"{local_path}\"",
                shell=True,
                capture_output=True,
                text=True
            )
            if pr.returncode != 0 or not os.path.exists(local_path) or (os.path.exists(local_path) and os.path.getsize(local_path) == 0):
                shutil.rmtree(work_dir, ignore_errors=True)
                return f"Failed to pull split APK '{name}': {pr.stderr or pr.stdout}", 500
            pulled_files.append(local_path)

        if custom_name:
            zip_name_root = re.sub(r'\.(apk|zip)$', '', custom_name, flags=re.IGNORECASE)
        else:
            zip_name_root = safe_package

        zip_filename = f"{zip_name_root}.zip"
        zip_path = os.path.join('tmp', zip_filename)

        import zipfile
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for f in pulled_files:
                zf.write(f, arcname=os.path.basename(f))

        resp = send_file(
            zip_path,
            as_attachment=True,
            download_name=zip_filename,
            mimetype='application/zip'
        )
        def _cleanup_zip():
            try:
                if os.path.exists(zip_path):
                    os.remove(zip_path)
            except Exception:
                pass
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass
        try:
            resp.call_on_close(_cleanup_zip)
        except Exception:
            _cleanup_zip()
        return resp

    except Exception as e:
        return f"Error: {str(e)}", 500
            
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
        # Optional extra CLI parameters for frida
        frida_extra_args = request.form.get('frida_args', '').strip()

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

        socketio.start_background_task(run_frida_with_socketio, script_path, package, frida_extra_args)


        return jsonify({"result": f'Successfully started Frida on {package} using {selected_script}'}), 200
    except KeyboardInterrupt:
        return jsonify({"error": "Frida process interrupted by user."}), 500
    except Exception as e:
        return jsonify({"error": f"Error: {e}"}), 500

    
def run_frida_with_socketio(script_path, package, frida_extra_args:str = ""):
    global process, frida_output_buffer, last_frida_command

    try:
        frida_output_buffer = []
        command = ["frida", "-l", script_path, "-U", "-f", package]
        extra_args_list = []
        if frida_extra_args:
            try:
                import shlex
                extra_args_list = shlex.split(frida_extra_args)
            except Exception:
                extra_args_list = [arg for arg in frida_extra_args.split(" ") if arg]
        if extra_args_list:
            command.extend(extra_args_list)

        last_frida_command = " ".join(
            [
                (f'"{c}"' if (" " in c and not c.startswith("\"")) else c)
                for c in command
            ]
        )
        socketio.emit("output", {"data": f"[COMMAND] {last_frida_command}\n"})

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,
        )
        
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

@app.route('/send-frida-input', methods=['POST'])
def send_frida_input():
    """Send interactive input to the running Frida CLI process."""
    global process
    try:
        if not process or process.poll() is not None:
            return jsonify({"success": False, "error": "Frida process is not running"}), 400

        data = request.get_json(silent=True) or {}
        user_input = data.get('input', '')
        if user_input is None:
            user_input = ''

        with process_input_lock:
            try:
                process.stdin.write(user_input + "\n")
                process.stdin.flush()
            except Exception as e:
                return jsonify({"success": False, "error": f"Failed to send input: {e}"}), 500

        socketio.emit("output", {"data": f"[INPUT] {user_input}\n"})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

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

@app.route('/api/devices/list')
def api_devices_list():
    """Get list of all connected devices (Android and iOS)"""
    try:
        all_devices = []
        
        try:
            result = run_adb_command(["adb", "devices", "-l"], timeout=5)
            if result and not result.strip().startswith("Error:"):
                lines = result.strip().split('\n') if result else []
                connected_devices = lines[1:] if len(lines) > 1 else []
                
                for line in connected_devices:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            device_id = parts[0].strip()
                            state = parts[1].strip()
                            if state == "device":
                                try:
                                    model = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.model"], timeout=3)
                                    serial_number = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.serialno"], timeout=3)
                                    android_version = run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"], timeout=3)
                                    
                                    model_val = model.strip() if model and not model.strip().startswith("Error:") else "Unknown"
                                    serial_val = serial_number.strip() if serial_number and not serial_number.strip().startswith("Error:") else device_id
                                    versi_val = android_version.strip() if android_version and not android_version.strip().startswith("Error:") else "N/A"
                                    
                                    all_devices.append({
                                        "device_id": device_id,
                                        "identifier": device_id,
                                        "type": "Android",
                                        "model": model_val,
                                        "serial_number": serial_val,
                                        "android_version": versi_val,
                                        "display_name": f"{model_val} ({device_id})"
                                    })
                                except Exception:
                                    all_devices.append({
                                        "device_id": device_id,
                                        "identifier": device_id,
                                        "type": "Android",
                                        "model": "Unknown",
                                        "serial_number": device_id,
                                        "android_version": "N/A",
                                        "display_name": f"Android Device ({device_id})"
                                    })
        except Exception:
            pass
        
        ios_devices = get_ios_devices()
        for ios_device in ios_devices:
            display_name = ios_device.get("device_name", ios_device.get("model", "iOS Device"))
            if ios_device.get("ios_version"):
                display_name += f" (iOS {ios_device['ios_version']})"
            all_devices.append({
                "udid": ios_device.get("UDID", ""),
                "identifier": ios_device.get("UDID", ""),
                "type": "iOS",
                "model": ios_device.get("model", "Unknown"),
                "device_name": ios_device.get("device_name", "Unknown"),
                "ios_version": ios_device.get("ios_version", "N/A"),
                "display_name": f"{display_name} ({ios_device.get('UDID', '')[:8]}...)"
            })
        
        return jsonify({
            "success": True,
            "devices": all_devices,
            "count": len(all_devices)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "devices": [],
            "count": 0
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

@app.route('/sslpindec/packages', methods=['GET'])
def sslpindetect_packages():
    """Get list of installed Android packages for SSL pinning detection"""
    try:
        adb_check = there_is_adb_and_devices()
        if not adb_check["is_true"]:
            return jsonify({
                'success': False,
                'error': 'No Android devices connected',
                'packages': []
            }), 400
        
        android_devices = [d for d in adb_check.get('available_devices', []) if 'device_id' in d]
        if not android_devices:
            return jsonify({
                'success': False,
                'error': 'No Android devices found',
                'packages': []
            }), 400
        
        device_id = android_devices[0].get('device_id')
        result = get_adb_packages(device_id)
        
        if result.get('success'):
            return jsonify({
                'success': True,
                'packages': result.get('packages', []),
                'device_id': device_id
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to get packages'),
                'packages': []
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error getting packages: {str(e)}',
            'packages': []
        }), 500

@app.route('/sslpindec/analyze', methods=['POST'])
def sslpindetect_analyze():
    """Analyze APK for SSL pinning - supports both upload and package selection"""
    try:
        from sslpindetect import SSLPinDetector
        
        apktool_path = request.form.get('apktool_path', '').strip()
        if not apktool_path:
            detector_temp = SSLPinDetector()
            apktool_path = detector_temp._find_apktool()
        
        if not apktool_path or not os.path.exists(apktool_path):
            return jsonify({
                'success': False, 
                'error': 'Apktool not found. Please specify the path to apktool (supports .jar, .exe, or binary).\n\nCommon locations:\n- apktool.jar (requires Java)\n- apktool.exe (Windows)\n- apktool (Linux/Mac binary)\n\nYou can download apktool from: https://ibotpeaches.github.io/Apktool/'
            }), 400
        
        verbose = request.form.get('verbose', 'false').lower() == 'true'
        apk_path = None
        downloaded_apk = False
        
        package_name = request.form.get('package_name', '').strip()
        
        if package_name:
            try:
                adb_check = there_is_adb_and_devices()
                if not adb_check["is_true"]:
                    return jsonify({
                        'success': False,
                        'error': 'No Android devices connected'
                    }), 400
                
                android_devices = [d for d in adb_check.get('available_devices', []) if 'device_id' in d]
                if not android_devices:
                    return jsonify({
                        'success': False,
                        'error': 'No Android devices found'
                    }), 400
                
                device_id = android_devices[0].get('device_id')
                
                detector = SSLPinDetector(apktool_path=apktool_path)
                
                safe_package = re.sub(r'[^a-zA-Z0-9_.-]', '_', package_name)
                apk_path = os.path.join(UPLOAD_FOLDER, f'{safe_package}_sslpindetect.apk')
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                
                log_to_fsr_logs(f"[SSLPINDETECT] Downloading APK for package: {package_name}")
                downloaded_path = detector.download_apk_from_package(package_name, device_id, apk_path)
                apk_path = downloaded_path
                downloaded_apk = True
                log_to_fsr_logs(f"[SSLPINDETECT] APK downloaded to: {apk_path}")
                
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Failed to download APK from package: {str(e)}'
                }), 500
        
        else:
            if 'apkFile' not in request.files:
                return jsonify({'success': False, 'error': 'No APK file uploaded and no package selected'}), 400
            
            file = request.files['apkFile']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'}), 400
            
            if not file.filename.endswith('.apk'):
                return jsonify({'success': False, 'error': 'Only APK files are allowed'}), 400
            
            filename = secure_filename(file.filename)
            apk_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(apk_path)
        
        try:
            detector = SSLPinDetector(apktool_path=apktool_path)
            result = detector.detect_ssl_pinning(apk_path, verbose=verbose)
            
            if downloaded_apk and os.path.exists(apk_path):
                try:
                    os.remove(apk_path)
                except Exception:
                    pass
            
            return jsonify(result)
            
        except Exception as e:
            if downloaded_apk and os.path.exists(apk_path):
                try:
                    os.remove(apk_path)
                except Exception:
                    pass
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
