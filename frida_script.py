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

sys.tracebacklimit = 0

parser = argparse.ArgumentParser(description='FSR Tool')
parser.add_argument('-p', '--port', type=int, default=5000, help='Port to run the server on')
parser.add_argument('-v', '--verbose', action='store_true', help='Show the Frida output')
parser.add_argument('--runw', nargs='+', metavar=('OS', 'FRIDA_VERSION'), help='Specify the OS and optional Frida version, e.g., --runw mac 16.0.7')
parser.add_argument('--force-download', action='store_true', help='Force download latest Frida server even if local file exists')
args = parser.parse_args()

app = Flask(__name__)
socketio = SocketIO(app)
process = None
SCRIPTS_DIRECTORY = f"{os.getcwd()}/scripts"

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
      
# adb status and connect
def run_adb_command(command, timeout=5):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout)

        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: ADB command failed. {e}"
    

def run_ideviceinfo(timeout=5):
    try:
        result = subprocess.run(["ideviceinfo"], capture_output=True, text=True, check=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Error: ideviceinfo command timed out."

def get_frida_server_url(architecture, version=None):
    if version:
        url = f'https://api.github.com/repos/frida/frida/releases/tags/{version}'
    else:
        url = 'https://api.github.com/repos/frida/frida/releases/latest'
    
    response = requests.get(url)
    response.raise_for_status()
    release_data = response.json()
    
    for asset in release_data['assets']:
        if 'frida-server' in asset['name'] and f'android-{architecture.strip()}' in asset['name']:
            print(f"[+] Found frida-server: {asset['browser_download_url']}")
            return asset['browser_download_url']
    
    print("[-] Frida server not found for this architecture.")
    return None

def frida_server_installed(device_id):
    try:
        result = run_adb_command(["adb", "-s", device_id, "shell", "ls", "/data/local/tmp/"])
        return "frida-server" in result
    except subprocess.CalledProcessError:
        return False

def is_frida_server_running(device_id):
    try:
        result = run_adb_command(["adb", "-s", device_id, "shell", "ps", "-A"])
        return "frida-server" in result
    except subprocess.CalledProcessError:
        return False

def download_and_push_frida(architecture, os_type, version=None):
    frida_server_path = os.path.join(f"./frida-server/{os_type}", "frida-server")
    
    should_download = True
    if os.path.isfile(frida_server_path) and version is None and not args.force_download:
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
                    if file_age < 86400:  # 24 hours in seconds
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
        
        # Clean up downloaded file
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
    
    # Parse arguments
    if len(runw_args) > 1:
        # Check if second argument is version or force-download flag
        if runw_args[1] == "--force-download":
            version = None  # Will use latest version
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
        # for ios use ideviceinfo
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
        result = subprocess.run(['frida-ps', '-Uai'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')[1:]
        identifiers = [line.split()[1] + " - " + line.split()[-1]  for line in lines]
        return identifiers
    except Exception as e:
        print(f"Error getting package identifiers: {e}")
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
            identifiers = get_package_identifiers()
            bypass_scripts_1, bypass_scripts_2 = get_bypass_scripts()
            return render_template('index.html', identifiers=identifiers, bypass_scripts_android=bypass_scripts_1, bypass_scripts_ios=bypass_scripts_2,devices=adb_check,connected_device=adb_check["available_devices"])

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

@app.route('/run-frida', methods=['POST'])
def run_frida():
    global process

    try:
        package = request.form['package']
        if not 'use_custom_script' in request.form.keys():
            use_custom_script = False
        else:
                use_custom_script = int(request.form['use_custom_script']) == 1

        selected_script = request.form['selected_script']
        script_content = request.form['script_content']

        if use_custom_script:
            script_name = hashlib.sha256(script_content.encode()).hexdigest() + ".js"
            script_path = os.path.join("tmp", script_name)
            selected_script = script_name
            with open(script_path, 'w') as file:
                file.write(script_content)
        else:
            script_path = os.path.join(SCRIPTS_DIRECTORY, selected_script)

        if process and process.poll() is None:
            process.terminate()

        socketio.start_background_task(run_frida_with_socketio, script_path, package)


        return jsonify({"result": f'Successfully started Frida on {package} using {selected_script}'}), 200
    except KeyboardInterrupt:
        return jsonify({"error": "Frida process interrupted by user."}), 500
    except Exception as e:
        return jsonify({"error": f"Error: {e}"}), 500

    
def run_frida_with_socketio(script_path, package):
    global process

    try:
        command = ["frida", "-l", script_path, "-U", "-f", package]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                if args.verbose:
                    print(output.replace('\n',''))
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

def check_port(port):
    """Check if a port is available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) != 0

def display_banner():
    """Display the application banner with help information"""
    banner = Fore.GREEN + r"""
                       ‸
                      _)\.-.
     .-.__,___,_.-=-. )\`  ͡⇼`\_
 .-.__\__,__,__.-=-. `/  \     `\\
 {~,-~-,-~.-~,-,;;;;\ |   '--;`)/
  \-,~_-~_-,~-,(_(_(;\/   ,;/
   ",-.~_,-~,-~,)_)_)'.  ;;(
     `~-,_-~,-~(_(_(_(_\  `;\\ 
,          `"~~--,)_)_)_)\_   \\
|\              (_(_/_(_,   \  ;  
\ '-.       _.--'  /_/_/_)   | |  FSR v0.2.0       
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
            if port == 5000:
                alt_port = 5001
                response = input(f"Would you like to use port {alt_port} instead? (Y/n): ").strip().lower()
                if response == "" or response.startswith('y'):
                    port = alt_port
                    if not check_port(port):
                        print(Fore.RED + f"Port {alt_port} is also in use. Please specify a different port using -p option." + Fore.RESET)
                        sys.exit(1)
                else:
                    print(Fore.YELLOW + "Please try again with a different port using -p option." + Fore.RESET)
                    sys.exit(0)
            else:
                print(Fore.YELLOW + "Please specify a different port using -p option." + Fore.RESET)
                sys.exit(0)
        
        print(Fore.GREEN + f"Please Access http://127.0.0.1:{port}" + Fore.RESET)
        print("Press CTRL+C to stop this program.")
        
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        socketio.run(app, port=port, debug=False if get_device_type() not in ['Windows','Linux'] else False)
    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Fore.RESET)
    print(Fore.CYAN + "\nThanks For Using This Tools ♡" + Fore.RESET)

# MAIN ENTRY POINT
if args.runw:
    push_and_run_fs(args.runw)
else:
    main()