from flask import Flask, render_template, request, jsonify, send_file
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
import frida # type: ignore

# Suppress traceback on keyboard interrupt
sys.tracebacklimit = 0

# Handle command line arguments for custom port
parser = argparse.ArgumentParser(description='FSR Tool')
parser.add_argument('-p', '--port', type=int, default=5000, help='Port to run the server on')
parser.add_argument('-v', '--verbose', action='store_true', help='Show the Frida output')
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
    
def detect_ios_device_with_frida():
    try:
        device_manager = frida.get_device_manager()
        devices = device_manager.enumerate_devices()

        print(f"Devices detected: {devices}") 

        device_list = []
        for device in devices:
            if device.type == 'usb' and 'iPhone' in device.name:
                device_list.append({'id': device.id, 'name': device.name})
        if device_list:
            print("Device detected:", device_list) 
            return device_list
        else:
            print("No iOS device detected.")
            return None
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return None
    
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
                available_devices.append({"model": model, "serial_number": serial_number, "versi_andro": versi_andro})
            adb_is_active = True
            message = "Device is available"
    except Exception as e:
        message = f"Error checking Android device connectivity: {e}"

    try:
        ios_devices = detect_ios_device_with_frida()
        if ios_devices:
            for device in ios_devices:
                available_devices.append({"model": device["name"], "UDID": device["id"]})
            adb_is_active = True
            message = "iOS device is available"
    except Exception as e:
        message = f"Error checking iOS device connectivity with Frida: {e}"

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
    list_script = json.load(open("script.json","r"))["scripts"]
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
    if adb_check and adb_check.get("is_true"):
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
            "python", "dump.py",
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

if __name__ == '__main__':
    main()