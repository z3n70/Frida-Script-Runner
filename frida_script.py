from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from colorama import Fore, Back, Style, init
import subprocess
import os
import json
import base64
import hashlib
import threading
import time
import signal
import logging
import re

app = Flask(__name__)
socketio = SocketIO(app)
process = None
SCRIPTS_DIRECTORY = f"{os.getcwd()}/scripts"


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
                available_devices.append({"model": model, "serial_number": serial_number})
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
        # if get_device_type() in ["Windows","Linux"]:
        #     process = subprocess.Popen(['frida-ps', '-Uai'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        #     result, _ = process.communicate()
        #     lines = result.strip().split('\n')[1:]
        # else:
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
    if adb_check["is_true"]:
        try:
            identifiers = get_package_identifiers()
            bypass_scripts_1, bypass_scripts_2 = get_bypass_scripts()
            return render_template('index.html', identifiers=identifiers, bypass_scripts_android=bypass_scripts_1, bypass_scripts_ios=bypass_scripts_2,devices=adb_check,connected_device=adb_check["available_devices"])

        except Exception as e:
            return render_template('index.html', error=f"Error: {e}")
    else:
        return render_template('no-usb.html')

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

        # memakai threading flask
        socketio_thread = threading.Thread(target=run_frida_with_socketio, args=(script_path, package))
        socketio_thread.daemon = True
        socketio_thread.start()

        return jsonify({"result": f'Successfully started Frida on {package} using {selected_script}'}), 200
    except KeyboardInterrupt:
        return jsonify({"error": "Frida process interrupted by user."}), 500
    except Exception as e:
        return jsonify({"error": f"Error: {e}"}), 500

    
def run_frida_with_socketio(script_path, package):
    global process

    try:
        command = ["frida", "-l", script_path, "-U", "-f", package]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                socketio.emit("output", {"data": output})
                
                time.sleep(0.010)

        socketio.emit("output", {"data": "Frida process finished."})
    except KeyboardInterrupt:
        socketio.emit("output", {"data": "Frida process interrupted by user."})
    except Exception as e:
        socketio.emit("output", {"data": f"Error: {e}"})

@socketio.on("connect")
def handle_connect():
    pass

@app.route('/stop-frida')
def stop_frida():
    global process

# proses dihentikan sebelum dikirim ke response
    if process and process.poll() is None:
        process.kill()
        process.wait() 
        return 'Frida process stopped', 200
    else:
        return 'Frida process is not running', 200

if __name__ == '__main__':
    try:
        print(Fore.GREEN + """
                           ‸
                          _)\\.-.
         .-.__,___,_.-=-. )\`  ͡⇼`\_
     .-.__\__,__,__.-=-. `/  \     `\\
     {~,-~-,-~.-~,-,;;;;\ |   '--;`)/
      \-,~_-~_-,~-,(_(_(;\/   ,;/
       ",-.~_,-~,-~,)_)_)'.  ;;(
         `~-,_-~,-~(_(_(_(_\  `;\\ 
   ,          `"~~--,)_)_)_)\_   \\
   |\              (_(_/_(_,   \  ;  
   \ '-.       _.--'  /_/_/_)   | |  FSR v1.3       
    '--.\    .'          /_/    | |
        ))  /       \      |   /.'
       //  /,        | __.'|  ||
      //   ||        /`    (  ||
     ||    ||      .'       \ \\
     ||    ||    .'_         \ \\
      \\   //   / _ `\         \ \\__
       \\'-'/(   _  `\,;        \ '--:,
        `"`  `"` `-,,;         `"`",,;
           
        """)
        print("Please Access http://127.0.0.1:5000\n")
        print("Press CTRL+C to stop this program.")
        socketio.run(app, debug=False if get_device_type() not in ['Windows','Linux'] else False)
    except KeyboardInterrupt:
        pass

    print("\nThanks For Using This Tools ♡")