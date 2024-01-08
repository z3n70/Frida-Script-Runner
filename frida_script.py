from flask import Flask, render_template, request, Response, jsonify
import subprocess
import os
import json
import base64
import hashlib


app = Flask(__name__)
process = None

SCRIPTS_DIRECTORY = f"{os.getcwd()}/scripts"

class OsNotSupportedError(Exception):
    pass

# fuction to check adb status and devices connectivity
def there_is_adb_and_devices():
    adb_is_active = False
    available_devices = []
    message = ""
    def run_adb_command(command):
        if os.name not in ["darwin","posix"]:
            result = subprocess.run(["adb"]+command, capture_output=True, text=True, check=True)
        else:
            result = subprocess.run(["frida-ps -Uai"]+command, capture_output=True, text=True, check=True)
            # pass
        return result.stdout.strip()
    # check for connected devices on machine other than osx.
    if os.name not in ["darwin","posix"]:
        connected_devices = run_adb_command(["devices"]).split('\n')[1:]
        device_ids = [line.split('\t')[0] for line in connected_devices if line.strip()]
        
        if device_ids:
            for device_id in device_ids:
                model = run_adb_command(["-s", device_id, "shell", "getprop", "ro.product.model"])
                serial_number = run_adb_command(["-s", device_id, "shell", "getprop", "ro.serialno"])
                available_devices.append({"model":model,"serial_number":serial_number})
            adb_is_active = True
            message = "device is avaliabe"
    else:
        adb_is_active = True
        message = "osx device always return True even device is not exist"

    return {"is_true":adb_is_active,"available_devices":available_devices,"message":message}

def get_package_identifiers():
    try:
        result = subprocess.run(['frida-ps', '-Uai'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')[1:]
        identifiers = [line.split()[-1] for line in lines]
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
    adb_check = there_is_adb_and_devices()
    if adb_check["is_true"]:
        try:
            identifiers = get_package_identifiers()
            bypass_scripts_1, bypass_scripts_2 = get_bypass_scripts()
            return render_template('index.html', identifiers=identifiers, bypass_scripts_android=bypass_scripts_1, bypass_scripts_ios=bypass_scripts_2,devices=adb_check)
        except Exception as e:
            return render_template('index.html', error=f"Error: {e}")
    else:
        return "<body style='background-color:black;'><h1 style='color:red;'>There is no adb or device connected. Make sure your ADB is installed correctly then connect your device, run your frida server and reload this page</h1></body>"
    
@app.route('/run-frida', methods=['POST'])
def run_frida():
    global process

    try:
        package = request.form['package']
        use_custom_script = int(request.form['use_custom_script'])
        selected_script = request.form['selected_script']
        script_content = request.form['script_content']

        if use_custom_script:
            script_name = hashlib.sha256(script_content.encode()).hexdigest() + ".js"
            script_path = os.path.join("tmp", script_name)
            with open(script_path, 'w') as file:
                file.write(script_content)

        else:
            script_path = os.path.join(SCRIPTS_DIRECTORY, selected_script)

        if process and process.poll() is None:
            process.terminate()

        command = f'frida -l {script_path} -U -f {package}'
        # determining wich OS is used by user
        if os.name in ["darwin","posix"]:
            process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # when user use windows machine
        elif os.name == "nt":
            process = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            raise OsNotSupportedError("This script only work on Windows, Linux and Darwin machines")

        return jsonify({"result": f'Successfully started Frida on {package} using {selected_script}'}), 200
    except Exception as e:
        return jsonify({"error": f"Error: {e}"}), 500

@app.route('/stop-frida')
def stop_frida():
    global process

    if process and process.poll() is None:
        process.terminate()
        return 'Frida process stopped', 200
    else:
        return 'Frida process is not running', 200

    # return render_template('index.html', result='Frida process stopped', identifiers=get_package_identifiers())


if __name__ == '__main__':
    app.run(debug=True)
    # print(get_bypass_scripts())
