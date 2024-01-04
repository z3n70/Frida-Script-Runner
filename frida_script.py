from flask import Flask, render_template, request, Response, jsonify
import subprocess
import os

app = Flask(__name__)
process = None

SCRIPTS_DIRECTORY = f"{os.getcwd()}/scripts"


class OsNotSupportedError(Exception):
    pass

# fuction to check adb status and devices connectivity
def there_is_adb_and_devices():
    def run_adb_command(command):
        if os.name not in if os.name in ["darwin","posix"]:
            result = subprocess.run(["adb"]+command, capture_output=True, text=True, check=True)
        else:
            result = ""
            # pass
        return result.stdout.strip()

    adb_is_active = False
    available_devices = []
    message = ""

    # check for connected devices.
    connected_devices = run_adb_command(["devices"]).split('\n')[1:]
    device_ids = [line.split('\t')[0] for line in connected_devices if line.strip()]

    if device_ids:
        for device_id in device_ids:
            model = run_adb_command(["-s", device_id, "shell", "getprop", "ro.product.model"])
            serial_number = run_adb_command(["-s", device_id, "shell", "getprop", "ro.serialno"])
            available_devices.append({"model":model,"serial_number":serial_number})
        adb_is_active = True
        message = "device is avaliabe"

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
    try:
        scripts_directory_1 = os.path.join(SCRIPTS_DIRECTORY, "Script Directory 1")
        bypass_scripts_1 = [f for f in os.listdir(scripts_directory_1) if f.endswith(".js")]

        scripts_directory_2 = os.path.join(SCRIPTS_DIRECTORY, "Script Directory 2")
        bypass_scripts_2 = [f for f in os.listdir(scripts_directory_2) if f.endswith(".js")]

        return bypass_scripts_1, bypass_scripts_2
    except Exception as e:
        print(f"Error getting bypass scripts: {e}")
        return [], []

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

def generate_output():
    global process
    while process and process.poll() is None:
        line_stdout = process.stdout.readline()
        line_stderr = process.stderr.readline()

        if not line_stdout and not line_stderr:
            break

        if line_stdout:
            yield f'data: Stdout: {line_stdout.decode("utf-8")}\n\n'

        if line_stderr:
            yield f'data: Stderr: {line_stderr.decode("utf-8")}\n\n'
    
    if process: #fix problem for notype object
        process.terminate()

@app.route('/')
def index():
    try:
        identifiers = get_package_identifiers()
        bypass_scripts_1, bypass_scripts_2 = get_bypass_scripts()
        return render_template('index.html', identifiers=identifiers, bypass_scripts_1=bypass_scripts_1, bypass_scripts_2=bypass_scripts_2)
    except Exception as e:
        return render_template('index.html', error=f"Error: {e}")

@app.route('/run-frida', methods=['POST'])
def run_frida():
    global process

    try:
        package = request.form['package']
        selected_script = request.form['selected_script']

        if process and process.poll() is None:
            process.terminate()

        script_path = os.path.join(SCRIPTS_DIRECTORY, selected_script)
        command = f'frida -l {script_path} -U -f {package}'
        process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        script_content = get_script_content(script_path)

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

@app.route('/stream')
def stream():
    return Response(generate_output(), content_type='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True)
