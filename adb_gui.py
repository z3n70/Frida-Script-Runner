import subprocess
import sys
import json
from typing import Dict, Any, List, Optional


def _run_adb_command(args, timeout: int = 10) -> Dict[str, Any]:
    """
    Helper to run an ADB command and return a structured result.
    Does NOT depend on the main app so it can be imported standalone.
    """
    cmd = ["adb"] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return {
            "success": True,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": " ".join(cmd),
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "stdout": e.stdout.strip() if e.stdout else "",
            "stderr": e.stderr.strip() if e.stderr else str(e),
            "command": " ".join(cmd),
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"ADB command timed out: {' '.join(cmd)}",
            "command": " ".join(cmd),
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Unexpected error running ADB: {e}",
            "command": " ".join(cmd),
        }


def connect_adb(ip: str, port: str) -> Dict[str, Any]:
    """
    Connect to ADB device via TCP/IP.
    """
    if not ip or not port:
        return {"success": False, "error": "IP and Port are required"}
    
    try:
        port_int = int(port)
        if port_int < 1 or port_int > 65535:
            return {"success": False, "error": "Port must be between 1 and 65535"}
    except ValueError:
        return {"success": False, "error": "Port must be a valid number"}
    
    result = _run_adb_command(["connect", f"{ip}:{port}"])
    if result["success"]:
        return {"success": True, "message": f"Connected to {ip}:{port}"}
    else:
        return {"success": False, "error": result["stderr"] or "Connection failed"}


def get_devices() -> Dict[str, Any]:
    """
    Get list of connected ADB devices.
    """
    result = _run_adb_command(["devices", "-l"], timeout=2)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "devices": []}
    
    devices = []
    lines = result["stdout"].splitlines()
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        
        parts = line.split()
        if len(parts) >= 2:
            serial = parts[0]
            state = parts[1]
            
            if state in ["device", "offline", "unauthorized", "sideload", "recovery"]:
                device_info = {"serial": serial, "state": state}
                
                for part in parts[2:]:
                    if ":" in part:
                        key, value = part.split(":", 1)
                        device_info[key] = value
                        if key == "model":
                            device_info["model"] = value
                        elif key == "product":
                            device_info["product"] = value
                
                devices.append(device_info)
    
    return {"success": True, "devices": devices}


def check_device_responsive(serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Quick check if device is responsive by running a simple command.
    """
    cmd = ["shell", "echo", "test"]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd, timeout=2)
    return {"success": result["success"], "responsive": result["success"]}


def get_device_info(serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get detailed information about a device.
    """
    responsive = check_device_responsive(serial)
    if not responsive["responsive"]:
        return {"success": False, "error": "Device is not responsive", "info": {}}
    
    cmd = ["shell", "getprop"]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd, timeout=3)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "info": {}}
    
    info = {}
    for line in result["stdout"].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().strip("[]")
            value = value.strip().strip("[]")
            info[key] = value

    device_info = {
        "STATE": "device",
        "USB": "1",
        "PRODUCT": info.get("ro.product.name", "unknown"),
        "DEVICE": info.get("ro.product.device", "unknown"),
        "MODEL": info.get("ro.product.model", "unknown"),
        "BRAND": info.get("ro.product.brand", "unknown"),
        "MANUFACTURER": info.get("ro.product.manufacturer", "unknown"),
        "ANDROID_VERSION": info.get("ro.build.version.release", "unknown"),
        "SDK_VERSION": info.get("ro.build.version.sdk", "unknown"),
    }
    
    return {"success": True, "info": device_info}


def get_packages(serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get list of installed packages on the device.
    """
    responsive = check_device_responsive(serial)
    if not responsive["responsive"]:
        return {"success": False, "error": "Device is not responsive", "packages": []}
    
    cmd = ["shell", "pm", "list", "packages"]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd, timeout=3)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "packages": []}
    
    packages = []
    for line in result["stdout"].splitlines():
        if line.startswith("package:"):
            package_name = line.replace("package:", "").strip()
            packages.append(package_name)
    
    return {"success": True, "packages": sorted(packages)}


def clear_package_data(package_name: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Clear data for a specific package.
    """
    cmd = ["shell", "pm", "clear", package_name]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Cleared data for {package_name}"}
    else:
        return {"success": False, "error": result["stderr"] or "Failed to clear data"}


def uninstall_package(package_name: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Uninstall a package from the device.
    """
    cmd = ["uninstall", package_name]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Uninstalled {package_name}"}
    else:
        return {"success": False, "error": result["stderr"] or "Failed to uninstall"}


def force_stop_package(package_name: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Force stop a running package.
    """
    cmd = ["shell", "am", "force-stop", package_name]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Force stopped {package_name}"}
    else:
        return {"success": False, "error": result["stderr"] or "Failed to force stop"}


def install_package(apk_path: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Install an APK package on the device.
    """
    cmd = ["install", apk_path]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd, timeout=60)
    if result["success"]:
        return {"success": True, "message": f"Installed {apk_path}"}
    else:
        return {"success": False, "error": result["stderr"] or "Failed to install"}


def get_running_processes(serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get list of running processes on the device.
    """
    cmd = ["shell", "ps"]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "processes": []}
    
    processes = []
    lines = result["stdout"].splitlines()
    if len(lines) > 1:
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                processes.append({
                    "USER": parts[0],
                    "PID": parts[1],
                    "PPID": parts[2],
                    "NAME": " ".join(parts[3:]) if len(parts) > 3 else parts[3]
                })
    
    return {"success": True, "processes": processes}


def get_app_memory_info(package_name: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get memory information for a specific app/package.
    """
    cmd = ["shell", "dumpsys", "meminfo", package_name]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "info": {}}
    
    return {"success": True, "info": result["stdout"]}


def get_system_memory_info(serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get system memory information from /proc/meminfo.
    """
    cmd = ["shell", "cat", "/proc/meminfo"]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd, timeout=5)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "meminfo": {}}
    
    meminfo = {}
    for line in result["stdout"].splitlines():
        if ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value_str = parts[1].strip()
                value_str = value_str.replace("kB", "").strip()
                try:
                    value = int(value_str)
                    meminfo[key] = value
                except ValueError:
                    meminfo[key] = value_str
    
    return {"success": True, "meminfo": meminfo}


def get_disk_space(serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get disk space information for the device.
    """
    cmd = ["shell", "df", "-h"]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd, timeout=3)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "info": "", "partitions": []}
    
    partitions = []
    lines = result["stdout"].splitlines()
    
    def parse_size(size_str):
        if not size_str or size_str == '-' or size_str == '0':
            return 0
        size_str = str(size_str).upper().strip()
        multipliers = {'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[:-1]) * multiplier)
                except:
                    return 0
        try:
            return int(size_str)
        except:
            return 0
    
    for line in lines[1:]:
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) >= 5:
            try:
                filesystem = parts[0]
                size_str = parts[1]
                used_str = parts[2]
                available_str = parts[3]
                use_percent_str = parts[4].rstrip('%')
                mounted_on = ' '.join(parts[5:]) if len(parts) > 5 else ""
                
                size_bytes = parse_size(size_str)
                used_bytes = parse_size(used_str)
                available_bytes = parse_size(available_str)
                
                try:
                    use_percent_float = float(use_percent_str)
                except:
                    if size_bytes > 0:
                        use_percent_float = (used_bytes / size_bytes) * 100
                    else:
                        use_percent_float = 0
                
                partitions.append({
                    "filesystem": filesystem,
                    "size": size_str,
                    "used": used_str,
                    "available": available_str,
                    "use_percent": use_percent_float,
                    "mounted_on": mounted_on,
                    "size_bytes": size_bytes,
                    "used_bytes": used_bytes,
                    "available_bytes": available_bytes
                })
            except Exception as e:
                continue
    
    return {
        "success": True, 
        "info": result["stdout"],
        "partitions": partitions
    }


def get_screen_info(serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get screen information (resolution, density) of the device.
    """
    cmd = ["shell", "wm", "size"]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "size": ""}
    
    size = result["stdout"].strip()
    
    cmd_density = ["shell", "wm", "density"]
    if serial:
        cmd_density = ["-s", serial] + cmd_density
    
    result_density = _run_adb_command(cmd_density)
    density = result_density["stdout"].strip() if result_density["success"] else ""
    
    return {"success": True, "size": size, "density": density}


def send_touch_event(x: int, y: int, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Send touch event to device at coordinates (x, y).
    """
    cmd = ["shell", "input", "tap", str(x), str(y)]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Touch sent to ({x}, {y})"}
    else:
        return {"success": False, "error": result["stderr"] or "Failed to send touch"}


def send_swipe_event(x1: int, y1: int, x2: int, y2: int, duration: int = 300, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Send swipe event from (x1, y1) to (x2, y2) with duration in milliseconds.
    """
    cmd = ["shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration)]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Swipe from ({x1}, {y1}) to ({x2}, {y2})"}
    else:
        return {"success": False, "error": result["stderr"] or "Failed to send swipe"}


def send_key_event(keycode: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Send key event (e.g., KEYCODE_HOME, KEYCODE_BACK, KEYCODE_MENU).
    """
    cmd = ["shell", "input", "keyevent", keycode]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Key event {keycode} sent"}
    else:
        return {"success": False, "error": result["stderr"] or "Failed to send key event"}


def send_text(text: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Send text input to device.
    """
    escaped_text = text.replace(" ", "\\ ").replace("&", "\\&").replace("'", "\\'").replace("(", "\\(").replace(")", "\\)")
    cmd = ["shell", "input", "text", escaped_text]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Text sent: {text}"}
    else:
        try:
            import shlex
            safe_text = shlex.quote(text)
            cmd_alt = ["shell", "input", "text", safe_text]
            if serial:
                cmd_alt = ["-s", serial] + cmd_alt
            result_alt = _run_adb_command(cmd_alt)
            if result_alt["success"]:
                return {"success": True, "message": f"Text sent: {text}"}
        except:
            pass
        return {"success": False, "error": result["stderr"] or "Failed to send text"}


def launch_app(package_name: str, activity: Optional[str] = None, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Launch an app by package name. If activity is provided, launch specific activity.
    """
    if activity:
        cmd = ["shell", "am", "start", "-n", f"{package_name}/{activity}"]
    else:
        cmd = ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"]
    
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if result["success"]:
        return {"success": True, "message": f"Launched {package_name}"}
    else:
        if not activity:
            cmd_alt = ["shell", "am", "start", "-n", package_name]
            if serial:
                cmd_alt = ["-s", serial] + cmd_alt
            result_alt = _run_adb_command(cmd_alt)
            if result_alt["success"]:
                return {"success": True, "message": f"Launched {package_name}"}
        return {"success": False, "error": result["stderr"] or "Failed to launch app"}


def get_package_activity(package_name: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """
    Get main activity of a package.
    """
    cmd = ["shell", "pm", "dump", package_name]
    if serial:
        cmd = ["-s", serial] + cmd
    
    result = _run_adb_command(cmd)
    if not result["success"]:
        return {"success": False, "error": result["stderr"], "activity": None}
    
    lines = result["stdout"].splitlines()
    activity = None
    for line in lines:
        if "android.intent.action.MAIN" in line and "android.intent.category.LAUNCHER" in line:
            parts = line.split()
            for part in parts:
                if package_name in part and "/" in part:
                    activity = part.split("/")[-1].strip()
                    break
            if activity:
                break
    
    return {"success": True, "activity": activity}