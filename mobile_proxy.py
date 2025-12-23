import subprocess
import sys
from typing import Dict, Any, List


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


def get_current_mobile_proxy() -> Dict[str, Any]:
    """
    Read the current global http_proxy from the Android device.
    """
    result = _run_adb_command(["shell", "settings", "get", "global", "http_proxy"])
    # Normalize value for UI convenience
    value = result["stdout"].strip() if result["success"] else ""
    return {
        "success": result["success"],
        "value": value,
        "error": result["stderr"] if not result["success"] else "",
    }


def set_mobile_proxy(ip: str, port: str) -> Dict[str, Any]:
    """
    Set global http_proxy on the Android device.

    Equivalent to:
        adb shell settings put global http_proxy 10.10.11.195:8888
    """
    proxy_value = f"{ip}:{port}"
    result = _run_adb_command(
        ["shell", "settings", "put", "global", "http_proxy", proxy_value]
    )
    return {
        "success": result["success"],
        "proxy": proxy_value,
        "error": result["stderr"] if not result["success"] else "",
    }


def unset_mobile_proxy() -> Dict[str, Any]:
    """
    Clear global http_proxy on the Android device.

    Equivalent to:
        adb shell settings put global http_proxy :0
    """
    result = _run_adb_command(
        ["shell", "settings", "put", "global", "http_proxy", ":0"]
    )
    return {
        "success": result["success"],
        "proxy": ":0",
        "error": result["stderr"] if not result["success"] else "",
    }


def get_local_proxy_ips() -> Dict[str, Any]:
    """
    Get list of local IP addresses that can be used as proxy targets.

    Uses `ifconfig` on Unix-like systems and `ipconfig` on Windows.
    Returns a dict: { "success": bool, "ips": [ { "ip": str, "label": str }, ... ], "error": str }
    """
    is_windows = sys.platform.startswith("win")
    cmd = ["ipconfig"] if is_windows else ["ifconfig"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        output = result.stdout
    except Exception as e:
        return {
            "success": False,
            "ips": [],
            "error": f"Failed to run {' '.join(cmd)}: {e}",
        }

    ips: List[Dict[str, str]] = []

    if is_windows:
        # Very simple parser for `ipconfig` IPv4 lines
        current_label = None
        for line in output.splitlines():
            line = line.rstrip()
            if not line:
                continue
            if not line.startswith(" "):
                # Interface header line
                current_label = line.strip()
                continue
            if "IPv4 Address" in line or "IPv4-adres" in line or "IPv4 Address." in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    ip = parts[-1].strip()
                    if ip and not ip.startswith("127."):
                        label = current_label or "IPv4"
                        ips.append({"ip": ip, "label": f"{label} ({ip})"})
    else:
        # Parse `ifconfig` output for inet lines (exclude 127.0.0.1)
        # macOS/BSD uses tabs for indentation, so we must check generic whitespace,
        # not only a single space.
        current_if = None
        for raw_line in output.splitlines():
            if not raw_line.strip():
                continue
            if not raw_line[0].isspace():
                # Interface name line, e.g. "en0: flags=..."
                current_if = raw_line.split(":", 1)[0].strip()
                continue
            line = raw_line.strip()
            if line.startswith("inet "):
                parts = line.split()
                # Typical: "inet 192.168.x.x  netmask ..."
                if len(parts) >= 2:
                    ip = parts[1]
                    if ip and not ip.startswith("127."):
                        iface = current_if or "iface"
                        ips.append({"ip": ip, "label": f"{iface} ({ip})"})

    # Deduplicate by IP keeping first label
    seen = set()
    unique_ips: List[Dict[str, str]] = []
    for item in ips:
        ip = item["ip"]
        if ip in seen:
            continue
        seen.add(ip)
        unique_ips.append(item)

    return {"success": True, "ips": unique_ips, "error": ""}


