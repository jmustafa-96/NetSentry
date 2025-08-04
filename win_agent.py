# agent.py
import requests
import socket
import platform
import uuid
import psutil
import time
import os
from datetime import datetime
# import pyudev
# import threading

SERVER_IP = 'http://192.168.31.187:5053'

# SERVER_IP = 'http://192.168.122.24:5000'
# Add to the beginning of win_agent.py
import sys
import os

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Then modify any file paths in your code to use resource_path()
# For example:
# file_path = resource_path('some_file.txt')
def get_system_info():
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time()).isoformat()
    except Exception:
        boot_time = "N/A"
    disk_info = []
    try:
        for partition in psutil.disk_partitions():
            usage = psutil.disk_usage(partition.mountpoint)
            disk_info.append({
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent_used": usage.percent
            })
    except Exception:
        disk_info = "Error retrieving disk information"

    # Get the correct network IP address in the desired subnet
    target_subnet = "192.168.31."
    ip_address = None
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == 'AF_INET':  # IPv4 address
                if addr.address.startswith(target_subnet):  # Match the desired subnet
                    ip_address = addr.address
                    break
        if ip_address:
            break

    return {
        "hostname": socket.gethostname(),
        "ip_address": ip_address or "Unknown",  # Fallback to "Unknown" if no valid IP is found
        "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0, 2*6, 8)][::-1]),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.architecture()[0],
        "processor": platform.processor(),
        "boot_time": boot_time,
        "ram_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "ram_used_gb": round(psutil.virtual_memory().used / (1024 ** 3), 2),
        "ram_available_gb": round(psutil.virtual_memory().available / (1024 ** 3), 2),
        "disks": disk_info
    }

def get_processes():
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 
                                       'cpu_percent', 'memory_percent', 'cmdline']):
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "user": proc.info['username'],
                "status": proc.info['status'],
                "cpu_usage": proc.info['cpu_percent'],
                "memory_usage": proc.info['memory_percent'],
                "command_line": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else None
            })
    except Exception:
        processes = "Error retrieving process information"
    return processes

def get_network_info():
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'NONE' or not conn.raddr:
                continue
            connections.append({
                "protocol": conn.type.name,
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                "status": conn.status,
                "pid": conn.pid
            })
    except Exception:
        connections = "Error retrieving network information"
    return connections

def get_user_info():
    users = []
    try:
        if platform.system() == 'Windows':
            for user in psutil.users():
                users.append({
                    "name": user.name,
                    "terminal": user.terminal,
                    "host": user.host,
                    "login_time": datetime.fromtimestamp(user.started).isoformat()
                })
        else:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        users.append({
                            "username": parts[0],
                            "uid": parts[2],
                            "gid": parts[3],
                            "home_dir": parts[5],
                            "shell": parts[6]
                        })
    except Exception as e:
        users = f"Error retrieving user information: {str(e)}"
    return users

def get_installed_software():
    software = []
    try:
        if platform.system() == 'Windows':
            import winreg
            reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(reg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                try:
                    subkey = winreg.OpenKey(key, winreg.EnumKey(key, i))
                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                    software.append({"name": name, "version": version})
                except Exception:
                    continue
        else:
            import subprocess
            try:
                pkgs = subprocess.check_output(['dpkg', '-l']).decode()
                for line in pkgs.split('\n'):
                    if line.startswith('ii '):
                        parts = line.split()
                        software.append({"name": parts[1], "version": parts[2]})
            except Exception:
                pass
    except Exception as e:
        software = f"Error retrieving software information: {str(e)}"
    return software

def get_security_events():
    events = []
    try:
        log_path = '/var/log/auth.log' if platform.system() != 'Windows' else 'Security'
        with open(log_path, 'r') as f:
            events = f.readlines()[-50:]  # Last 50 lines
    except Exception as e:
        events = f"Error retrieving security events: {str(e)}"
    return events

def get_antivirus_status():
    av_processes = {
        'Windows': ['MsMpEng.exe', 'avguard.exe'],
        'Linux': ['clamd', 'freshclam'],
        'Darwin': ['clamav', 'SophosScanD']
    }
    running = []
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in av_processes.get(platform.system(), []):
                running.append(proc.info['name'])
    except Exception:
        running = "Error checking antivirus status"
    return running

def get_device_info():
    return {
        "timestamp": datetime.now().isoformat(),
        "system": get_system_info(),
        "processes": get_processes(),
        "network_connections": get_network_info(),
        "users": get_user_info(),
        "installed_software": get_installed_software(),
        "security_events": get_security_events(),
        "antivirus_status": get_antivirus_status(),
        "sensitive_files": check_file_integrity(),
        "performance": {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent
        }
    }

def check_file_integrity():
    critical_files = {
        'Windows': [
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\System32\\cmd.exe'
        ],
        'Linux': [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers'
        ],
        'Darwin': [
            '/etc/hosts',
            '/etc/sudoers'
        ]
    }
    file_info = []
    for fpath in critical_files.get(platform.system(), []):
        try:
            stat = os.stat(fpath)
            file_info.append({
                "path": fpath,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
            })
        except Exception as e:
            file_info.append({"path": fpath, "error": str(e)})
    return file_info

if __name__ == "__main__":
    while True:
        try:
            device_info = get_device_info()
            response = requests.post(f"{SERVER_IP}/update_device", json=device_info, timeout=10)
            print(f"Status: {response.status_code}, Response: {response.text}")
            
        except Exception as e:
            print(f"Error: {str(e)}")
        
        time.sleep(10)  # Send data every 2 minutes