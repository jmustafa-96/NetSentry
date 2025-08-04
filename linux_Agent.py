#!/usr/bin/env python3
import os
import socket
import json
import time
import subprocess
import pyudev
import requests
import threading
import uuid
import platform
import psutil
from datetime import datetime

# Configuration
SYSTEM_SERVER_URL = "http://192.168.34.102:5053/update_device"  # System monitoring endpoint
PERIPHERAL_SERVER_URL = "http://192.168.34.102:5053/api/device"  # Peripheral management endpoint
SYSTEM_REPORT_INTERVAL = 120  # seconds (2 minutes)
PERIPHERAL_CHECK_INTERVAL = 1  # seconds

class ComprehensiveAgent:
    def __init__(self):
        # System monitoring initialization
        self.system_last_report = 0
        
        # Peripheral management initialization
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by(subsystem='usb')
        self.approved_devices = set()
        self.blocked_devices = set()
        self.pending_devices = {}
        
        # Create storage directory if it doesn't exist
        os.makedirs('/etc/comprehensive-agent', exist_ok=True)
        
        # Load previously approved and blocked devices
        self.load_device_lists()

    # ====================== System Monitoring Functions ======================
    
    def get_system_info(self):
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
        target_subnet = "192.168.34."
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
            "ip_address": ip_address or "Unknown",
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

    def get_processes(self):
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

    def get_network_info(self):
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

    def get_user_info(self):
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

    def get_installed_software(self):
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

    def get_security_events(self):
        events = []
        try:
            log_path = '/var/log/auth.log' if platform.system() != 'Windows' else 'Security'
            with open(log_path, 'r') as f:
                events = f.readlines()[-50:]  # Last 50 lines
        except Exception as e:
            events = f"Error retrieving security events: {str(e)}"
        return events

    def get_antivirus_status(self):
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

    def check_file_integrity(self):
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

    def get_device_info(self):
        return {
            "timestamp": datetime.now().isoformat(),
            "system": self.get_system_info(),
            "processes": self.get_processes(),
            "network_connections": self.get_network_info(),
            "users": self.get_user_info(),
            "installed_software": self.get_installed_software(),
            "security_events": self.get_security_events(),
            "antivirus_status": self.get_antivirus_status(),
            "sensitive_files": self.check_file_integrity(),
            "performance": {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent
            }
        }

    def send_system_report(self):
        try:
            device_info = self.get_device_info()
            response = requests.post(SYSTEM_SERVER_URL, json=device_info, timeout=10)
            print(f"System Status: {response.status_code}, Response: {response.text}")
            return True
        except Exception as e:
            print(f"System Report Error: {str(e)}")
            return False

    # ====================== Peripheral Management Functions ======================
    
    def load_device_lists(self):
        try:
            if os.path.exists('/etc/comprehensive-agent/approved_devices.json'):
                with open('/etc/comprehensive-agent/approved_devices.json', 'r') as f:
                    self.approved_devices = set(json.load(f))
                print(f"Loaded {len(self.approved_devices)} approved devices")
            
            if os.path.exists('/etc/comprehensive-agent/blocked_devices.json'):
                with open('/etc/comprehensive-agent/blocked_devices.json', 'r') as f:
                    self.blocked_devices = set(json.load(f))
                print(f"Loaded {len(self.blocked_devices)} blocked devices")
        except Exception as e:
            print(f"Error loading device lists: {e}")
            
    def save_device_lists(self):
        try:
            with open('/etc/comprehensive-agent/approved_devices.json', 'w') as f:
                json.dump(list(self.approved_devices), f)
            
            with open('/etc/comprehensive-agent/blocked_devices.json', 'w') as f:
                json.dump(list(self.blocked_devices), f)
            
            print("Device lists saved successfully")
        except Exception as e:
            print(f"Error saving device lists: {e}")
    
    def get_peripheral_info(self, device):
        try:
            vendor_id = device.attributes.get('idVendor', '').decode('utf-8')
            product_id = device.attributes.get('idProduct', '').decode('utf-8')
            manufacturer = device.attributes.get('manufacturer', b'Unknown').decode('utf-8')
            product = device.attributes.get('product', b'Unknown').decode('utf-8')
            serial = device.attributes.get('serial', b'Unknown').decode('utf-8')
            
            device_info = {
                'id': f"{vendor_id}:{product_id}:{serial}",
                'vendor_id': vendor_id,
                'product_id': product_id,
                'manufacturer': manufacturer,
                'product': product,
                'serial': serial,
                'sys_path': device.sys_path,
                'device_type': device.device_type,
                'driver': device.driver or 'Unknown',
                'subsystem': device.subsystem,
                'device_node': device.device_node,
                'detected_at': datetime.now().isoformat(),
                'request_id': str(uuid.uuid4())
            }
            return device_info
        except Exception as e:
            print(f"Error getting device info: {e}")
            return None
    
    def create_udev_rule(self, device_info, action):
        """Create a udev rule to block or allow a device."""
        rule_file = f'/etc/udev/rules.d/99-peripheral-{device_info["vendor_id"]}-{device_info["product_id"]}-{device_info["serial"]}.rules'
        
        if action == 'block':
            rule_content = f'SUBSYSTEM=="usb", ATTR{{idVendor}}=="{device_info["vendor_id"]}", ATTR{{idProduct}}=="{device_info["product_id"]}", ATTR{{serial}}=="{device_info["serial"]}", RUN+="/bin/sh -c \'echo 0 > /sys$devpath/authorized\'"'
        elif action == 'allow':
            rule_content = f'SUBSYSTEM=="usb", ATTR{{idVendor}}=="{device_info["vendor_id"]}", ATTR{{idProduct}}=="{device_info["product_id"]}", ATTR{{serial}}=="{device_info["serial"]}", RUN+="/bin/sh -c \'echo 1 > /sys$devpath/authorized\'"'
        
        with open(rule_file, 'w') as f:
            f.write(rule_content)
        
        print(f"Created udev rule for {action}: {rule_file}")
        return rule_file
    
    def remove_udev_rule(self, device_info):
        """Remove any existing udev rule for the device."""
        rule_file = f'/etc/udev/rules.d/99-peripheral-{device_info["vendor_id"]}-{device_info["product_id"]}-{device_info["serial"]}.rules'
        
        if os.path.exists(rule_file):
            os.remove(rule_file)
            print(f"Removed udev rule: {rule_file}")
    
    def reload_udev_rules(self):
        """Reload udev rules and trigger them."""
        try:
            subprocess.run(['udevadm', 'control', '--reload-rules'], check=True)
            subprocess.run(['udevadm', 'trigger'], check=True)
            print("Udev rules reloaded")
        except Exception as e:
            print(f"Error reloading udev rules: {e}")
    
    def block_device(self, device_info):
        """Block a device and update internal lists."""
        device_id = device_info['id']
        
        try:
            self.remove_udev_rule(device_info)
            self.create_udev_rule(device_info, 'block')
            self.reload_udev_rules()
            
            if device_info['sys_path']:
                auth_path = f"{device_info['sys_path']}/authorized"
                if os.path.exists(auth_path):
                    try:
                        with open(auth_path, 'w') as f:
                            f.write('0')
                        print(f"Immediately deauthorized device: {device_id}")
                    except Exception as e:
                        print(f"Failed to immediately deauthorize device: {e}")
            
            if device_id in self.approved_devices:
                self.approved_devices.remove(device_id)
            
            self.blocked_devices.add(device_id)
            self.save_device_lists()
            
            print(f"Device blocked: {device_id}")
            return True
        except Exception as e:
            print(f"Error blocking device: {e}")
            return False
    
    def allow_device(self, device_info):
        """Allow a device and update internal lists."""
        device_id = device_info['id']
        
        try:
            self.remove_udev_rule(device_info)
            self.create_udev_rule(device_info, 'allow')
            self.reload_udev_rules()
            
            if device_info['sys_path']:
                auth_path = f"{device_info['sys_path']}/authorized"
                if os.path.exists(auth_path):
                    try:
                        with open(auth_path, 'w') as f:
                            f.write('1')
                        print(f"Immediately authorized device: {device_id}")
                    except Exception as e:
                        print(f"Failed to immediately authorize device: {e}")
            
            if device_id in self.blocked_devices:
                self.blocked_devices.remove(device_id)
            
            self.approved_devices.add(device_id)
            self.save_device_lists()
            
            print(f"Device allowed: {device_id}")
            return True
        except Exception as e:
            print(f"Error allowing device: {e}")
            return False
    
    def send_peripheral_info(self, device_info):
        try:
            response = requests.post(PERIPHERAL_SERVER_URL, json=device_info)
            if response.status_code == 200:
                result = response.json()
                self.pending_devices[device_info['request_id']] = device_info
                print(f"Device info sent to server: {device_info['id']}")
                return True
            else:
                print(f"Failed to send device info: {response.status_code} - {response.text}")
                self.block_device(device_info)
                return False
        except Exception as e:
            print(f"Error sending to server: {e}")
            self.block_device(device_info)
            return False
    
    def check_peripheral_status(self):
        while True:
            try:
                all_devices = {}
                if isinstance(self.pending_devices, dict):
                    all_devices.update(self.pending_devices)
                if isinstance(self.approved_devices, dict):
                    all_devices.update(self.approved_devices)
                if isinstance(self.blocked_devices, dict):
                    all_devices.update(self.blocked_devices)

                for request_id, device_info in list(all_devices.items()):
                    try:
                        response = requests.get(f"{PERIPHERAL_SERVER_URL}/{request_id}")
                        if response.status_code == 200:
                            result = response.json()
                            device_id = device_info.get('id')
                            new_status = result.get('status')

                            if new_status == 'approved' and request_id not in self.approved_devices:
                                print(f"Real-time approval detected: {device_id}")
                                self.allow_device(device_info)

                            elif new_status == 'blocked' and request_id not in self.blocked_devices:
                                print(f"Real-time block detected: {device_id}")
                                self.block_device(device_info)

                    except Exception as e:
                        print(f"Error checking device status for {request_id}: {e}")

            except Exception as e:
                print(f"Error in check_peripheral_status: {e}")

            time.sleep(PERIPHERAL_CHECK_INTERVAL)
    
    def peripheral_event(self, action, device):
        if action == 'add':
            print(f"New device detected: {device}")
            
            device_info = self.get_peripheral_info(device)
            if not device_info:
                return
            
            device_id = device_info['id']
            
            if device_id in self.approved_devices:
                print(f"Device already approved: {device_id}")
                self.allow_device(device_info)
                return
            
            if device_id in self.blocked_devices:
                print(f"Device already blocked: {device_id}")
                self.block_device(device_info)
                return
            
            print(f"Temporarily blocking device: {device_id}")
            self.block_device(device_info)
            
            self.send_peripheral_info(device_info)

    # ====================== Main Agent Functions ======================
    
    def system_monitor_loop(self):
        while True:
            try:
                current_time = time.time()
                if current_time - self.system_last_report >= SYSTEM_REPORT_INTERVAL:
                    if self.send_system_report():
                        self.system_last_report = current_time
            except Exception as e:
                print(f"System monitor loop error: {e}")
            
            time.sleep(10)  # Check every 10 seconds
    
    def peripheral_monitor_loop(self):
        observer = pyudev.MonitorObserver(self.monitor, self.peripheral_event)
        observer.start()
        
        status_thread = threading.Thread(target=self.check_peripheral_status, daemon=True)
        status_thread.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
    
    def run(self):
        # Start system monitoring in a separate thread
        system_thread = threading.Thread(target=self.system_monitor_loop, daemon=True)
        system_thread.start()
        
        # Start peripheral monitoring in the main thread
        self.peripheral_monitor_loop()

def main():
    agent = ComprehensiveAgent()
    agent.run()

if __name__ == "__main__":
    main()