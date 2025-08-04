import shutil
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, Response, send_file
import tempfile
from scapy.all import ARP, Ether, srp
import nmap
import socket
import threading
import queue
import json  
import time
import subprocess
import logging
import re
import netifaces
import networkx as nx
import matplotlib.pyplot as plt
import requests
import io
import base64
from functools import lru_cache, wraps
from datetime import datetime, timedelta
from threading import Lock
from urllib.parse import quote
import os

app = Flask(__name__)
app.secret_key = "replace_with_your_secret_key"  # Use a secure random key

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global dictionaries to store device statuses and scanned devices
device_status = {} 
scanned_devices = {}

# Define global variables first to avoid redefinition issues
# Global dictionary to store scan progress
scan_progress = {}

# Global dictionary to store device alerts
device_alerts = {}

# Define default alert rules
alert_rules = {
    "critical": True,
    "high": True,
    "medium": False,
    "low": False,
    "none": False,
    "threshold": 7.0  # CVSS score threshold for alerting
}

class NVDApiClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.last_request_time = None
        self.lock = Lock()
        self.min_request_interval = timedelta(seconds=6.1)  # Slightly more than 6 seconds
        self.logger = logging.getLogger(__name__ + '.NVDApiClient')
    
    def get_vulnerabilities(self, cpe_name=None, keywords=None, results_per_page=20):
        """
        Fetch vulnerabilities from NVD API with flexible configuration
        
        :param cpe_name: CPE name to filter vulnerabilities
        :param keywords: Keywords to search
        :param results_per_page: Number of results to return
        :return: Vulnerability data
        """
        try:
            # Rate limiting
            with self.lock:
                now = datetime.now()
                if self.last_request_time and (now - self.last_request_time) < self.min_request_interval:
                    wait_time = (self.min_request_interval - (now - self.last_request_time)).total_seconds()
                    self.logger.info(f"Rate limiting - waiting {wait_time:.1f} seconds")
                    time.sleep(wait_time)
                self.last_request_time = datetime.now()

            params = {
                "resultsPerPage": results_per_page
            }
            
            headers = {
                "Content-Type": "application/json"
            }
            
            # Add optional API key to headers if available
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            # Add optional filters
            if cpe_name:
                params["cpeName"] = cpe_name
            if keywords:
                params["keywordSearch"] = keywords
            
            response = requests.get(
                self.BASE_URL, 
                params=params, 
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"API request failed. Status: {response.status_code}")
                return None
        
        except Exception as e:
            self.logger.error(f"Error fetching vulnerabilities: {e}")
            return None
    
    def get_severity_rating(self, cvss_score):
        """
        Convert CVSS score to severity rating
        
        :param cvss_score: CVSS score (0.0-10.0)
        :return: Severity rating string
        """
        if cvss_score is None:
            return "Unknown"
        elif cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        elif cvss_score >= 0.1:
            return "Low"
        else:
            return "None"
    
    def normalize_software_name(self, name):
        """
        Normalize software name for better CPE matching
        """
        # Common name mappings
        name_mappings = {
            "microsoft office": "office",
            "mozilla firefox": "firefox",
            "vlc media player": "vlc",
            "oracle virtualbox": "virtualbox",
            "vmware workstation": "vmware_workstation",
            "mysql workbench": "mysql_workbench",
            "arduino ide": "arduino",
            "android studio": "android_studio",
            "autohotkey": "autohotkey",
            "cisco packet tracer": "cisco",
            "git": "git",
            "xampp": "xampp"
        }
        
        name_lower = name.lower()
        if name_lower in name_mappings:
            return name_mappings[name_lower]
        return name_lower
    
    def generate_cpe_pattern(self, software):
        """
        Generate a best-effort CPE pattern for a software name and version
        """
        vendor = ""
        product = self.normalize_software_name(software["name"])
        version = software["version"]
        
        # Handle special cases where vendor should be separated
        if "microsoft" in product:
            vendor = "microsoft"
            product = product.replace("microsoft ", "")
        elif "mozilla" in product:
            vendor = "mozilla"
            product = product.replace("mozilla ", "")
        elif "oracle" in product:
            vendor = "oracle"
            product = product.replace("oracle ", "")
        elif "vmware" in product:
            vendor = "vmware"
            product = product.replace("vmware ", "")
        elif "cisco" in product:
            vendor = "cisco"
            product = product.replace("cisco ", "")
        elif "apache" in product:
            vendor = "apache"
            product = product.replace("apache ", "")
        
        # Generate CPE pattern
        if vendor:
            return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        else:
            # Try with product as vendor
            return f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"
    
    def scan_software_vulnerabilities(self, software_list, max_results=5):
        """
        Scan a list of software for vulnerabilities
        
        :param software_list: List of software dictionaries with name and version
        :param max_results: Maximum number of vulnerabilities to show per software
        :return: Dictionary of results
        """
        results = {}
        
        for software in software_list:
            name = software['name']
            version = software['version']
            self.logger.info(f"Scanning {name} {version} for vulnerabilities...")
            
            # Try with CPE pattern first
            cpe_pattern = self.generate_cpe_pattern(software)
            self.logger.info(f"Using CPE pattern: {cpe_pattern}")
            
            vuln_data = self.get_vulnerabilities(cpe_name=cpe_pattern, results_per_page=max_results)
            
            # If no results with CPE, try with keywords
            if not vuln_data or vuln_data.get("totalResults", 0) == 0:
                self.logger.info(f"No results with CPE pattern. Trying keyword search...")
                # Use software name + version as keywords for better precision
                keywords = f"{name} {version}"
                vuln_data = self.get_vulnerabilities(keywords=keywords, results_per_page=max_results)
            
            if vuln_data and vuln_data.get("totalResults", 0) > 0:
                total_results = vuln_data.get("totalResults", 0)
                vulnerabilities = []
                
                for vuln in vuln_data["vulnerabilities"][:max_results]:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "Unknown CVE")
                    description = cve_data.get("descriptions", [{}])[0].get("value", "No description")
                    
                    # Get CVSS scores and ratings
                    metrics = cve_data.get("metrics", {})
                    
                    # Try to get CVSS V3 score first, then fall back to CVSS V2
                    cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                    cvss_v2 = metrics.get("cvssMetricV2", [])
                    
                    if cvss_v3:
                        score = cvss_v3[0].get("cvssData", {}).get("baseScore")
                        cvss_version = "3"
                    elif cvss_v2:
                        score = cvss_v2[0].get("cvssData", {}).get("baseScore")
                        cvss_version = "2"
                    else:
                        score = None
                        cvss_version = "Unknown"
                    
                    severity = self.get_severity_rating(score)
                    
                    vulnerability = {
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_version": cvss_version,
                        "cvss_score": score,
                        "severity": severity
                    }
                    
                    vulnerabilities.append(vulnerability)
                
                results[f"{name} {version}"] = {
                    "total_found": total_results,
                    "vulnerabilities": vulnerabilities
                }
            else:
                results[f"{name} {version}"] = {
                    "total_found": 0,
                    "vulnerabilities": []
                }
                self.logger.info(f"No vulnerabilities found for {name} {version}")
            
            # Add a small delay to avoid rate limiting
            time.sleep(0.5)
            
        return results
    
nvd_client = NVDApiClient(api_key="092aefa3-55a5-485d-8f5a-1c026a23d2e5")


# # Initialize the NVD API client

# ------------------------
# Helper functions for scanning
# ------------------------
def nmap_scan(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    devices = [{'ip': host, 'status': 'Up'} for host in nm.all_hosts()]
    return devices

def arp_scan(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname:
            return hostname
    except socket.herror:
        pass 
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True,
            text=True
        )
        lines = result.stdout.split("\n")
        for line in lines:
            if "<00>" in line and "UNIQUE" in line:
                return line.split()[0]
    except Exception:
        pass
    return ip

def get_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
    return default_gateway[0] if default_gateway else None

# ------------------------
# Authentication helpers
# ------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------------
# Routes for login/logout
# ------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get username and password from form data
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'netadmin' and password == 'Admin@123':
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "error")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    """
    Clear the user's session and redirect to the login page.
    """
    # Clear the session data
    session.clear()
    # Add a flash message to confirm logout
    flash("You have been successfully logged out.", "success")
    # Redirect to the login page
    return redirect(url_for('login'))

def get_network_ip_range():
    """
    Automatically detect the IP range from the primary network interface (ens33 or eth0)
    Returns a string like '192.168.1.0/24'
    """
    # Try ens33 first (common on newer Linux), then eth0 (older Linux)
    interfaces = ['ens33', 'eth0']
    
    for interface in interfaces:
        try:
            # Get interface details
            iface_details = netifaces.ifaddresses(interface)
            ip_info = iface_details[netifaces.AF_INET][0]
            ip_address = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Convert IP and netmask to network address
            ip_parts = list(map(int, ip_address.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            
            network_parts = []
            for ip_part, mask_part in zip(ip_parts, mask_parts):
                network_parts.append(str(ip_part & mask_part))
            
            # Calculate CIDR notation
            cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
            
            return f"{'.'.join(network_parts)}/{cidr}"
            
        except (KeyError, ValueError, IndexError):
            continue
    
    # Fallback to default range if auto-detection fails
    return "192.168.1.0/24"

# ------------------------
# Main application routes
# ------------------------
@app.route('/')
@login_required
def dashboard():
    ip_range = get_network_ip_range()  # Automatically detect IP range
    global scanned_devices
    logger.info(f"Dashboard requested - starting network scan for range {ip_range}")
    
    # Perform network scans
    nmap_devices = nmap_scan(ip_range)
    arp_devices = arp_scan(ip_range)
    
    # Create a dictionary of all devices found in ARP scan
    combined_devices = {d['ip']: d for d in arp_devices}
    
    # Add or update with nmap results
    for nmap_device in nmap_devices:
        ip = nmap_device['ip']
        if ip in combined_devices:
            combined_devices[ip]['status'] = nmap_device.get('status', 'Up')
        else:
            combined_devices[ip] = nmap_device
    
    # Update existing scanned_devices with new info, maintaining agent status
    for ip, device in combined_devices.items():
        if ip in scanned_devices:
            # Keep existing name and agent_installed status
            device['name'] = scanned_devices[ip].get('name', resolve_hostname(ip))
            device['agent_installed'] = scanned_devices[ip].get('agent_installed', False)
        else:
            # New device, resolve hostname and check if agent is installed
            device['name'] = resolve_hostname(ip)
            device['agent_installed'] = ip in device_status
        
        # Ensure all required fields are present
        if 'mac' not in device:
            device['mac'] = 'Unknown'
    
    # Update global scanned_devices
    scanned_devices.update(combined_devices)
    
    # Convert to list for template
    devices = list(scanned_devices.values())
    
    return render_template('index.html', devices=devices)

@app.route('/device/<ip>')
@login_required
def device_details(ip):
    data = device_status.get(ip, {})
    logger.info(f"Device details requested for {ip}")
    
    if not data:
        flash("No agent data found for this device. Please ensure the agent is installed and running.", "warning")
        return redirect(url_for('dashboard'))
    
    # Get installed software from device data
    installed_software = data.get("installed_software", [])
    
    # Retrieve vulnerability scan results if available
    vulnerability_results = data.get("vulnerability_scan", {}).get("results", {})
    total_score = 0
    for software_data in vulnerability_results.values():
        for vuln in software_data.get("vulnerabilities", []):
            total_score += vuln.get("cvss_score", 0) or 0
    
    # Retrieve network scan results if available
    network_scan_results = data.get("network_scan", {})
    
    # Retrieve service vulnerability scan results if available
    service_vulnerability_results = network_scan_results.get("service_vulnerabilities", {})
    
    results = {
        "total_score": total_score,
        "vulnerability_results": vulnerability_results,
        "installed_software": installed_software,
        "network_scan_results": network_scan_results,
        "service_vulnerability_results": service_vulnerability_results
    }
    
    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"data": data, "results": results})
    
    # Normal page request
    return render_template('device.html', ip=ip, data=data, results=results)

@app.route('/update_device', methods=['POST'])
def update_device():
    try:
        data = request.json
        if not data:
            logger.error("No JSON data received in the request.")
            return jsonify({"status": "error", "message": "No data received"}), 400

        logger.info(f"Received data from agent: {data['system']['hostname']}")
        
        # Extract IP address and hostname from the data
        ip = data['system'].get('ip_address', 'Unknown')
        hostname = data['system'].get('hostname', ip)
        logger.info(f"Updating device status for {ip} ({hostname})")
        
        if ip in device_status:
            device_status[ip].update(data)  # Merge new data into existing
        else:
            device_status[ip] = data
        
        # Update device information in scanned_devices too
        if ip in scanned_devices:
            scanned_devices[ip]['name'] = hostname
            scanned_devices[ip]['agent_installed'] = True
            
        # If the device wasn't previously scanned, add it
        else:
            # Get MAC address from the data if available
            mac = data['system'].get('mac_address', 'Unknown')
            scanned_devices[ip] = {
                'ip': ip,
                'name': hostname,
                'mac': mac,
                'agent_installed': True,
                'status': 'Up'
            }
                
        return jsonify({"status": "success"}), 200
    except KeyError as e:
        logger.error(f"Missing key in the received data: {str(e)}")
        return jsonify({"status": "error", "message": f"Missing key: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Error processing agent data: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

# ------------------------
# API endpoints (no login required for agent/alert endpoints)
# ------------------------

# Add a function to process vulnerabilities and set alerts
def process_vulnerabilities_and_alerts(ip, installed_software):
    try:
        # Scan vulnerabilities using the NVD API client
        vulnerability_results = nvd_client.scan_software_vulnerabilities(installed_software)
        
        # Save results to device status
        if ip in device_status:
            device_status[ip]['vulnerability_scan'] = {
                "timestamp": datetime.now().isoformat(),
                "results": vulnerability_results
            }
        
        # Trigger alerts based on user-defined rules
        alerts = []
        for software, details in vulnerability_results.items():
            for vuln in details.get("vulnerabilities", []):
                severity = vuln.get("severity", "Unknown").lower()
                cvss_score = vuln.get("cvss_score", 0)
                
                # Check if the vulnerability meets the alert criteria
                if severity in alert_rules and alert_rules[severity] or cvss_score >= alert_rules["threshold"]:
                    alerts.append({
                        "ip": ip,
                        "software": software,
                        "cve_id": vuln.get("cve_id", "Unknown"),
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "description": vuln.get("description", "No description"),
                        "timestamp": datetime.now().isoformat()
                    })
        
        # Store alerts in a global dictionary
        if ip not in device_alerts:
            device_alerts[ip] = []
        device_alerts[ip].extend(alerts)
        
        return alerts
    except Exception as e:
        logger.error(f"Error processing vulnerabilities for {ip}: {str(e)}")
        return []

# Add a route to trigger vulnerability scans and alerts
# Add a mutex to prevent multiple scans running on the same IP simultaneously
scan_mutex = {}

@app.route('/scan_vulnerabilities', methods=['POST'])
@login_required
def scan_vulnerabilities():
    """
    Trigger a vulnerability scan for a specific IP and update progress.
    """
    try:
        ip = request.form.get('ip')
        if not ip:
            flash("IP address is required", "error")
            return redirect(url_for('dashboard'))

        # Check if a scan is already in progress for this IP
        if ip in scan_mutex and scan_mutex[ip]:
            # Return a conflict error for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    "status": "error", 
                    "message": "A scan is already in progress for this device. Please wait for it to complete.",
                    "type": "vulnerability_scan"
                }), 409
            
            flash("A scan is already in progress for this device. Please wait for it to complete.", "warning")
            return redirect(url_for('device_details', ip=ip))

        data = device_status.get(ip, {})
        if not data:
            flash("No device data found for this IP", "error")
            return redirect(url_for('dashboard'))

        installed_software = data.get("installed_software", [])
        if not installed_software:
            # Return a JSON response with an error for the fetch request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    "status": "error", 
                    "message": "No software information available for this device",
                    "type": "vulnerability_scan"
                }), 400
            
            flash("No software information available for this device", "warning")
            return redirect(url_for('device_details', ip=ip))

        # Set the mutex to indicate a scan is in progress
        scan_mutex[ip] = True

        # Initialize scan progress with empty results and correct type
        scan_progress[ip] = {
            "status": "in_progress", 
            "message": "Starting vulnerability scan...", 
            "type": "vulnerability_scan",
            "results": [],
            "completed": 0,
            "total": len(installed_software)
        }

        # Perform the scan in a separate thread
        def perform_scan():
            try:
                vulnerability_results = {}
                count = 0
                
                # Simulate initialization phase
                scan_progress[ip]["message"] = "Initializing vulnerability database..."
                scan_progress[ip]["completed"] = 0
                scan_progress[ip]["type"] = "vulnerability_scan"  # Ensure type is set on every update
                time.sleep(1)  # Simulate initialization work
                
                for software in installed_software:
                    try:
                        count += 1
                        name = software.get("name", "Unknown")
                        version = software.get("version", "Unknown")
                        
                        # Update progress with type
                        scan_progress[ip]["message"] = f"Scanning {name} {version}... ({count}/{len(installed_software)})"
                        scan_progress[ip]["completed"] = count
                        scan_progress[ip]["type"] = "vulnerability_scan"
                        
                        # Log scanning status
                        logger.info(f"Scanning {name} {version} for vulnerabilities...")
                        
                        # Perform the actual scan
                        result = nvd_client.scan_software_vulnerabilities([software], max_results=5)
                        
                        if result:
                            # Add results to the main dictionary
                            vulnerability_results.update(result)
                            
                            # Update the progress with the latest result
                            software_key = next(iter(result.keys()))
                            if result[software_key]["total_found"] > 0:
                                scan_progress[ip]["results"].append(result)
                                logger.info(f"Found {result[software_key]['total_found']} vulnerabilities for {name} {version}")
                            else:
                                logger.info(f"No vulnerabilities found for {name} {version}")
                    
                    except Exception as e:
                        logger.error(f"Error scanning {name} {version}: {str(e)}")
                        scan_progress[ip]["message"] = f"Error scanning {name} {version}: {str(e)}"
                        scan_progress[ip]["type"] = "vulnerability_scan"
                
                # Save results to device status
                if ip in device_status:
                    device_status[ip]['vulnerability_scan'] = {
                        "timestamp": datetime.now().isoformat(),
                        "results": vulnerability_results
                    }

                # Calculate total score for all vulnerabilities
                total_score = 0
                for software_data in vulnerability_results.values():
                    for vuln in software_data.get("vulnerabilities", []):
                        total_score += vuln.get("cvss_score", 0) or 0
                
                # Update final progress status with type
                scan_progress[ip]["status"] = "completed"
                scan_progress[ip]["message"] = f"Scan completed. Found vulnerabilities in {len(scan_progress[ip]['results'])} software packages."
                scan_progress[ip]["total_score"] = total_score
                scan_progress[ip]["type"] = "vulnerability_scan"
                
                logger.info(f"Vulnerability scan completed for {ip}")
                
            except Exception as e:
                scan_progress[ip]["status"] = "error"
                scan_progress[ip]["message"] = f"Error during scan: {str(e)}"
                scan_progress[ip]["type"] = "vulnerability_scan"
                logger.error(f"Error during vulnerability scan for {ip}: {str(e)}")
            finally:
                # Release the mutex when done
                scan_mutex[ip] = False

        # Start the scan in a separate thread
        scan_thread = threading.Thread(target=perform_scan)
        scan_thread.daemon = True
        scan_thread.start()

        # Return a 202 Accepted response for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "status": "accepted", 
                "message": "Vulnerability scan started",
                "type": "vulnerability_scan"
            }), 202
            
        # For regular form submissions, redirect to the device details page
        return redirect(url_for('device_details', ip=ip))
    
    except Exception as e:
        logger.error(f"Error initiating vulnerability scan: {str(e)}")
        
        # Release the mutex if there was an error starting the scan
        if ip in scan_mutex:
            scan_mutex[ip] = False
        
        # Return a JSON error response for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "status": "error", 
                "message": str(e),
                "type": "vulnerability_scan"
            }), 500
        
        flash(f"Error scanning vulnerabilities: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/scan_progress/<ip>')
def scan_progress_stream(ip):
    """
    Stream the progress of the vulnerability scan for a specific IP.
    """
    def generate():
        last_data = None
        while True:
            progress = scan_progress.get(ip, {"status": "idle", "message": "No scan in progress"})
            
            # Only send updates when data changes
            current_data = json.dumps(progress)
            if current_data != last_data:
                last_data = current_data
                yield f"data: {current_data}\n\n"
            
            # If the scan is complete or in error state, break the loop after sending the final update
            if progress.get("status") in ["completed", "error"]:
                break
                
            time.sleep(0.5)
        
        # Send a final complete message to ensure client knows the stream is done
        yield f"data: {json.dumps({'status': 'stream_closed'})}\n\n"

    return Response(generate(), content_type='text/event-stream')

# Add a route to view alerts
@app.route('/alerts')
@login_required
def view_alerts():
    ip = request.args.get('ip')
    alerts = device_alerts.get(ip, []) if ip else [alert for alerts in device_alerts.values() for alert in alerts]
    return render_template('alerts.html', alerts=alerts)

# Add a route to update alert rules
@app.route('/update_alert_rules', methods=['POST'])
@login_required
def update_alert_rules():
    try:
        global alert_rules
        alert_rules = {
            "critical": request.form.get('critical') == 'on',
            "high": request.form.get('high') == 'on',
            "medium": request.form.get('medium') == 'on',
            "low": request.form.get('low') == 'on',
            "none": request.form.get('none') == 'on',
            "threshold": float(request.form.get('threshold', 7.0))
        }
        flash("Alert rules updated successfully.", "success")
    except Exception as e:
        flash(f"Error updating alert rules: {str(e)}", "error")
    return redirect(url_for('view_alerts'))

def perform_network_scan(ip):
    """
    Perform a network scan on the given IP to retrieve open ports, OS version, and services.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-sV -O')  # -sV for service version detection, -O for OS detection
        scan_results = {
            "os": nm[ip].get("osmatch", [{}])[0].get("name", "Unknown OS"),
            "ports": [],
            "service_vulnerabilities": {}  # New field to store vulnerabilities by service
        }
        for port in nm[ip].get("tcp", {}):
            port_data = nm[ip]["tcp"][port]
            scan_results["ports"].append({
                "port": port,
                "state": port_data.get("state", "unknown"),
                "name": port_data.get("name", "unknown"),
                "product": port_data.get("product", "unknown"),
                "version": port_data.get("version", "unknown")
            })
        return scan_results
    except Exception as e:
        logger.error(f"Error performing network scan on {ip}: {str(e)}")
        return {"os": "Unknown OS", "ports": [], "service_vulnerabilities": {}}

@app.route('/scan_network', methods=['POST'])
@login_required
def scan_network():
    """
    Trigger a network scan for a specific IP and store the results.
    """
    try:
        ip = request.form.get('ip')
        if not ip:
            return jsonify({"status": "error", "message": "IP address is required for network scan."}), 400

        # Check if a scan is already in progress for this IP
        if ip in scan_mutex and scan_mutex[ip]:
            return jsonify({
                "status": "error", 
                "message": "A scan is already in progress for this device. Please wait for it to complete.",
                "type": "network_scan"
            }), 409

        logger.info(f"Performing network scan on {ip}...")
        
        # Set the mutex to indicate a scan is in progress
        scan_mutex[ip] = True
        
        # Initialize scan progress
        scan_progress[ip] = {
            "status": "in_progress",
            "message": "Starting network scan...",
            "completed": 0,
            "total": 100,
            "type": "network_scan"
        }
        
        def perform_network_scan_thread():
            try:
                nm = nmap.PortScanner()
                
                # Update progress at different stages
                scan_progress[ip]["message"] = "Detecting network hosts..."
                scan_progress[ip]["completed"] = 25
                
                scan_progress[ip]["message"] = "Scanning for open ports..."
                scan_progress[ip]["completed"] = 50
                
                # Perform the actual scan
                nm.scan(hosts=ip, arguments='-sV -O')
                
                scan_progress[ip]["message"] = "Analyzing services and OS..."
                scan_progress[ip]["completed"] = 75
                
                # Process scan results
                scan_results = {
                    "os": "Unknown OS",
                    "ports": []
                }
                
                # Safely extract data from nmap results
                if ip in nm.all_hosts():
                    if 'osmatch' in nm[ip] and len(nm[ip]['osmatch']) > 0:
                        scan_results["os"] = nm[ip]['osmatch'][0].get('name', "Unknown OS")
                    
                    if 'tcp' in nm[ip]:
                        for port in nm[ip]['tcp']:
                            port_data = nm[ip]['tcp'][port]
                            scan_results["ports"].append({
                                "port": port,
                                "state": port_data.get("state", "unknown"),
                                "name": port_data.get("name", "unknown"),
                                "product": port_data.get("product", "unknown"),
                                "version": port_data.get("version", "unknown")
                            })
                
                # Save results
                if ip in device_status:
                    device_status[ip]['network_scan'] = scan_results
                else:
                    device_status[ip] = {'network_scan': scan_results}
                
                scan_progress[ip]["status"] = "completed"
                scan_progress[ip]["message"] = f"Network scan completed. Found {len(scan_results['ports'])} open ports."
                scan_progress[ip]["completed"] = 100
                
                logger.info(f"Network scan completed for {ip}: {len(scan_results['ports'])} ports found")
                
            except Exception as e:
                scan_progress[ip]["status"] = "error"
                scan_progress[ip]["message"] = f"Error during network scan: {str(e)}"
                scan_progress[ip]["completed"] = 0
                logger.error(f"Error during network scan for {ip}: {str(e)}")
            finally:
                # Release the mutex when done
                scan_mutex[ip] = False

        # Start the scan thread
        thread = threading.Thread(target=perform_network_scan_thread)
        thread.daemon = True
        thread.start()

        return jsonify({"status": "accepted", "message": "Network scan started"}), 202
    
    except Exception as e:
        logger.error(f"Error initiating network scan: {str(e)}")
        
        # Release the mutex if there was an error starting the scan
        if ip in scan_mutex:
            scan_mutex[ip] = False
            
        return jsonify({"status": "error", "message": f"Failed to start network scan: {str(e)}"}), 500

@app.route('/scan_service_vulnerabilities', methods=['POST'])
@login_required
def scan_service_vulnerabilities():
    """
    Scan for vulnerabilities in discovered network services.
    """
    try:
        ip = request.form.get('ip')
        if not ip:
            flash("IP address is required for service vulnerability scan.", "error")
            return redirect(url_for('dashboard'))

        # Check if a scan is already in progress for this IP
        if ip in scan_mutex and scan_mutex[ip]:
            # Return a conflict error for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    "status": "error", 
                    "message": "A scan is already in progress for this device. Please wait for it to complete.",
                    "type": "service_scan"
                }), 409
            
            flash("A scan is already in progress for this device. Please wait for it to complete.", "warning")
            return redirect(url_for('device_details', ip=ip))

        if ip not in device_status or 'network_scan' not in device_status[ip]:
            # Return error for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    "status": "error", 
                    "message": "Network scan must be performed first.",
                    "type": "service_scan"
                }), 400
                
            flash("Network scan must be performed first.", "error")
            return redirect(url_for('device_details', ip=ip))

        network_scan = device_status[ip]['network_scan']
        ports = network_scan.get("ports", [])

        # Set the mutex to indicate a scan is in progress
        scan_mutex[ip] = True

        # Initialize progress tracking with explicit type
        total_services = len([p for p in ports if p.get('product') and p.get('version')])
        scan_progress[ip] = {
            "status": "in_progress", 
            "message": f"Starting service vulnerability scan for {total_services} services...", 
            "completed": 0,
            "total": total_services,
            "results": [],
            "type": "service_scan"  # Explicitly set the scan type
        }

        # Perform the scan in a separate thread
        def perform_service_scan():
            try:
                service_vulns = {}
                count = 0
                
                for port_info in ports:
                    product = port_info.get('product')
                    version = port_info.get('version')
                    port = port_info.get('port')
                    
                    if product and version and product != "unknown" and version != "unknown":
                        count += 1
                        service_name = f"{product} {version} (Port {port})"
                        
                        # Update progress with type
                        scan_progress[ip]["message"] = f"Scanning {service_name}... ({count}/{total_services})"
                        scan_progress[ip]["completed"] = count
                        scan_progress[ip]["type"] = "service_scan"
                        
                        logger.info(f"Scanning service {service_name} for vulnerabilities...")
                        
                        # Format software entry for NVD API
                        software = {"name": product, "version": version}
                        
                        # Perform the actual scan
                        result = nvd_client.scan_software_vulnerabilities([software], max_results=5)
                        
                        if result:
                            # Add results with service identification
                            key = next(iter(result.keys()))
                            result_with_port = {
                                f"{key} (Port {port})": result[key]
                            }
                            service_vulns.update(result_with_port)
                            
                            # Update progress with the latest result
                            if result[key]["total_found"] > 0:
                                scan_progress[ip]["results"].append(result_with_port)
                                logger.info(f"Found {result[key]['total_found']} vulnerabilities for {service_name}")
                            else:
                                logger.info(f"No vulnerabilities found for {service_name}")
                
                # Save results to device status
                if ip in device_status and 'network_scan' in device_status[ip]:
                    device_status[ip]['network_scan']["service_vulnerabilities"] = service_vulns
                
                # Calculate total score
                total_score = 0
                for service_data in service_vulns.values():
                    for vuln in service_data.get("vulnerabilities", []):
                        total_score += vuln.get("cvss_score", 0) or 0
                
                # Update final progress status with type
                scan_progress[ip]["status"] = "completed"
                scan_progress[ip]["message"] = f"Scan completed. Found vulnerabilities in {len(scan_progress[ip]['results'])} services."
                scan_progress[ip]["total_score"] = total_score
                scan_progress[ip]["type"] = "service_scan"
                
                logger.info(f"Service vulnerability scan completed for {ip}")
                
            except Exception as e:
                scan_progress[ip]["status"] = "error"
                scan_progress[ip]["message"] = f"Error during scan: {str(e)}"
                scan_progress[ip]["type"] = "service_scan"
                logger.error(f"Error during service vulnerability scan for {ip}: {str(e)}")
            finally:
                # Release the mutex when done
                scan_mutex[ip] = False

        # Start the scan in a separate thread
        scan_thread = threading.Thread(target=perform_service_scan)
        scan_thread.daemon = True
        scan_thread.start()

        # Return a 202 Accepted response for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "status": "accepted", 
                "message": "Service vulnerability scan started",
                "type": "service_scan"
            }), 202

        # Redirect to the device details page
        return redirect(url_for('device_details', ip=ip))
    
    except Exception as e:
        logger.error(f"Error initiating service vulnerability scan: {str(e)}")
        
        # Release the mutex if there was an error starting the scan
        if ip in scan_mutex:
            scan_mutex[ip] = False
        
        # Return a JSON error response for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "status": "error", 
                "message": str(e),
                "type": "service_scan"
            }), 500
            
        flash(f"Error scanning service vulnerabilities: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/network_map')
def network_map():
    global scanned_devices  # Use the globally stored scan results
    gateway_ip = get_default_gateway()

    if not scanned_devices:
        return "No scanned devices available. Please visit the dashboard first."

    # Build graph
    G = nx.Graph()
    for ip, device in scanned_devices.items():
        name_label = f"{device['name']} ({ip})"
        G.add_node(name_label)

        # Connect to gateway
        if gateway_ip and ip != gateway_ip:
            gateway_label = f"Gateway ({gateway_ip})"
            G.add_edge(name_label, gateway_label)

    # Draw the network map
    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightblue", edge_color="gray", font_size=10)
    plt.title("Network Map")

    # Convert to Base64 image
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    img_base64 = base64.b64encode(img.getvalue()).decode()

    return render_template("network_map.html", img_data=img_base64)

# Data storage
DEVICES_DB = 'devices.json'
devices = {}

def load_devices():
    global devices
    if os.path.exists(DEVICES_DB):
        try:
            with open(DEVICES_DB, 'r') as f:
                devices = json.load(f)
        except Exception as e:
            print(f"Error loading devices: {e}")
            devices = {}

def save_devices():
    try:
        with open(DEVICES_DB, 'w') as f:
            json.dump(devices, f, indent=2)
    except Exception as e:
        print(f"Error saving devices: {e}")

# Load devices on startup
load_devices()

@app.route('/peripheral_monitor')
def peripheral():
    pending_devices = {k: v for k, v in devices.items() if v.get('status') == 'pending'}
    approved_devices = {k: v for k, v in devices.items() if v.get('status') == 'approved'}
    blocked_devices = {k: v for k, v in devices.items() if v.get('status') == 'blocked'}
    
    return render_template('peripherals.html', 
                          pending_devices=pending_devices,
                          approved_devices=approved_devices,
                          blocked_devices=blocked_devices)

@app.route('/api/device', methods=['POST'])
def receive_device():
    device_info = request.json
    request_id = device_info.get('request_id')
    
    if not request_id:
        return jsonify({'error': 'Missing request_id'}), 400
    
    # Add status and timestamp
    device_info['status'] = 'pending'
    device_info['received_at'] = datetime.now().isoformat()
    
    # Store device info
    devices[request_id] = device_info
    save_devices()
    
    return jsonify({'status': 'received', 'request_id': request_id})

@app.route('/api/device/<request_id>', methods=['GET'])
def get_device_status(request_id):
    if request_id not in devices:
        return jsonify({'error': 'Device not found'}), 404
    
    return jsonify(devices[request_id])

@app.route('/approve/<request_id>', methods=['POST'])
def approve_device(request_id):
    if request_id not in devices:
        return jsonify({'error': 'Device not found'}), 404
    
    devices[request_id]['status'] = 'approved'
    devices[request_id]['decision_time'] = datetime.now().isoformat()
    save_devices()
    
    return redirect(url_for('peripheral'))

@app.route('/block/<request_id>', methods=['POST'])
def block_device(request_id):
    if request_id not in devices:
        return jsonify({'error': 'Device not found'}), 404
    
    devices[request_id]['status'] = 'blocked'
    devices[request_id]['decision_time'] = datetime.now().isoformat()
    save_devices()
    
    return redirect(url_for('peripheral'))

# Add this near the other route definitions in Server.py

@app.route('/download')
@login_required
def download_agents():
    """
    Serve download page with pre-configured agents for Windows and Linux.
    The agents will be automatically configured with the current server's IP.
    """
    # Get the server's IP address that clients should connect to
    server_ip = request.host.split(':')[0]
    
    # Create modified versions of the agents with the correct server IP
    linux_agent_content = generate_linux_agent(server_ip)
    windows_agent_content = generate_windows_agent_content(server_ip)
    
    return render_template('download.html', 
                         server_ip=server_ip,
                         linux_agent_content=linux_agent_content,
                         windows_agent_content=windows_agent_content)

@app.route('/download/linux_agent')
@login_required
def download_linux_agent():
    """
    Download the Linux agent as a shell script.
    """
    server_ip = request.host.split(':')[0]
    agent_content = generate_linux_agent(server_ip)
    
    # Create a response with the agent content
    response = Response(
        agent_content,
        mimetype='text/x-shellscript',
        headers={
            'Content-Disposition': f'attachment; filename=netsentry_agent_linux.sh',
            'Content-Length': len(agent_content)
        }
    )
    return response

@app.route('/download/windows_agent')
@login_required
def download_windows_agent():
    """
    Download the Windows agent as a batch installer script.
    """
    server_ip = request.host.split(':')[0]
    agent_content = generate_windows_agent_content(server_ip)
    
    # Create a response with the agent content
    response = Response(
        agent_content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': 'attachment; filename=install_netsentry_agent.bat',
            'Content-Length': len(agent_content)
        }
    )
    return response

def generate_windows_agent_content(server_ip):
    """
    Generate the Windows agent content with the correct server IP.
    Returns the content as a string.
    """
    # Read the original Windows agent content
    with open('win_agent.py', 'r') as f:
        content = f.read()
    
    # Replace the server IP in the content
    content = content.replace(
        "SERVER_IP = 'http://192.168.31.187:5053'",
        f"SERVER_IP = 'http://{server_ip}:5053'"
    )
    
    # Create a batch script wrapper
    script = f"""@echo off
REM NetSentry Windows Agent Installer
REM Automatically generated by NetSentry Server

echo Installing NetSentry Windows Agent...
echo Server: {server_ip}

set AGENT_DIR="%ProgramFiles%\\NetSentry"
set AGENT_FILE="%AGENT_DIR%\\netsentry_agent.pyw"

mkdir %AGENT_DIR% 2>nul

echo Writing agent file...
echo {content} > %AGENT_FILE%

echo Creating scheduled task...
schtasks /create /tn "NetSentry Agent" /tr "pythonw %AGENT_FILE%" /sc minute /mo 5 /ru SYSTEM /f

echo NetSentry Agent installed and running as a scheduled task
echo To check status: schtasks /query /tn "NetSentry Agent"
"""
    
    return script

def generate_linux_agent(server_ip):
    """
    Generate the Linux agent script with the correct server IP.
    Returns the content as a string.
    """
    # Read the original Linux agent content
    with open('linux_Agent.py', 'r') as f:
        content = f.read()
    
    # Replace the server IP in the content
    content = content.replace(
        'SYSTEM_SERVER_URL = "http://192.168.31.187:5053/update_device"',
        f'SYSTEM_SERVER_URL = "http://{server_ip}:5053/update_device"'
    )
    content = content.replace(
        'PERIPHERAL_SERVER_URL = "http://192.168.31.187:5053/api/device"',
        f'PERIPHERAL_SERVER_URL = "http://{server_ip}:5053/api/device"'
    )
    
    # Create a shell script wrapper
    script = f"""#!/bin/bash
# NetSentry Linux Agent Installer
# Automatically generated by NetSentry Server

echo "Installing NetSentry Linux Agent..."
echo "Server: {server_ip}"

# Create agent directory
mkdir -p /opt/netsentry
AGENT_FILE="/opt/netsentry/netsentry_agent.py"

# Write the agent file
cat > "$AGENT_FILE" << 'EOF'
{content}
EOF

# Make executable
chmod +x "$AGENT_FILE"

# Create systemd service
cat > /etc/systemd/system/netsentry.service << EOF
[Unit]
Description=NetSentry Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 "$AGENT_FILE"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable netsentry
systemctl start netsentry

echo "NetSentry Agent installed and running as a system service"
echo "To check status: systemctl status netsentry"
"""
    
    return script

if __name__ == "__main__":
    print("\n=============================================")
    print("NetSentry Server starting...")
    print("Make sure your firewall allows connections to port 5053")
    print("Server will be accessible at:")
    
    # Try to get and display all network interfaces
    try:
        hostname = socket.gethostname()
        host_ip = socket.gethostbyname(hostname)
        print(f"• http://{host_ip}:5053 (Primary IP)")
        
        # Try to get all IP addresses
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip != host_ip:
                print(f"• http://{ip}:5053")
                
        print("• http://localhost:5053 (Local access only)")
        print("=============================================\n")
    except Exception as e:
        print(f"Error detecting network interfaces: {e}")
        
    # You can change the port here if 5053 is being blocked or used
    app.run(host='0.0.0.0', port=5053, debug=True)