#!/usr/bin/env python3
"""
SSH MANAGER - Multi-Computer Connection Tool with Network Discovery
Standalone tool to connect to multiple Linux/Windows computers via SSH
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import paramiko
import yaml
import json
import os
import sys
import threading
import datetime
import socket
import csv
import subprocess
import time
import ipaddress
import netifaces
import qrcode
import pyotp
from pathlib import Path
from io import BytesIO
from PIL import Image, ImageTk

# ==================== CONFIGURATION ====================
CONFIG_FILE = "ssh_hosts.yaml"
RESULTS_DIR = "ssh_results"
LOG_FILE = "ssh_manager.log"
SECRETS_FILE = "ssh_secrets.json"

# Colors for GUI
BG_COLOR = "#f0f8ff"
HEADER_COLOR = "#1e88e5"
SIDEBAR_COLOR = "#bbdefb"
BUTTON_COLOR = "#2196f3"
BUTTON_HOVER = "#1976d2"
TEXT_COLOR = "#212121"
COLOR_SUCCESS = "#4caf50"
COLOR_ERROR = "#f44336"
COLOR_WARNING = "#ff9800"
COLOR_INFO = "#2196f3"

class TwoFactorAuth:
    """Two-Factor Authentication Manager"""
    def __init__(self):
        self.secrets = self.load_secrets()
        
    def load_secrets(self):
        """Load TOTP secrets from file"""
        if os.path.exists(SECRETS_FILE):
            with open(SECRETS_FILE, 'r') as f:
                return json.load(f)
        return {}
    
    def save_secrets(self):
        """Save TOTP secrets to file"""
        with open(SECRETS_FILE, 'w') as f:
            json.dump(self.secrets, f, indent=2)
    
    def generate_secret(self, hostname, username):
        """Generate a new TOTP secret for a host"""
        secret = pyotp.random_base32()
        key = f"{hostname}:{username}"
        self.secrets[key] = secret
        self.save_secrets()
        
        # Generate provisioning URI for QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=f"{username}@{hostname}",
            issuer_name="SSH Manager"
        )
        
        return secret, provisioning_uri
    
    def get_secret(self, hostname, username):
        """Get secret for a host"""
        key = f"{hostname}:{username}"
        return self.secrets.get(key)
    
    def verify_otp(self, hostname, username, otp_code):
        """Verify OTP code"""
        secret = self.get_secret(hostname, username)
        if not secret:
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(otp_code)
    
    def get_current_otp(self, hostname, username):
        """Get current OTP code"""
        secret = self.get_secret(hostname, username)
        if not secret:
            return None
        
        totp = pyotp.TOTP(secret)
        return totp.now()

class NetworkScanner:
    """Network Scanning and Discovery"""
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.discovered_hosts = []
        
    def log(self, message, level="info"):
        """Log messages"""
        if self.log_callback:
            self.log_callback(message, level)
        else:
            print(f"[{level.upper()}] {message}")
    
    def get_local_networks(self):
        """Get all local network ranges"""
        networks = []
        
        try:
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for link in addrs[netifaces.AF_INET]:
                            ip = link['addr']
                            netmask = link['netmask']
                            
                            # Skip localhost and docker networks
                            if ip.startswith('127.') or ip.startswith('172.17.'):
                                continue
                            
                            # Calculate network
                            network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                            networks.append(str(network))
                            
                except:
                    continue
                    
        except ImportError:
            # Fallback if netifaces not available
            self.log("netifaces not installed, using default network ranges", "warning")
            networks = ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"]
        
        return list(set(networks))  # Remove duplicates
    
    def ping_sweep(self, network_range, timeout=1):
        """Ping sweep to find active hosts"""
        active_hosts = []
        network = ipaddress.ip_network(network_range)
        
        def ping_host(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((str(ip), 80))
                sock.close()
                return ip if result == 0 else None
            except:
                return None
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(str(result))
        
        return active_hosts
    
    def scan_ssh_ports(self, ip_list, ports=[22, 2222, 22222]):
        """Scan for SSH ports on active hosts"""
        ssh_hosts = []
        
        def check_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Try to get SSH banner
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3)
                        sock.connect((ip, port))
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                        
                        if 'SSH' in banner or 'OpenSSH' in banner:
                            return ip, port, banner[:100]
                    except:
                        pass
                    return ip, port, "SSH Detected"
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for ip in ip_list:
                for port in ports:
                    futures.append(executor.submit(check_port, ip, port))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip, port, banner = result
                    ssh_hosts.append({
                        'ip': ip,
                        'port': port,
                        'banner': banner,
                        'status': 'detected'
                    })
        
        return ssh_hosts
    
    def discover_ssh_hosts(self):
        """Main discovery method - finds SSH hosts on network"""
        self.log("Starting network discovery...", "info")
        
        all_ssh_hosts = []
        networks = self.get_local_networks()
        
        self.log(f"Found {len(networks)} network interfaces", "info")
        
        for network in networks:
            self.log(f"Scanning network: {network}", "info")
            
            # Step 1: Find active hosts
            self.log(f"  Performing ping sweep on {network}...", "info")
            active_hosts = self.ping_sweep(network)
            self.log(f"  Found {len(active_hosts)} active hosts", "success")
            
            # Step 2: Scan for SSH ports
            if active_hosts:
                self.log(f"  Scanning for SSH ports...", "info")
                ssh_hosts = self.scan_ssh_ports(active_hosts)
                all_ssh_hosts.extend(ssh_hosts)
                self.log(f"  Found {len(ssh_hosts)} SSH hosts", "success")
        
        self.log(f"Discovery complete. Found {len(all_ssh_hosts)} SSH hosts total", "info")
        return all_ssh_hosts

class SSHManager:
    """Main SSH manager class"""
    def __init__(self):
        self.hosts = []
        self.settings = {}
        self.results = {}
        self.twofa = TwoFactorAuth()
        self.scanner = NetworkScanner()
        self.ensure_directories()
        self.load_config()
        
    def ensure_directories(self):
        """Create necessary directories"""
        os.makedirs(RESULTS_DIR, exist_ok=True)
        
    def load_config(self, config_path=None):
        """Load hosts from YAML configuration file"""
        if config_path is None:
            config_path = CONFIG_FILE
            
        if not os.path.exists(config_path):
            # Create sample config
            sample_config = {
                'hosts': [
                    {
                        'name': 'ubuntu-server',
                        'hostname': '192.168.1.100',
                        'port': 22,
                        'username': 'ubuntu',
                        'auth_type': 'key',
                        'key_file': '~/.ssh/id_rsa',
                        'password': '',
                        'tags': ['linux', 'ubuntu', 'server'],
                        'enable_2fa': False,
                        '2fa_secret': ''
                    }
                ],
                'settings': {
                    'timeout': 10,
                    'banner_timeout': 30,
                    'default_port': 22,
                    'default_username': 'root',
                    'auto_discover': True,
                    'scan_networks': ['192.168.1.0/24']
                }
            }
            
            with open(config_path, 'w') as f:
                yaml.dump(sample_config, f, default_flow_style=False)
            
            print(f"[INFO] Sample config created at {config_path}")
            self.hosts = sample_config['hosts']
            self.settings = sample_config['settings']
            return self.hosts
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            self.hosts = config.get('hosts', [])
            self.settings = config.get('settings', {})
            print(f"[INFO] Loaded {len(self.hosts)} hosts from {config_path}")
            return self.hosts
            
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            return []
    
    def save_config(self, hosts=None, config_path=None):
        """Save hosts to YAML configuration file"""
        if config_path is None:
            config_path = CONFIG_FILE
        
        if hosts is None:
            hosts = self.hosts
            
        config = {
            'hosts': hosts,
            'settings': self.settings
        }
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            print(f"[INFO] Config saved to {config_path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save config: {e}")
            return False
    
    def discover_network_hosts(self):
        """Discover SSH hosts on local network"""
        return self.scanner.discover_ssh_hosts()
    
    def test_connection_with_2fa(self, host_info, otp_code=None):
        """Test SSH connection with optional 2FA"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Prepare connection parameters
            hostname = host_info['hostname']
            port = host_info.get('port', self.settings.get('default_port', 22))
            username = host_info.get('username', self.settings.get('default_username', 'root'))
            timeout = self.settings.get('timeout', 10)
            enable_2fa = host_info.get('enable_2fa', False)
            
            print(f"[DEBUG] Connecting to {hostname}:{port} as {username}")
            
            # Handle authentication
            auth_type = host_info.get('auth_type', 'key')
            password = None
            key_filename = None
            
            if auth_type == 'password':
                password = host_info.get('password', '')
            else:
                key_file = host_info.get('key_file', '')
                if key_file:
                    key_path = os.path.expanduser(key_file)
                    if os.path.exists(key_path):
                        key_filename = key_path
                    else:
                        # Try default keys
                        default_keys = [
                            '~/.ssh/id_rsa',
                            '~/.ssh/id_dsa',
                            '~/.ssh/id_ecdsa',
                            '~/.ssh/id_ed25519'
                        ]
                        for key in default_keys:
                            key_path = os.path.expanduser(key)
                            if os.path.exists(key_path):
                                key_filename = key_path
                                break
            
            # Connect
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=timeout,
                banner_timeout=self.settings.get('banner_timeout', 30),
                allow_agent=True,
                look_for_keys=True
            )
            
            print(f"[DEBUG] Connected successfully to {hostname}")
            
            # If 2FA is enabled, verify OTP
            if enable_2fa and otp_code:
                # Execute OTP verification command (customize based on your setup)
                verify_command = f"echo {otp_code} | /usr/local/bin/verify_otp.sh"
                stdin, stdout, stderr = client.exec_command(verify_command)
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code != 0:
                    client.close()
                    return {'status': 'error', 'message': '2FA verification failed'}
            
            # Get system info
            stdin, stdout, stderr = client.exec_command('uname -a 2>/dev/null || echo "Unknown OS"')
            os_info = stdout.read().decode().strip()
            
            return {
                'status': 'success',
                'os_info': os_info,
                'hostname': hostname,
                '2fa_required': enable_2fa,
                '2fa_passed': enable_2fa and otp_code is not None
            }
            
        except paramiko.ssh_exception.AuthenticationException as e:
            return {'status': 'error', 'message': 'Authentication failed'}
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            return {'status': 'error', 'message': f'Cannot connect to host'}
        except socket.timeout as e:
            return {'status': 'error', 'message': 'Connection timeout'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
        finally:
            try:
                client.close()
            except:
                pass
    
    def execute_command(self, host_info, command):
        """Execute a command on remote host"""
        return self.execute_command_with_2fa(host_info, command)
    
    def execute_command_with_2fa(self, host_info, command, otp_code=None):
        """Execute command with optional 2FA"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Prepare connection
            hostname = host_info['hostname']
            port = host_info.get('port', self.settings.get('default_port', 22))
            username = host_info.get('username', self.settings.get('default_username', 'root'))
            
            # Authentication
            auth_type = host_info.get('auth_type', 'key')
            password = None
            key_filename = None
            
            if auth_type == 'password':
                password = host_info.get('password', '')
            else:
                key_file = host_info.get('key_file', '')
                if key_file:
                    key_path = os.path.expanduser(key_file)
                    if os.path.exists(key_path):
                        key_filename = key_path
            
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=self.settings.get('timeout', 10)
            )
            
            # Execute command
            stdin, stdout, stderr = client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            return {
                'success': exit_code == 0,
                'exit_code': exit_code,
                'output': output,
                'error': error,
                'command': command
            }
            
        except Exception as e:
            return {
                'success': False,
                'exit_code': -1,
                'output': '',
                'error': str(e),
                'command': command
            }
        finally:
            try:
                client.close()
            except:
                pass
    
    def get_system_info(self, host_info):
        """Get comprehensive system information from host"""
        commands = [
            ("System Uptime", "uptime"),
            ("Current User", "whoami"),
            ("Date/Time", "date"),
            ("Kernel Version", "uname -r"),
            ("CPU Info", "lscpu 2>/dev/null || echo 'Not available'"),
            ("Memory Info", "free -h 2>/dev/null || echo 'Not available'"),
            ("Disk Usage", "df -h 2>/dev/null || echo 'Not available'"),
        ]
        
        results = []
        for name, cmd in commands:
            result = self.execute_command(host_info, cmd)
            results.append({
                'check': name,
                'command': cmd,
                'output': result['output'][:500],
                'success': result['success']
            })
        
        return results
    
    def run_security_scan(self, host_info):
        """Run basic security checks on host"""
        security_checks = [
            ("SSH Service Status", "systemctl status sshd 2>/dev/null || echo 'SSH service check not available'"),
            ("Firewall Status", "sudo ufw status 2>/dev/null || echo 'Firewall check not available'"),
            ("Open Ports", "ss -tuln 2>/dev/null || echo 'Port check not available'"),
            ("Failed Logins", "sudo lastb 2>/dev/null || echo 'Failed login check not available'"),
        ]
        
        results = []
        for name, cmd in security_checks:
            result = self.execute_command(host_info, cmd)
            results.append({
                'check': name,
                'command': cmd,
                'output': result['output'][:500],
                'success': result['success'],
                'status': 'PASS' if result['success'] else 'FAIL'
            })
        
        return results
    
    def upload_file(self, host_info, local_path, remote_path):
        """Upload file to remote host"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connection setup
            hostname = host_info['hostname']
            port = host_info.get('port', self.settings.get('default_port', 22))
            username = host_info.get('username', self.settings.get('default_username', 'root'))
            
            auth_type = host_info.get('auth_type', 'key')
            password = None
            key_filename = None
            
            if auth_type == 'password':
                password = host_info.get('password', '')
            else:
                key_file = host_info.get('key_file', '')
                if key_file:
                    key_path = os.path.expanduser(key_file)
                    if os.path.exists(key_path):
                        key_filename = key_path
            
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=self.settings.get('timeout', 10)
            )
            
            # SFTP transfer
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            
            return {'success': True, 'message': f'File uploaded to {remote_path}'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            try:
                client.close()
            except:
                pass
    
    def download_file(self, host_info, remote_path, local_path):
        """Download file from remote host"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connection setup (same as upload)
            hostname = host_info['hostname']
            port = host_info.get('port', self.settings.get('default_port', 22))
            username = host_info.get('username', self.settings.get('default_username', 'root'))
            
            auth_type = host_info.get('auth_type', 'key')
            password = None
            key_filename = None
            
            if auth_type == 'password':
                password = host_info.get('password', '')
            else:
                key_file = host_info.get('key_file', '')
                if key_file:
                    key_path = os.path.expanduser(key_file)
                    if os.path.exists(key_path):
                        key_filename = key_path
            
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=self.settings.get('timeout', 10)
            )
            
            # SFTP transfer
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            
            return {'success': True, 'message': f'File downloaded to {local_path}'}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
        finally:
            try:
                client.close()
            except:
                pass
    
    def export_results(self, results, format='json'):
        """Export scan results to file"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'json':
            filename = f"{RESULTS_DIR}/ssh_scan_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            return filename
        
        elif format == 'csv':
            filename = f"{RESULTS_DIR}/ssh_scan_{timestamp}.csv"
            
            rows = []
            for hostname, data in results.items():
                if data.get('connection') == 'success':
                    for check in data.get('system_info', []):
                        rows.append([
                            hostname,
                            'system_info',
                            check['check'],
                            check['output'],
                            'PASS' if check['success'] else 'FAIL',
                            data.get('timestamp', '')
                        ])
                else:
                    rows.append([
                        hostname,
                        'connection',
                        'Connection Test',
                        data.get('error', 'Unknown error'),
                        'FAIL',
                        data.get('timestamp', '')
                    ])
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Hostname', 'Category', 'Check', 'Output', 'Status', 'Timestamp'])
                writer.writerows(rows)
            
            return filename
        
        elif format == 'txt':
            filename = f"{RESULTS_DIR}/ssh_scan_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write(f"SSH Scan Report - {timestamp}\n")
                f.write("="*60 + "\n\n")
                
                for hostname, data in results.items():
                    f.write(f"HOST: {hostname}\n")
                    f.write("-"*40 + "\n")
                    
                    if data.get('connection') == 'success':
                        f.write(f"Status: CONNECTED\n")
                        f.write(f"Timestamp: {data.get('timestamp')}\n\n")
                    else:
                        f.write(f"Status: FAILED\n")
                        f.write(f"Error: {data.get('error', 'Unknown error')}\n")
                    
                    f.write("\n" + "="*60 + "\n\n")
            
            return filename

class SSHManagerGUI:
    """GUI for SSH Manager"""
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Manager - Multi-Computer Connection Tool")
        self.root.geometry("1200x700")
        self.root.configure(bg=BG_COLOR)
        
        self.manager = SSHManager()
        self.current_otp_codes = {}
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI interface"""
        # Header
        header = tk.Frame(self.root, bg=HEADER_COLOR, height=80)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="🔗 SSH MANAGER", fg="white", bg=HEADER_COLOR,
                font=("Segoe UI", 20, "bold")).pack(side=tk.LEFT, padx=20, pady=20)
        
        tk.Label(header, text="Connect to Multiple Computers", fg="white", bg=HEADER_COLOR,
                font=("Segoe UI", 12)).pack(side=tk.LEFT, padx=10, pady=20)
        
        # Main container
        main_container = tk.Frame(self.root, bg=BG_COLOR)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel - Hosts
        left_panel = tk.Frame(main_container, bg=SIDEBAR_COLOR, width=300, relief=tk.RAISED, borderwidth=2)
        left_panel.pack(side=tk.LEFT, fill=tk.Y)
        left_panel.pack_propagate(False)
        
        tk.Label(left_panel, text="HOSTS", bg=SIDEBAR_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=20)
        
        # Host buttons frame
        host_buttons = tk.Frame(left_panel, bg=SIDEBAR_COLOR)
        host_buttons.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(host_buttons, text="➕ Add Host", bg=COLOR_SUCCESS, fg="white",
                 font=("Segoe UI", 10, "bold"), width=20, height=2,
                 command=self.add_host).pack(pady=5)
        
        tk.Button(host_buttons, text="🔍 Discover", bg=COLOR_INFO, fg="white",
                 font=("Segoe UI", 10, "bold"), width=20, height=2,
                 command=self.discover_hosts).pack(pady=5)
        
        tk.Button(host_buttons, text="🔄 Reload", bg="#9e9e9e", fg="white",
                 font=("Segoe UI", 10, "bold"), width=20, height=2,
                 command=self.reload_hosts).pack(pady=5)
        
        # Hosts list
        hosts_frame = tk.LabelFrame(left_panel, text=" Configured Hosts ", 
                               font=("Segoe UI", 11, "bold"),
                               bg=SIDEBAR_COLOR, fg=TEXT_COLOR)
        hosts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.hosts_listbox = tk.Listbox(hosts_frame, bg="white", fg=TEXT_COLOR,
                                       font=("Consolas", 10), selectbackground=BUTTON_COLOR)
        self.hosts_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right panel - Actions & Output
        right_panel = tk.Frame(main_container, bg=BG_COLOR)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(20, 0))
        
        # Action buttons
        actions_frame = tk.Frame(right_panel, bg=BG_COLOR)
        actions_frame.pack(fill=tk.X, pady=(0, 10))
        
        action_buttons = [
            ("🔍 Test All", COLOR_INFO, self.test_all),
            ("📊 System Scan", "#673ab7", self.scan_systems),
            ("🛡️ Security Scan", COLOR_WARNING, self.scan_security),
            ("📋 Run Command", "#009688", self.run_custom_command),
            ("📤 Upload File", "#ff5722", self.upload_file),
            ("💾 Export", COLOR_SUCCESS, self.export_results),
        ]
        
        for text, color, command in action_buttons:
            btn = tk.Button(actions_frame, text=text, bg=color, fg="white",
                          font=("Segoe UI", 10, "bold"), height=2,
                          command=command)
            btn.pack(side=tk.LEFT, padx=5)
        
        # Console output
        console_frame = tk.LabelFrame(right_panel, text=" Console Output ", 
                                 font=("Segoe UI", 11, "bold"),
                                 bg=BG_COLOR, fg=TEXT_COLOR)
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.console = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD,
                                               font=("Consolas", 10), bg="#2b2b2b",
                                               fg="white", height=20)
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure console tags
        self.console.tag_config("success", foreground=COLOR_SUCCESS)
        self.console.tag_config("error", foreground=COLOR_ERROR)
        self.console.tag_config("warning", foreground=COLOR_WARNING)
        self.console.tag_config("info", foreground=COLOR_INFO)
        self.console.tag_config("command", foreground="#9c27b0")
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                             bg=SIDEBAR_COLOR, fg=TEXT_COLOR,
                             font=("Segoe UI", 9), relief=tk.SUNKEN, borderwidth=1)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Load initial hosts
        self.reload_hosts()
    
    def log(self, message, level="info"):
        """Log message to console"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.console.see(tk.END)
        self.status_var.set(message)
        self.root.update()
    
    def reload_hosts(self):
        """Reload hosts from config file"""
        self.hosts_listbox.delete(0, tk.END)
        self.manager.load_config()
        
        for host in self.manager.hosts:
            display_text = f"{host['name']} ({host['hostname']})"
            if host.get('enable_2fa'):
                display_text += " 🔒"
            self.hosts_listbox.insert(tk.END, display_text)
        
        self.log(f"Loaded {len(self.manager.hosts)} hosts from config", "info")
    
    def discover_hosts(self):
        """Discover hosts on network"""
        self.log("Starting network discovery...", "info")
        
        def do_discovery():
            discovered = self.manager.discover_network_hosts()
            
            if discovered:
                self.log(f"Discovered {len(discovered)} SSH hosts:", "success")
                
                # Show discovered hosts
                for host in discovered:
                    self.log(f"  • {host['ip']}:{host['port']} - {host['banner']}", "info")
                
                # Ask to add to config
                self.root.after(0, lambda: self.ask_to_add_discovered(discovered))
            else:
                self.log("No SSH hosts discovered", "warning")
        
        threading.Thread(target=do_discovery, daemon=True).start()
    
    def ask_to_add_discovered(self, discovered_hosts):
        """Ask user to add discovered hosts to config"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Discovered Hosts")
        dialog.geometry("600x400")
        dialog.configure(bg=BG_COLOR)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Discovered SSH Hosts", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=20)
        
        # List of discovered hosts
        list_frame = tk.Frame(dialog, bg=BG_COLOR)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        hosts_list = tk.Listbox(list_frame, selectmode=tk.MULTIPLE, yscrollcommand=scrollbar.set)
        hosts_list.pack(fill=tk.BOTH, expand=True)
        
        for host in discovered_hosts:
            hosts_list.insert(tk.END, f"{host['ip']}:{host['port']} - {host['banner'][:50]}")
        
        scrollbar.config(command=hosts_list.yview)
        
        # Buttons
        buttons_frame = tk.Frame(dialog, bg=BG_COLOR)
        buttons_frame.pack(pady=20)
        
        def add_selected():
            selected_indices = hosts_list.curselection()
            if not selected_indices:
                messagebox.showwarning("Warning", "Please select hosts to add")
                return
            
            for idx in selected_indices:
                host = discovered_hosts[idx]
                
                # Create host entry
                new_host = {
                    'name': f"discovered-{host['ip']}",
                    'hostname': host['ip'],
                    'port': host['port'],
                    'username': 'root',  # Default
                    'auth_type': 'key',
                    'key_file': '~/.ssh/id_rsa',
                    'password': '',
                    'tags': ['discovered'],
                    'enable_2fa': False
                }
                
                self.manager.hosts.append(new_host)
            
            # Save config
            self.manager.save_config()
            self.reload_hosts()
            
            self.log(f"Added {len(selected_indices)} discovered hosts", "success")
            dialog.destroy()
        
        tk.Button(buttons_frame, text="Add Selected", bg=COLOR_SUCCESS, fg="white",
                 width=15, command=add_selected).pack(side=tk.LEFT, padx=5)
        
        tk.Button(buttons_frame, text="Cancel", bg="#9e9e9e", fg="white",
                 width=15, command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def add_host(self):
        """Add a new host via dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add SSH Host")
        dialog.geometry("500x700")
        dialog.configure(bg=BG_COLOR)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        tk.Label(dialog, text="Add New SSH Host", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=20)
        
        # Scrollable form
        canvas = tk.Canvas(dialog, bg=BG_COLOR)
        scrollbar = tk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Field definitions
        fields = [
            ("name", "Display Name:", "ubuntu-server"),
            ("hostname", "Hostname/IP:", "192.168.1.100"),
            ("port", "SSH Port:", "22"),
            ("username", "Username:", "root"),
            ("auth_type", "Auth Type:", "key"),
            ("key_file", "SSH Key File:", "~/.ssh/id_rsa"),
            ("password", "Password:", ""),
            ("enable_2fa", "Enable 2FA:", False),
            ("tags", "Tags (comma-separated):", "linux,server"),
        ]
        
        vars_dict = {}
        row = 0
        
        for field_name, label, default in fields:
            tk.Label(scrollable_frame, text=label, bg=BG_COLOR, fg=TEXT_COLOR,
                    font=("Segoe UI", 10)).grid(row=row, column=0, padx=5, pady=5, sticky="w")
            
            if field_name == "auth_type":
                var = tk.StringVar(value=default)
                vars_dict[field_name] = var
                
                auth_frame = tk.Frame(scrollable_frame, bg=BG_COLOR)
                auth_frame.grid(row=row, column=1, padx=5, pady=5, sticky="w")
                
                tk.Radiobutton(auth_frame, text="SSH Key", variable=var,
                              value="key", bg=BG_COLOR).pack(side=tk.LEFT, padx=5)
                tk.Radiobutton(auth_frame, text="Password", variable=var,
                              value="password", bg=BG_COLOR).pack(side=tk.LEFT, padx=5)
            
            elif field_name == "enable_2fa":
                var = tk.BooleanVar(value=default)
                vars_dict[field_name] = var
                
                tk.Checkbutton(scrollable_frame, variable=var, bg=BG_COLOR).grid(row=row, column=1, padx=5, pady=5, sticky="w")
            
            elif field_name == "password":
                var = tk.StringVar(value=default)
                vars_dict[field_name] = var
                entry = tk.Entry(scrollable_frame, textvariable=var, width=30, show="*")
                entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")
            else:
                var = tk.StringVar(value=default)
                vars_dict[field_name] = var
                entry = tk.Entry(scrollable_frame, textvariable=var, width=30)
                entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")
            
            row += 1
        
        # Setup 2FA button
        def setup_2fa():
            hostname = vars_dict['hostname'].get()
            username = vars_dict['username'].get()
            
            if not hostname or not username:
                messagebox.showerror("Error", "Please enter hostname and username first")
                return
            
            secret, uri = self.manager.twofa.generate_secret(hostname, username)
            
            # Show QR code dialog
            qr_dialog = tk.Toplevel(dialog)
            qr_dialog.title("Setup 2FA")
            qr_dialog.geometry("400x500")
            qr_dialog.configure(bg=BG_COLOR)
            qr_dialog.transient(dialog)
            
            tk.Label(qr_dialog, text="Scan QR Code with Google Authenticator", 
                    bg=BG_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 12, "bold")).pack(pady=20)
            
            # Generate QR code
            qr = qrcode.make(uri)
            qr_image = ImageTk.PhotoImage(qr)
            
            qr_label = tk.Label(qr_dialog, image=qr_image, bg=BG_COLOR)
            qr_label.image = qr_image
            qr_label.pack(pady=10)
            
            tk.Label(qr_dialog, text="Or enter this code manually:", 
                    bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=10)
            
            code_label = tk.Label(qr_dialog, text=secret, font=("Consolas", 12), 
                                bg="white", relief=tk.SUNKEN, padx=10, pady=5)
            code_label.pack(pady=10)
            
            tk.Label(qr_dialog, text="Save this secret key securely!", 
                    bg=BG_COLOR, fg=COLOR_WARNING).pack(pady=10)
            
            tk.Button(qr_dialog, text="Done", bg=COLOR_SUCCESS, fg="white",
                     command=qr_dialog.destroy).pack(pady=20)
            
            self.log(f"2FA secret generated for {username}@{hostname}", "success")
        
        tk.Button(scrollable_frame, text="Setup 2FA", bg=COLOR_WARNING, fg="white",
                 command=setup_2fa).grid(row=row, column=1, padx=5, pady=20, sticky="w")
        row += 1
        
        canvas.pack(side="left", fill="both", expand=True, padx=20)
        scrollbar.pack(side="right", fill="y")
        
        # Test and Save buttons
        buttons_frame = tk.Frame(dialog, bg=BG_COLOR)
        buttons_frame.pack(pady=20)
        
        def test_host():
            """Test the host connection"""
            host_info = {
                'name': vars_dict['name'].get(),
                'hostname': vars_dict['hostname'].get(),
                'port': int(vars_dict['port'].get() or 22),
                'username': vars_dict['username'].get(),
                'auth_type': vars_dict['auth_type'].get(),
                'key_file': vars_dict['key_file'].get(),
                'password': vars_dict['password'].get() if vars_dict['auth_type'].get() == 'password' else '',
                'enable_2fa': vars_dict['enable_2fa'].get(),
                'tags': [t.strip() for t in vars_dict['tags'].get().split(',') if t.strip()]
            }
            
            # If 2FA is enabled, ask for OTP
            otp_code = None
            if host_info['enable_2fa']:
                otp_code = simpledialog.askstring("2FA Code", "Enter 6-digit OTP code:")
                if not otp_code:
                    return
            
            self.log(f"Testing connection to {host_info['hostname']}...", "info")
            result = self.manager.test_connection_with_2fa(host_info, otp_code)
            
            if result['status'] == 'success':
                self.log(f"✓ Connection successful! OS: {result.get('os_info', 'Unknown')}", "success")
                if host_info['enable_2fa']:
                    self.log(f"✓ 2FA verification passed", "success")
                tk.messagebox.showinfo("Test Successful", 
                                  f"Successfully connected to {host_info['hostname']}!\n\n"
                                  f"OS: {result.get('os_info', 'Unknown')}")
            else:
                self.log(f"✗ Connection failed: {result.get('message')}", "error")
                tk.messagebox.showerror("Test Failed", 
                                   f"Failed to connect to {host_info['hostname']}:\n\n"
                                   f"Error: {result.get('message', 'Unknown error')}")
        
        def save_host():
            """Save the host to config"""
            host_info = {
                'name': vars_dict['name'].get(),
                'hostname': vars_dict['hostname'].get(),
                'port': int(vars_dict['port'].get() or 22),
                'username': vars_dict['username'].get(),
                'auth_type': vars_dict['auth_type'].get(),
                'key_file': vars_dict['key_file'].get(),
                'password': vars_dict['password'].get() if vars_dict['auth_type'].get() == 'password' else '',
                'enable_2fa': vars_dict['enable_2fa'].get(),
                'tags': [t.strip() for t in vars_dict['tags'].get().split(',') if t.strip()]
            }
            
            # Add to hosts list
            self.manager.hosts.append(host_info)
            
            # Save to config file
            if self.manager.save_config(self.manager.hosts):
                self.log(f"Host '{host_info['name']}' saved successfully", "success")
                dialog.destroy()
                self.reload_hosts()
            else:
                self.log(f"Failed to save host", "error")
        
        tk.Button(buttons_frame, text="Test Connection", bg=COLOR_INFO, fg="white",
                 width=15, command=test_host).pack(side=tk.LEFT, padx=5)
        
        tk.Button(buttons_frame, text="Save Host", bg=COLOR_SUCCESS, fg="white",
                 width=15, command=save_host).pack(side=tk.LEFT, padx=5)
        
        tk.Button(buttons_frame, text="Cancel", bg="#9e9e9e", fg="white",
                 width=15, command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def test_all(self):
        """Test connection to all hosts"""
        self.log("Testing connections to all hosts...", "info")
        
        def do_test():
            success_count = 0
            fail_count = 0
            
            for host in self.manager.hosts:
                self.log(f"Testing {host['hostname']}...", "info")
                
                # If 2FA is enabled, get current OTP
                otp_code = None
                if host.get('enable_2fa'):
                    otp_code = self.manager.twofa.get_current_otp(host['hostname'], host['username'])
                    if otp_code:
                        self.log(f"  Using 2FA code: {otp_code}", "info")
                
                result = self.manager.test_connection_with_2fa(host, otp_code)
                
                if result['status'] == 'success':
                    self.log(f"✓ {host['hostname']} - Connected", "success")
                    if host.get('enable_2fa'):
                        self.log(f"  ✓ 2FA verified", "success")
                    success_count += 1
                else:
                    self.log(f"✗ {host['hostname']} - Failed: {result.get('message', 'Unknown')}", "error")
                    fail_count += 1
            
            self.log(f"Connection test completed: {success_count} successful, {fail_count} failed", "info")
            
            # Show summary
            self.root.after(0, lambda: tk.messagebox.showinfo(
                "Connection Test Complete",
                f"Tested {len(self.manager.hosts)} hosts:\n\n"
                f"✓ Successful: {success_count}\n"
                f"✗ Failed: {fail_count}"
            ))
        
        threading.Thread(target=do_test, daemon=True).start()
    
    def scan_systems(self):
        """Scan system information from all hosts"""
        self.log("Starting system information scan...", "info")
        
        def do_scan():
            all_results = {}
            
            for host in self.manager.hosts:
                hostname = host['hostname']
                self.log(f"Scanning {hostname}...", "info")
                
                # Test connection
                otp_code = None
                if host.get('enable_2fa'):
                    otp_code = self.manager.twofa.get_current_otp(host['hostname'], host['username'])
                
                connection_test = self.manager.test_connection_with_2fa(host, otp_code)
                
                if connection_test['status'] == 'success':
                    # Get system info
                    system_info = self.manager.get_system_info(host)
                    
                    all_results[hostname] = {
                        'connection': 'success',
                        'os_info': connection_test.get('os_info', 'Unknown'),
                        'system_info': system_info,
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    self.log(f"✓ {hostname} - System scan completed", "success")
                    
                    # Show some key info
                    if system_info:
                        for check in system_info[:3]:
                            self.log(f"  • {check['check']}: {check['output'][:50]}...", "info")
                else:
                    all_results[hostname] = {
                        'connection': 'failed',
                        'error': connection_test.get('message', 'Unknown error'),
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    self.log(f"✗ {hostname} - Scan failed: {connection_test.get('message', 'Unknown')}", "error")
            
            self.log("System scan completed for all hosts", "info")
            
            # Save results
            filename = self.manager.export_results(all_results, 'json')
            self.log(f"Results saved to: {filename}", "success")
            
            self.root.after(0, lambda: tk.messagebox.showinfo(
                "Scan Complete",
                f"System scan completed!\n\n"
                f"Results saved to:\n{filename}"
            ))
        
        threading.Thread(target=do_scan, daemon=True).start()
    
    def scan_security(self):
        """Run security scan on all hosts"""
        self.log("Starting security scan...", "info")
        
        def do_security_scan():
            all_results = {}
            
            for host in self.manager.hosts:
                hostname = host['hostname']
                self.log(f"Scanning {hostname} for security issues...", "info")
                
                # Test connection
                otp_code = None
                if host.get('enable_2fa'):
                    otp_code = self.manager.twofa.get_current_otp(host['hostname'], host['username'])
                
                connection_test = self.manager.test_connection_with_2fa(host, otp_code)
                
                if connection_test['status'] == 'success':
                    # Run security scan
                    security_results = self.manager.run_security_scan(host)
                    
                    # Count results
                    pass_count = sum(1 for r in security_results if r.get('status') == 'PASS')
                    fail_count = sum(1 for r in security_results if r.get('status') == 'FAIL')
                    
                    self.log(f"✓ {hostname} - Security scan: {pass_count} passed, {fail_count} failed", 
                           "success" if fail_count == 0 else "warning")
                    
                    all_results[hostname] = {
                        'connection': 'success',
                        'security_scan': security_results,
                        'summary': f"{pass_count} passed, {fail_count} failed",
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                else:
                    self.log(f"✗ {hostname} - Connection failed", "error")
                    all_results[hostname] = {
                        'connection': 'failed',
                        'error': connection_test.get('message', 'Unknown error'),
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
            
            self.log("Security scan completed", "info")
            
            # Export results
            filename = self.manager.export_results(all_results, 'txt')
            self.log(f"Security report saved to: {filename}", "success")
            
            self.root.after(0, lambda: tk.messagebox.showinfo(
                "Security Scan Complete",
                f"Security scan completed!\n\n"
                f"Report saved to:\n{filename}"
            ))
        
        threading.Thread(target=do_security_scan, daemon=True).start()
    
    def run_custom_command(self):
        """Run custom command on selected or all hosts"""
        # Get command from user
        command_dialog = tk.Toplevel(self.root)
        command_dialog.title("Run Custom Command")
        command_dialog.geometry("600x400")
        command_dialog.configure(bg=BG_COLOR)
        command_dialog.transient(self.root)
        command_dialog.grab_set()
        
        tk.Label(command_dialog, text="Run Custom SSH Command", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=20)
        
        # Command entry
        tk.Label(command_dialog, text="Command to execute:", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 10)).pack(anchor="w", padx=20)
        
        command_text = scrolledtext.ScrolledText(command_dialog, wrap=tk.WORD,
                                               font=("Consolas", 10), height=5)
        command_text.pack(fill=tk.X, padx=20, pady=10)
        command_text.insert("1.0", "uptime")
        
        # Target selection
        target_frame = tk.Frame(command_dialog, bg=BG_COLOR)
        target_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(target_frame, text="Run on:", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 10)).pack(side=tk.LEFT)
        
        target_var = tk.StringVar(value="all")
        tk.Radiobutton(target_frame, text="All Hosts", variable=target_var,
                      value="all", bg=BG_COLOR).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(target_frame, text="Selected Host", variable=target_var,
                      value="selected", bg=BG_COLOR).pack(side=tk.LEFT, padx=10)
        
        # Buttons
        buttons_frame = tk.Frame(command_dialog, bg=BG_COLOR)
        buttons_frame.pack(pady=20)
        
        def execute_command():
            command = command_text.get("1.0", tk.END).strip()
            if not command:
                messagebox.showerror("Error", "Please enter a command")
                return
            
            command_dialog.destroy()
            self._execute_custom_command_impl(command, target_var.get())
        
        def preview_command():
            command = command_text.get("1.0", tk.END).strip()
            target = target_var.get()
            
            if target == "all":
                target_text = "all hosts"
            else:
                selection = self.hosts_listbox.curselection()
                if not selection:
                    target_text = "all hosts (no selection)"
                else:
                    index = selection[0]
                    host = self.manager.hosts[index]
                    target_text = f"host: {host['name']} ({host['hostname']})"
            
            messagebox.showinfo("Command Preview", 
                              f"Command: {command}\n\n"
                              f"Will execute on: {target_text}")
        
        tk.Button(buttons_frame, text="Preview", bg=COLOR_INFO, fg="white",
                 width=12, command=preview_command).pack(side=tk.LEFT, padx=5)
        
        tk.Button(buttons_frame, text="Execute", bg=COLOR_SUCCESS, fg="white",
                 width=12, command=execute_command).pack(side=tk.LEFT, padx=5)
        
        tk.Button(buttons_frame, text="Cancel", bg="#9e9e9e", fg="white",
                 width=12, command=command_dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _execute_custom_command_impl(self, command, target):
        """Execute custom command implementation"""
        self.log(f"Executing command: '{command}'", "command")
        
        if target == "selected":
            selection = self.hosts_listbox.curselection()
            if not selection:
                self.log("No host selected, running on all hosts", "warning")
                hosts_to_run = self.manager.hosts
            else:
                index = selection[0]
                hosts_to_run = [self.manager.hosts[index]]
        else:
            hosts_to_run = self.manager.hosts
        
        def do_execute():
            results = {}
            
            for host in hosts_to_run:
                self.log(f"Running command on {host['hostname']}...", "info")
                
                try:
                    result = self.manager.execute_command(host, command)
                    
                    if result['success']:
                        self.log(f"✓ {host['hostname']} - Command executed successfully", "success")
                        if result['output'].strip():
                            output_preview = result['output'][:100] + ("..." if len(result['output']) > 100 else "")
                            self.log(f"  Output: {output_preview}", "info")
                    else:
                        self.log(f"✗ {host['hostname']} - Command failed (exit code: {result['exit_code']})", "error")
                        if result['error'].strip():
                            error_preview = result['error'][:100] + ("..." if len(result['error']) > 100 else "")
                            self.log(f"  Error: {error_preview}", "error")
                    
                    results[host['hostname']] = result
                    
                except Exception as e:
                    self.log(f"✗ {host['hostname']} - Error: {str(e)}", "error")
                    results[host['hostname']] = {'error': str(e)}
            
            # Show summary
            success_count = sum(1 for r in results.values() if isinstance(r, dict) and r.get('success', False))
            fail_count = len(results) - success_count
            
            self.log(f"Command execution completed: {success_count} successful, {fail_count} failed", "info")
            
            # Export results if multiple hosts
            if len(hosts_to_run) > 1:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{RESULTS_DIR}/command_results_{timestamp}.txt"
                
                with open(filename, 'w') as f:
                    f.write(f"Command Execution Report - {timestamp}\n")
                    f.write(f"Command: {command}\n")
                    f.write("="*60 + "\n\n")
                    
                    for hostname, result in results.items():
                        f.write(f"Host: {hostname}\n")
                        f.write("-"*40 + "\n")
                        
                        if isinstance(result, dict):
                            if result.get('success'):
                                f.write("Status: SUCCESS\n")
                                f.write(f"Exit Code: {result.get('exit_code', 0)}\n\n")
                                f.write("Output:\n")
                                f.write(result.get('output', '') + "\n")
                            else:
                                f.write("Status: FAILED\n")
                                f.write(f"Exit Code: {result.get('exit_code', -1)}\n\n")
                                f.write("Error:\n")
                                f.write(result.get('error', 'Unknown error') + "\n")
                        else:
                            f.write("Status: ERROR\n")
                            f.write(f"Error: {result}\n")
                        
                        f.write("\n" + "="*60 + "\n\n")
                
                self.log(f"Full results saved to: {filename}", "success")
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "Execution Complete",
                    f"Command execution completed!\n\n"
                    f"Successful: {success_count}\n"
                    f"Failed: {fail_count}\n\n"
                    f"Results saved to:\n{filename}"
                ))
            else:
                self.root.after(0, lambda: messagebox.showinfo(
                    "Execution Complete",
                    f"Command execution {'succeeded' if success_count > 0 else 'failed'}!"
                ))
        
        threading.Thread(target=do_execute, daemon=True).start()
    
    def upload_file(self):
        """Upload file to remote host"""
        # Select local file
        local_path = filedialog.askopenfilename(title="Select file to upload")
        if not local_path:
            return
        
        # Select target host
        selection = self.hosts_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a host")
            return
        
        index = selection[0]
        host = self.manager.hosts[index]
        
        # Ask for remote path
        remote_path = simpledialog.askstring("Remote Path", 
                                           f"Enter remote path for {os.path.basename(local_path)}:",
                                           initialvalue=f"/tmp/{os.path.basename(local_path)}")
        if not remote_path:
            return
        
        self.log(f"Uploading {local_path} to {host['hostname']}:{remote_path}...", "info")
        
        def do_upload():
            result = self.manager.upload_file(host, local_path, remote_path)
            
            if result['success']:
                self.log(f"✓ File uploaded successfully", "success")
                self.root.after(0, lambda: messagebox.showinfo(
                    "Upload Complete",
                    f"File uploaded to {host['hostname']}:\n{remote_path}"
                ))
            else:
                self.log(f"✗ Upload failed: {result['message']}", "error")
                self.root.after(0, lambda: messagebox.showerror(
                    "Upload Failed",
                    f"Failed to upload file:\n{result['message']}"
                ))
        
        threading.Thread(target=do_upload, daemon=True).start()
    
    def export_results(self):
        """Export results in various formats"""
        export_dialog = tk.Toplevel(self.root)
        export_dialog.title("Export Results")
        export_dialog.geometry("400x300")
        export_dialog.configure(bg=BG_COLOR)
        export_dialog.transient(self.root)
        export_dialog.grab_set()
        
        tk.Label(export_dialog, text="Export Results", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=20)
        
        # Format selection
        tk.Label(export_dialog, text="Select format:", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 10)).pack(anchor="w", padx=20)
        
        format_var = tk.StringVar(value="json")
        formats = [
            ("JSON (.json) - Structured data", "json"),
            ("CSV (.csv) - Spreadsheet format", "csv"),
            ("Text (.txt) - Readable report", "txt"),
        ]
        
        for text, value in formats:
            tk.Radiobutton(export_dialog, text=text, variable=format_var,
                          value=value, bg=BG_COLOR).pack(anchor="w", padx=20, pady=5)
        
        # Buttons
        buttons_frame = tk.Frame(export_dialog, bg=BG_COLOR)
        buttons_frame.pack(pady=20)
        
        def do_export():
            format_type = format_var.get()
            export_dialog.destroy()
            
            # Run scan and export
            self.log(f"Running scan for export ({format_type})...", "info")
            
            def scan_and_export():
                all_results = {}
                
                for host in self.manager.hosts:
                    hostname = host['hostname']
                    
                    # Test connection
                    otp_code = None
                    if host.get('enable_2fa'):
                        otp_code = self.manager.twofa.get_current_otp(host['hostname'], host['username'])
                    
                    connection_test = self.manager.test_connection_with_2fa(host, otp_code)
                    
                    if connection_test['status'] == 'success':
                        system_info = self.manager.get_system_info(host)
                        all_results[hostname] = {
                            'connection': 'success',
                            'os_info': connection_test.get('os_info', 'Unknown'),
                            'system_info': system_info,
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                    else:
                        all_results[hostname] = {
                            'connection': 'failed',
                            'error': connection_test.get('message', 'Unknown error'),
                            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                
                filename = self.manager.export_results(all_results, format_type)
                self.log(f"Results exported to: {filename}", "success")
                
                self.root.after(0, lambda: messagebox.showinfo(
                    "Export Complete",
                    f"Results exported successfully!\n\n"
                    f"File: {filename}"
                ))
            
            threading.Thread(target=scan_and_export, daemon=True).start()
        
        tk.Button(buttons_frame, text="Export", bg=COLOR_SUCCESS, fg="white",
                 width=12, command=do_export).pack(side=tk.LEFT, padx=5)
        
        tk.Button(buttons_frame, text="Cancel", bg="#9e9e9e", fg="white",
                 width=12, command=export_dialog.destroy).pack(side=tk.LEFT, padx=5)

def main():
    """Main entry point"""
    try:
        # Check dependencies
        import paramiko
        import yaml
        import netifaces
        import qrcode
        import pyotp
        from PIL import Image, ImageTk
    except ImportError as e:
        print(f"Error: Missing dependency - {e}")
        print("Please install required packages:")
        print("  pip install paramiko pyyaml netifaces qrcode[pil] pyotp pillow")
        sys.exit(1)
    
    # Create GUI
    root = tk.Tk()
    app = SSHManagerGUI(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Start main loop
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nExiting SSH Manager...")
        sys.exit(0)

if __name__ == "__main__":
    main()
