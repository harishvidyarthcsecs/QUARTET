#!/usr/bin/env python3
"""
SSH MANAGER - Multi-Computer Connection Tool
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
from pathlib import Path

# ==================== CONFIGURATION ====================
CONFIG_FILE = "ssh_hosts.yaml"
RESULTS_DIR = "ssh_results"
LOG_FILE = "ssh_manager.log"

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

class SSHManager:
    """Main SSH manager class"""
    def __init__(self):
        self.hosts = []
        self.settings = {}
        self.results = {}
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
                        'tags': ['linux', 'ubuntu', 'server']
                    },
                    {
                        'name': 'windows-pc',
                        'hostname': '192.168.1.200',
                        'port': 22,
                        'username': 'Administrator',
                        'auth_type': 'password',
                        'key_file': '',
                        'password': 'YourPassword123',
                        'tags': ['windows', 'desktop']
                    }
                ],
                'settings': {
                    'timeout': 10,
                    'banner_timeout': 30,
                    'default_port': 22,
                    'default_username': 'root'
                }
            }
            
            with open(config_path, 'w') as f:
                yaml.dump(sample_config, f, default_flow_style=False)
            
            print(f"[INFO] Sample config created at {config_path}")
            print("[INFO] Please edit with your actual hosts")
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
    
    def test_connection(self, host_info):
        """Test SSH connection to a single host"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Prepare connection parameters
            hostname = host_info['hostname']
            port = host_info.get('port', self.settings.get('default_port', 22))
            username = host_info.get('username', self.settings.get('default_username', 'root'))
            timeout = self.settings.get('timeout', 10)
            
            print(f"[DEBUG] Connecting to {hostname}:{port} as {username}")
            
            # Handle authentication
            auth_type = host_info.get('auth_type', 'key')
            password = None
            key_filename = None
            
            if auth_type == 'password':
                password = host_info.get('password', '')
                print(f"[DEBUG] Using password authentication")
            else:
                key_file = host_info.get('key_file', '')
                if key_file:
                    key_path = os.path.expanduser(key_file)
                    if os.path.exists(key_path):
                        key_filename = key_path
                        print(f"[DEBUG] Using key file: {key_path}")
                    else:
                        print(f"[DEBUG] Key file not found: {key_path}")
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
                                print(f"[DEBUG] Using default key: {key_path}")
                                break
            
            # Connect
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=timeout,
                banner_timeout=self.settings.get('banner_timeout', 30)
            )
            
            print(f"[DEBUG] Connected successfully to {hostname}")
            
            # Get system info
            stdin, stdout, stderr = client.exec_command('uname -a 2>/dev/null || echo "Unknown OS"')
            os_info = stdout.read().decode().strip()
            
            # Try to get more details
            stdin, stdout, stderr = client.exec_command('cat /etc/os-release 2>/dev/null || systeminfo 2>/dev/null || echo "No detailed info"')
            os_details = stdout.read().decode().strip()[:200]
            
            return {
                'status': 'success',
                'os_info': os_info,
                'os_details': os_details,
                'hostname': hostname
            }
            
        except paramiko.ssh_exception.AuthenticationException as e:
            print(f"[DEBUG] Authentication failed: {e}")
            return {'status': 'error', 'message': 'Authentication failed'}
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(f"[DEBUG] No valid connections: {e}")
            return {'status': 'error', 'message': f'Cannot connect to host (port {port} might be closed)'}
        except socket.timeout as e:
            print(f"[DEBUG] Connection timeout: {e}")
            return {'status': 'error', 'message': 'Connection timeout'}
        except Exception as e:
            print(f"[DEBUG] Connection error: {type(e).__name__}: {e}")
            return {'status': 'error', 'message': str(e)}
        finally:
            try:
                client.close()
            except:
                pass
    
    def execute_command(self, host_info, command):
        """Execute a command on remote host"""
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
            print(f"[DEBUG] Executing command on {hostname}: {command}")
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
            print(f"[DEBUG] Command execution error on {host_info.get('hostname', 'unknown')}: {e}")
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
            ("CPU Info", "lscpu 2>/dev/null || wmic cpu get name 2>/dev/null || echo 'Not available'"),
            ("Memory Info", "free -h 2>/dev/null || wmic ComputerSystem get TotalPhysicalMemory 2>/dev/null || echo 'Not available'"),
            ("Disk Usage", "df -h 2>/dev/null || wmic logicaldisk get size,freespace,caption 2>/dev/null || echo 'Not available'"),
            ("Logged in Users", "who 2>/dev/null || query user 2>/dev/null || echo 'Not available'"),
            ("Network Interfaces", "ip addr show 2>/dev/null || ipconfig /all 2>/dev/null || ifconfig 2>/dev/null || echo 'Not available'"),
            ("Running Processes", "ps aux | wc -l 2>/dev/null || tasklist | find /c /v \"\" 2>/dev/null || echo 'Not available'"),
        ]
        
        results = []
        for name, cmd in commands:
            result = self.execute_command(host_info, cmd)
            results.append({
                'check': name,
                'command': cmd,
                'output': result['output'][:500],  # Limit output length
                'success': result['success']
            })
        
        return results
    
    def run_security_scan(self, host_info):
        """Run basic security checks on host"""
        # Basic security checks (safe commands)
        security_checks = [
            ("SSH Service Status", "systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null || service sshd status 2>/dev/null || echo 'SSH service check not available'"),
            ("Firewall Status", "sudo ufw status 2>/dev/null || sudo firewall-cmd --state 2>/dev/null || netsh advfirewall show allprofiles 2>/dev/null || echo 'Firewall check not available'"),
            ("Open Ports", "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo 'Port check not available'"),
            ("Failed Logins", "sudo lastb 2>/dev/null || echo 'Failed login check not available'"),
            ("System Updates", "apt list --upgradable 2>/dev/null || yum check-update 2>/dev/null || echo 'Update check not available'"),
            ("SELinux Status", "getenforce 2>/dev/null || echo 'SELinux not installed'"),
            ("Root Login Check", "grep PermitRootLogin /etc/ssh/sshd_config 2>/dev/null || echo 'SSH config not accessible'"),
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
    
    def test_all_connections(self):
        """Test connection to all hosts"""
        results = {}
        for host in self.hosts:
            hostname = host['hostname']
            print(f"[INFO] Testing connection to {hostname}")
            results[hostname] = self.test_connection(host)
        return results
    
    def scan_all_hosts(self):
        """Scan all hosts for system info and security"""
        all_results = {}
        
        for host in self.hosts:
            hostname = host['hostname']
            print(f"[INFO] Scanning {hostname}...")
            
            # Test connection first
            connection_test = self.test_connection(host)
            
            if connection_test['status'] == 'success':
                # Get system info
                system_info = self.get_system_info(host)
                
                # Run security scan
                security_scan = self.run_security_scan(host)
                
                all_results[hostname] = {
                    'connection': 'success',
                    'os_info': connection_test.get('os_info', 'Unknown'),
                    'system_info': system_info,
                    'security_scan': security_scan,
                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                all_results[hostname] = {
                    'connection': 'failed',
                    'error': connection_test.get('message', 'Unknown error'),
                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
        
        return all_results
    
    def export_results(self, results, format='json'):
        """Export scan results to file"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'json':
            filename = f"{RESULTS_DIR}/ssh_scan_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[INFO] Exported JSON to {filename}")
            return filename
        
        elif format == 'csv':
            filename = f"{RESULTS_DIR}/ssh_scan_{timestamp}.csv"
            
            # Flatten results for CSV
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
                            data['timestamp']
                        ])
                    for check in data.get('security_scan', []):
                        rows.append([
                            hostname,
                            'security_scan',
                            check['check'],
                            check['output'],
                            check.get('status', 'UNKNOWN'),
                            data['timestamp']
                        ])
                else:
                    rows.append([
                        hostname,
                        'connection',
                        'Connection Test',
                        data.get('error', 'Unknown error'),
                        'FAIL',
                        data['timestamp']
                    ])
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Hostname', 'Category', 'Check', 'Output', 'Status', 'Timestamp'])
                writer.writerows(rows)
            
            print(f"[INFO] Exported CSV to {filename}")
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
                        f.write(f"OS Info: {data.get('os_info', 'Unknown')}\n")
                        f.write(f"Timestamp: {data.get('timestamp')}\n\n")
                        
                        f.write("System Information:\n")
                        for check in data.get('system_info', []):
                            f.write(f"  • {check['check']}: {check['output'][:100]}...\n")
                        
                        f.write("\nSecurity Checks:\n")
                        for check in data.get('security_scan', []):
                            status = check.get('status', 'UNKNOWN')
                            f.write(f"  • {check['check']}: {status}\n")
                    else:
                        f.write(f"Status: FAILED\n")
                        f.write(f"Error: {data.get('error', 'Unknown error')}\n")
                        f.write(f"Timestamp: {data.get('timestamp')}\n")
                    
                    f.write("\n" + "="*60 + "\n\n")
            
            print(f"[INFO] Exported TXT to {filename}")
            return filename

class SSHManagerGUI:
    """GUI for SSH Manager"""
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Manager - Multi-Computer Connection Tool")
        self.root.geometry("1200x700")
        self.root.configure(bg=BG_COLOR)
        
        self.manager = SSHManager()
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
        
        tk.Button(host_buttons, text="✏️ Edit Config", bg=BUTTON_COLOR, fg="white",
                 font=("Segoe UI", 10, "bold"), width=20, height=2,
                 command=self.edit_config).pack(pady=5)
        
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
            self.hosts_listbox.insert(tk.END, display_text)
        
        self.log(f"Loaded {len(self.manager.hosts)} hosts from config", "info")
    
    def add_host(self):
        """Add a new host via dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add SSH Host")
        dialog.geometry("500x600")
        dialog.configure(bg=BG_COLOR)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        tk.Label(dialog, text="Add New SSH Host", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=20)
        
        form_frame = tk.Frame(dialog, bg=BG_COLOR)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        # Field definitions
        fields = [
            ("name", "Display Name:", "ubuntu-server"),
            ("hostname", "Hostname/IP:", "192.168.1.100"),
            ("port", "SSH Port:", "22"),
            ("username", "Username:", "root"),
            ("auth_type", "Auth Type:", "key"),
            ("key_file", "SSH Key File:", "~/.ssh/id_rsa"),
            ("password", "Password:", ""),
            ("tags", "Tags (comma-separated):", "linux,server"),
        ]
        
        vars_dict = {}
        row = 0
        
        for field_name, label, default in fields:
            tk.Label(form_frame, text=label, bg=BG_COLOR, fg=TEXT_COLOR,
                    font=("Segoe UI", 10)).grid(row=row, column=0, padx=5, pady=5, sticky="w")
            
            var = tk.StringVar(value=default)
            vars_dict[field_name] = var
            
            if field_name == "auth_type":
                # Radio buttons for auth type
                auth_frame = tk.Frame(form_frame, bg=BG_COLOR)
                auth_frame.grid(row=row, column=1, padx=5, pady=5, sticky="w")
                
                tk.Radiobutton(auth_frame, text="SSH Key", variable=var,
                              value="key", bg=BG_COLOR).pack(side=tk.LEFT, padx=5)
                tk.Radiobutton(auth_frame, text="Password", variable=var,
                              value="password", bg=BG_COLOR).pack(side=tk.LEFT, padx=5)
            
            elif field_name == "password":
                entry = tk.Entry(form_frame, textvariable=var, width=30, show="*")
                entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")
            else:
                entry = tk.Entry(form_frame, textvariable=var, width=30)
                entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")
            
            row += 1
        
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
                'tags': [t.strip() for t in vars_dict['tags'].get().split(',') if t.strip()]
            }
            
            self.log(f"Testing connection to {host_info['hostname']}...", "info")
            result = self.manager.test_connection(host_info)
            
            if result['status'] == 'success':
                self.log(f"✓ Connection successful! OS: {result.get('os_info', 'Unknown')}", "success")
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
    
    def edit_config(self):
        """Open config file for editing"""
        config_file = CONFIG_FILE
        
        if not os.path.exists(config_file):
            self.manager.load_config()  # Creates sample config
        
        try:
            if os.name == 'nt':  # Windows
                os.startfile(config_file)
            else:  # Linux/Mac
                editor = os.environ.get('EDITOR', 'nano')
                import subprocess
                subprocess.Popen([editor, config_file])
            
            self.log(f"Opened config file: {config_file}", "info")
        except Exception as e:
            self.log(f"Failed to open config: {str(e)}", "error")
    
    def test_all(self):
        """Test connection to all hosts"""
        self.log("Testing connections to all hosts...", "info")
        
        def do_test():
            results = self.manager.test_all_connections()
            
            success_count = 0
            fail_count = 0
            
            for hostname, result in results.items():
                if result['status'] == 'success':
                    self.log(f"✓ {hostname} - Connected ({result.get('os_info', 'Unknown')})", "success")
                    success_count += 1
                else:
                    self.log(f"✗ {hostname} - Failed: {result.get('message', 'Unknown')}", "error")
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
            results = self.manager.scan_all_hosts()
            
            for hostname, data in results.items():
                if data.get('connection') == 'success':
                    self.log(f"✓ {hostname} - System scan completed", "success")
                    
                    # Show some key info
                    if data.get('system_info'):
                        for check in data['system_info'][:3]:  # Show first 3 checks
                            self.log(f"  • {check['check']}: {check['output'][:50]}...", "info")
                else:
                    self.log(f"✗ {hostname} - Scan failed: {data.get('error', 'Unknown')}", "error")
            
            self.log("System scan completed for all hosts", "info")
            
            # Save results
            filename = self.manager.export_results(results, 'json')
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
                connection_test = self.manager.test_connection(host)
                
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
                        'summary': f"{pass_count} passed, {fail_count} failed"
                    }
                else:
                    self.log(f"✗ {hostname} - Connection failed", "error")
                    all_results[hostname] = {
                        'connection': 'failed',
                        'error': connection_test.get('message', 'Unknown error')
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
                    messagebox.showwarning("Warning", "No host selected. Will run on all hosts.")
                    target_text = "all hosts"
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
        
        # Data selection
        tk.Label(export_dialog, text="Select data:", bg=BG_COLOR, fg=TEXT_COLOR,
                font=("Segoe UI", 10)).pack(anchor="w", padx=20, pady=(10, 0))
        
        data_var = tk.StringVar(value="recent")
        tk.Radiobutton(export_dialog, text="Recent scan results", variable=data_var,
                      value="recent", bg=BG_COLOR).pack(anchor="w", padx=20, pady=2)
        tk.Radiobutton(export_dialog, text="Run new scan now", variable=data_var,
                      value="new", bg=BG_COLOR).pack(anchor="w", padx=20, pady=2)
        
        # Buttons
        buttons_frame = tk.Frame(export_dialog, bg=BG_COLOR)
        buttons_frame.pack(pady=20)
        
        def do_export():
            format_type = format_var.get()
            data_type = data_var.get()
            
            export_dialog.destroy()
            
            if data_type == "new":
                self.log(f"Running new scan for export ({format_type})...", "info")
                
                def scan_and_export():
                    results = self.manager.scan_all_hosts()
                    filename = self.manager.export_results(results, format_type)
                    self.log(f"Results exported to: {filename}", "success")
                    
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Export Complete",
                        f"Results exported successfully!\n\n"
                        f"File: {filename}"
                    ))
                
                threading.Thread(target=scan_and_export, daemon=True).start()
            else:
                # For recent results, we need to have some results first
                messagebox.showwarning("No Recent Data", 
                                    "Please run a scan first to have data to export.")
        
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
    except ImportError as e:
        print(f"Error: Missing dependency - {e}")
        print("Please install required packages:")
        print("  pip install paramiko pyyaml")
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
