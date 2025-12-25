"""
UNIFIED ACCURATE CYBER DEFENSE SUITE
Author: Ian Carter Kulani

"""

import sys
import os
import time
import json
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import threading
import queue
import asyncio
import concurrent.futures

# Core imports
import socket
import subprocess
import requests
import random
import platform
import psutil
import getpass
import hashlib
import sqlite3
import ipaddress
import re
import shutil
import urllib.parse
import secrets

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext, Menu
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("GUI features unavailable - tkinter not installed")

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Configuration
CONFIG_FILE = "accurate_cyber_defense_config.json"
DATABASE_FILE = "cyber_defense_data.db"
REPORT_DIR = "reports"
LOG_DIR = "logs"
CACHE_DIR = "cache"
BACKUP_DIR = "backups"

# Create directories
for directory in [REPORT_DIR, LOG_DIR, CACHE_DIR, BACKUP_DIR]:
    os.makedirs(directory, exist_ok=True)

THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00ff00",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#00ff00",
        "highlight": "#006600",
        "accent": "#00cc00"
    },
    "cyberpunk": {
        "bg": "#0a0a1a",
        "fg": "#ff00ff",
        "text_bg": "#151530",
        "text_fg": "#ffffff",
        "button_bg": "#252550",
        "button_fg": "#00ffff",
        "highlight": "#6600cc",
        "accent": "#ff5500"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "highlight": "#a0a0a0",
        "accent": "#0066cc"
    }
}

class EnhancedLogger:
    """Enhanced logging system with multiple handlers"""
    
    def __init__(self, name="CyberDefense"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_format)
        
        # File handler
        log_file = os.path.join(LOG_DIR, f"cyber_defense_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def info(self, message):
        self.logger.info(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)
    
    def debug(self, message):
        self.logger.debug(message)

class EnhancedTracerouteTool:
    """Enhanced traceroute with advanced features"""
    
    def __init__(self):
        self.logger = EnhancedLogger("Traceroute")
    
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str]:
        """Validate and classify target"""
        try:
            ipaddress.ip_address(target)
            return True, "ipv4" if '.' in target else "ipv6"
        except ValueError:
            # Check if it's a hostname
            if len(target) > 255:
                return False, "invalid"
            if target.endswith('.'):
                target = target[:-1]
            HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
            if HOSTNAME_RE.match(target):
                return True, "hostname"
            return False, "invalid"
    
    def get_traceroute_command(self, target: str, options: Dict[str, Any] = None) -> List[str]:
        """Get appropriate traceroute command with options"""
        system = platform.system()
        default_options = {
            'max_hops': 30,
            'timeout': 2,
            'queries': 1,
            'resolve_names': False
        }
        
        if options:
            default_options.update(options)
        
        if system == 'Windows':
            cmd = ['tracert']
            if not default_options['resolve_names']:
                cmd.append('-d')
            cmd.extend(['-h', str(default_options['max_hops'])])
            cmd.extend(['-w', str(default_options['timeout'] * 1000)])
            cmd.append(target)
        else:
            if shutil.which('traceroute'):
                cmd = ['traceroute']
                cmd.extend(['-m', str(default_options['max_hops'])])
                cmd.extend(['-q', str(default_options['queries'])])
                cmd.extend(['-w', str(default_options['timeout'])])
                if not default_options['resolve_names']:
                    cmd.append('-n')
                cmd.append(target)
            elif shutil.which('tracepath'):
                cmd = ['tracepath', target]
            else:
                cmd = ['ping', '-c', '4', target]
        
        return cmd
    
    def perform_traceroute(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform traceroute and return structured results"""
        valid, target_type = self.validate_target(target)
        if not valid:
            return {"error": f"Invalid target: {target}", "success": False}
        
        cmd = self.get_traceroute_command(target, options)
        self.logger.info(f"Executing: {' '.join(cmd)}")
        
        result = {
            "success": False,
            "target": target,
            "target_type": target_type,
            "command": ' '.join(cmd),
            "hops": [],
            "start_time": datetime.now().isoformat()
        }
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            output_lines = []
            for line in process.stdout:
                line = line.strip()
                output_lines.append(line)
                self.logger.debug(f"Traceroute output: {line}")
                
                # Parse traceroute output
                hop_info = self.parse_traceroute_line(line)
                if hop_info:
                    result["hops"].append(hop_info)
            
            process.wait()
            result["return_code"] = process.returncode
            result["output"] = '\n'.join(output_lines)
            result["success"] = process.returncode == 0
            result["end_time"] = datetime.now().isoformat()
            
        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Traceroute error: {e}")
        
        return result
    
    def parse_traceroute_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a line of traceroute output"""
        patterns = [
            # Windows tracert pattern
            r'\s*(\d+)\s+([\d\.]+)\s+([\dms\<\>]+)\s+([\dms\<\>]+)\s+([\dms\<\>]+)',
            # Linux traceroute pattern
            r'\s*(\d+)\s+([\w\.\-\:]+)\s+\(([\d\.\:]+)\)\s+([\d\.]+)\s+ms',
            # Simple pattern
            r'\s*(\d+)\s+([\w\.\-\:]+)'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                groups = match.groups()
                if len(groups) >= 2:
                    return {
                        "hop": int(groups[0]),
                        "host": groups[1],
                        "ip": groups[2] if len(groups) > 2 else groups[1],
                        "rtt": groups[3] if len(groups) > 3 else "N/A"
                    }
        return None
    
    def interactive_traceroute(self, target: str = None) -> str:
        """Interactive traceroute interface"""
        if not target:
            while True:
                target = input("Enter target (IP/hostname) or 'quit': ").strip()
                if target.lower() in ('q', 'quit', 'exit'):
                    return "Traceroute cancelled."
                
                valid, _ = self.validate_target(target)
                if valid:
                    break
                print(f"Invalid target: {target}. Try again.")
        
        print(f"\n🚀 Starting traceroute to {target}...\n")
        result = self.perform_traceroute(target)
        
        if result["success"]:
            output = f"🛣️ Traceroute to {target}\n"
            output += f"Command: {result['command']}\n"
            output += f"Hops: {len(result['hops'])}\n\n"
            
            for hop in result["hops"]:
                output += f"{hop['hop']:>3}  {hop['host']:30}  {hop.get('rtt', 'N/A'):10}\n"
            
            output += f"\n✅ Traceroute completed successfully."
        else:
            output = f"❌ Traceroute failed: {result.get('error', 'Unknown error')}"
        
        return output

class DatabaseManager:
    """Unified database management for all modules"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.logger = EnhancedLogger("Database")
        self.init_database()
    
    def backup_database(self):
        """Create database backup"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(BACKUP_DIR, f"backup_{timestamp}.db")
        try:
            shutil.copy2(self.db_file, backup_file)
            self.logger.info(f"Database backed up to {backup_file}")
            return backup_file
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
            return None
    
    def init_database(self):
        """Initialize all database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Core tables
        tables = {
            "monitored_ips": """
                CREATE TABLE IF NOT EXISTS monitored_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    threat_level INTEGER DEFAULT 0,
                    last_scan TIMESTAMP,
                    tags TEXT,
                    notes TEXT
                )
            """,
            "threat_logs": """
                CREATE TABLE IF NOT EXISTS threat_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT 0,
                    action_taken TEXT,
                    evidence TEXT,
                    FOREIGN KEY (ip_address) REFERENCES monitored_ips(ip_address)
                )
            """,
            "command_history": """
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command TEXT NOT NULL,
                    source TEXT DEFAULT 'local',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1,
                    output TEXT,
                    execution_time REAL
                )
            """,
            "scan_results": """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    open_ports TEXT,
                    services TEXT,
                    os_info TEXT,
                    vulnerabilities TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_duration REAL,
                    FOREIGN KEY (ip_address) REFERENCES monitored_ips(ip_address)
                )
            """,
            "intrusion_detection": """
                CREATE TABLE IF NOT EXISTS intrusion_detection (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT NOT NULL,
                    dest_ip TEXT,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    packet_count INTEGER,
                    description TEXT,
                    action_taken TEXT,
                    protocol TEXT,
                    port INTEGER,
                    raw_data BLOB
                )
            """,
            "network_stats": """
                CREATE TABLE IF NOT EXISTS network_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    packets_processed INTEGER,
                    packet_rate REAL,
                    tcp_count INTEGER,
                    udp_count INTEGER,
                    icmp_count INTEGER,
                    threat_count INTEGER,
                    bandwidth_in REAL,
                    bandwidth_out REAL
                )
            """,
            "traceroute_results": """
                CREATE TABLE IF NOT EXISTS traceroute_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    command TEXT NOT NULL,
                    output TEXT,
                    hops INTEGER,
                    execution_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """,
            "web_requests": """
                CREATE TABLE IF NOT EXISTS web_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool TEXT NOT NULL,
                    target TEXT NOT NULL,
                    command TEXT NOT NULL,
                    output TEXT,
                    execution_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status_code INTEGER
                )
            """,
            "system_events": """
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_data TEXT,
                    severity TEXT DEFAULT 'info',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """,
            "user_sessions": """
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    actions_count INTEGER DEFAULT 0
                )
            """
        }
        
        for table_name, table_sql in tables.items():
            try:
                cursor.execute(table_sql)
                self.logger.debug(f"Table {table_name} initialized")
            except Exception as e:
                self.logger.error(f"Failed to create table {table_name}: {e}")
        
        # Create indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_threats_ip ON threat_logs(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_threats_time ON threat_logs(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_intrusion_time ON intrusion_detection(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_commands_time ON command_history(timestamp)",
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except Exception as e:
                self.logger.error(f"Failed to create index: {e}")
        
        conn.commit()
        conn.close()
        self.logger.info("Database initialized successfully")
    
    def log_command(self, command: str, source: str = 'local', 
                   success: bool = True, output: str = "", 
                   execution_time: float = 0.0):
        """Log command execution"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success, output, execution_time) VALUES (?, ?, ?, ?, ?)',
            (command[:500], source, success, output[:1000], execution_time)
        )
        conn.commit()
        conn.close()
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, 
                  description: str = "", action: str = "", evidence: str = ""):
        """Log threat detection"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO threat_logs 
               (ip_address, threat_type, severity, description, action_taken, evidence) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (ip_address, threat_type, severity, description, action, evidence)
        )
        conn.commit()
        conn.close()
    
    def log_intrusion(self, source_ip: str, threat_type: str, severity: str,
                     packet_count: int = 0, description: str = "", 
                     action: str = "logged", dest_ip: str = None,
                     protocol: str = None, port: int = None):
        """Log intrusion detection event"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO intrusion_detection 
               (source_ip, dest_ip, threat_type, severity, packet_count, description, action_taken, protocol, port) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (source_ip, dest_ip, threat_type, severity, packet_count, description, action, protocol, port)
        )
        conn.commit()
        conn.close()
    
    def get_recent_intrusions(self, limit: int = 50, hours: int = 24) -> List[Dict]:
        """Get recent intrusion detection events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, source_ip, dest_ip, threat_type, severity, description, protocol, port
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            ORDER BY timestamp DESC LIMIT ?
        ''', (f'-{hours} hours', limit))
        
        results = []
        columns = [desc[0] for desc in cursor.description]
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        conn.close()
        return results
    
    def get_statistics(self, time_range: str = '24h') -> Dict[str, Any]:
        """Get comprehensive statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        stats = {}
        
        # Time range mapping
        time_mapping = {
            '1h': '-1 hour',
            '24h': '-24 hours',
            '7d': '-7 days',
            '30d': '-30 days'
        }
        time_param = time_mapping.get(time_range, '-24 hours')
        
        # Threat statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_threats,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_severity,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_severity,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_severity
            FROM threat_logs 
            WHERE timestamp > datetime('now', ?)
        ''', (time_param,))
        
        threat_stats = cursor.fetchone()
        stats['threats'] = {
            'total': threat_stats[0],
            'high': threat_stats[1],
            'medium': threat_stats[2],
            'low': threat_stats[3]
        }
        
        # Network statistics
        cursor.execute('''
            SELECT 
                SUM(packets_processed) as total_packets,
                AVG(packet_rate) as avg_packet_rate,
                SUM(threat_count) as total_threats_detected
            FROM network_stats 
            WHERE timestamp > datetime('now', ?)
        ''', (time_param,))
        
        network_stats = cursor.fetchone()
        stats['network'] = {
            'total_packets': network_stats[0] or 0,
            'avg_packet_rate': network_stats[1] or 0,
            'total_threats_detected': network_stats[2] or 0
        }
        
        conn.close()
        return stats

class EnhancedNetworkScanner:
    """Comprehensive network scanning with multiple techniques"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = EnhancedLogger("NetworkScanner")
        self.traceroute = EnhancedTracerouteTool()
        
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
            self.logger.warning("Nmap not available. Some scanning features will be limited.")
    
    def ping_sweep(self, network: str, timeout: int = 1) -> List[Dict]:
        """Ping sweep to discover live hosts in a network"""
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for ip in network_obj.hosts():
                    futures.append(executor.submit(self._ping_host, str(ip), timeout))
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result['alive']:
                        hosts.append(result)
            
            self.logger.info(f"Ping sweep completed: {len(hosts)} hosts found")
            return hosts
            
        except Exception as e:
            self.logger.error(f"Ping sweep error: {e}")
            return []
    
    def _ping_host(self, ip: str, timeout: int) -> Dict:
        """Ping a single host"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            cmd = ['ping', param, '1', '-W' if 'linux' in platform.system().lower() else '-w', 
                  str(timeout * 1000), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            alive = result.returncode == 0
            
            return {
                'ip': ip,
                'alive': alive,
                'response_time': self._extract_ping_time(result.stdout) if alive else None
            }
        except Exception:
            return {'ip': ip, 'alive': False, 'response_time': None}
    
    def _extract_ping_time(self, output: str) -> Optional[float]:
        """Extract ping time from ping output"""
        patterns = [
            r'time=([\d\.]+)\s*ms',
            r'time<([\d\.]+)\s*ms',
            r'time>([\d\.]+)\s*ms'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    pass
        return None
    
    def port_scan(self, target: str, ports: str = "1-1000", 
                  scan_type: str = "connect", options: Dict = None) -> Dict[str, Any]:
        """Advanced port scanning with multiple techniques"""
        result = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "start_time": datetime.now().isoformat(),
            "success": False,
            "open_ports": [],
            "scan_duration": 0
        }
        
        start_time = time.time()
        
        try:
            if scan_type == "nmap" and self.nm:
                scan_result = self._nmap_scan(target, ports, options)
                result.update(scan_result)
            elif scan_type == "connect":
                scan_result = self._connect_scan(target, ports)
                result.update(scan_result)
            elif scan_type == "syn" and SCAPY_AVAILABLE:
                scan_result = self._syn_scan(target, ports)
                result.update(scan_result)
            else:
                result["error"] = f"Unsupported scan type: {scan_type}"
        
        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Port scan error: {e}")
        
        result["scan_duration"] = time.time() - start_time
        result["end_time"] = datetime.now().isoformat()
        
        # Save to database
        if result.get("success"):
            self._save_scan_result(result)
        
        return result
    
    def _nmap_scan(self, target: str, ports: str, options: Dict = None) -> Dict[str, Any]:
        """Perform Nmap scan"""
        scan_options = {
            'arguments': '-T4 -sV',
            'timeout': 300
        }
        
        if options:
            scan_options.update(options)
        
        try:
            self.nm.scan(target, ports, arguments=scan_options['arguments'], 
                        timeout=scan_options['timeout'])
            
            open_ports = []
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    for port, port_info in self.nm[target][proto].items():
                        if port_info['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extra': port_info.get('extrainfo', '')
                            })
            
            return {
                "success": True,
                "open_ports": open_ports,
                "hostname": self.nm[target].hostname(),
                "os_info": self.nm[target].get('osmatch', []),
                "nmap_output": self.nm.csv()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _connect_scan(self, target: str, ports: str) -> Dict[str, Any]:
        """TCP connect scan"""
        open_ports = []
        
        # Parse port range
        port_list = self._parse_port_range(ports)
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            return port, result == 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(check_port, port) for port in port_list]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': self._get_service_name(port)
                    })
        
        return {
            "success": True,
            "open_ports": open_ports
        }
    
    def _syn_scan(self, target: str, ports: str) -> Dict[str, Any]:
        """SYN scan using Scapy"""
        if not SCAPY_AVAILABLE:
            return {"success": False, "error": "Scapy not available"}
        
        open_ports = []
        port_list = self._parse_port_range(ports)
        
        try:
            # Send SYN packets
            syn_packet = IP(dst=target)/TCP(dport=port_list, flags="S")
            answered, unanswered = sr(syn_packet, timeout=2, verbose=0)
            
            for sent, received in answered:
                if received.haslayer(TCP) and received.getlayer(TCP).flags & 0x12:  # SYN-ACK
                    open_ports.append({
                        'port': sent.dport,
                        'protocol': 'tcp',
                        'service': self._get_service_name(sent.dport)
                    })
            
            return {
                "success": True,
                "open_ports": open_ports
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_port_range(self, ports: str) -> List[int]:
        """Parse port range string into list of ports"""
        port_list = []
        parts = ports.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part))
        
        return list(set(port_list))  # Remove duplicates
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "dns", 80: "http", 110: "pop3",
            143: "imap", 443: "https", 465: "smtps", 993: "imaps",
            995: "pop3s", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 8080: "http-proxy"
        }
        return common_ports.get(port, "unknown")
    
    def _save_scan_result(self, result: Dict):
        """Save scan result to database"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        open_ports_json = json.dumps([p['port'] for p in result['open_ports']])
        services_json = json.dumps([p.get('service', '') for p in result['open_ports']])
        
        cursor.execute('''
            INSERT INTO scan_results 
            (ip_address, scan_type, open_ports, services, scan_duration)
            VALUES (?, ?, ?, ?, ?)
        ''', (result['target'], result['scan_type'], 
              open_ports_json, services_json, result['scan_duration']))
        
        conn.commit()
        conn.close()
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Perform vulnerability scan"""
        if not self.nm:
            return {"success": False, "error": "Nmap not available"}
        
        try:
            self.nm.scan(target, arguments='--script vuln,default,safe -sV')
            
            vulns = []
            if target in self.nm.all_hosts():
                for hostscript in self.nm[target].get('hostscript', []):
                    if 'vuln' in hostscript.get('output', '').lower():
                        vulns.append(hostscript)
            
            return {
                "success": True,
                "target": target,
                "vulnerabilities": vulns,
                "scan_time": datetime.now().isoformat()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """Get comprehensive IP information"""
        info = {
            "ip": ip,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Get location info
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                location_data = response.json()
                if location_data.get('status') == 'success':
                    info.update({
                        "country": location_data.get('country'),
                        "region": location_data.get('regionName'),
                        "city": location_data.get('city'),
                        "isp": location_data.get('isp'),
                        "org": location_data.get('org'),
                        "as": location_data.get('as'),
                        "lat": location_data.get('lat'),
                        "lon": location_data.get('lon'),
                        "timezone": location_data.get('timezone')
                    })
            
            # Check if IP is in threat databases
            threat_info = self._check_threat_databases(ip)
            info["threat_info"] = threat_info
            
            # Get reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                info["hostname"] = hostname
            except socket.herror:
                info["hostname"] = None
            
            return info
            
        except Exception as e:
            self.logger.error(f"IP info error: {e}")
            info["error"] = str(e)
            return info
    
    def _check_threat_databases(self, ip: str) -> Dict[str, Any]:
        """Check IP against threat databases"""
        # This is a simplified version - in production, use proper threat intelligence APIs
        threat_info = {
            "is_malicious": False,
            "reputation": "unknown",
            "threat_types": [],
            "sources": []
        }
        
        # Example checks (simulated)
        suspicious_patterns = [
            r"^185\.", r"^188\.",  # Some known malicious ranges
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, ip):
                threat_info["is_malicious"] = True
                threat_info["reputation"] = "suspicious"
                threat_info["threat_types"].append("Known malicious range")
                threat_info["sources"].append("Internal DB")
                break
        
        return threat_info

class ThreatDetectionSystem:
    """Advanced threat detection with machine learning capabilities"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = EnhancedLogger("ThreatDetection")
        
        # Detection thresholds
        self.thresholds = {
            'port_scan': {
                'ports_per_minute': 50,
                'unique_ports': 20,
                'time_window': 60
            },
            'dos_attack': {
                'packets_per_second': 1000,
                'time_window': 5
            },
            'syn_flood': {
                'syn_per_second': 500,
                'syn_ack_ratio': 0.1,
                'time_window': 10
            },
            'brute_force': {
                'failed_auth_per_minute': 20,
                'time_window': 60
            }
        }
        
        # State tracking
        self.ip_stats = {}
        self.port_stats = {}
        self.connection_stats = {}
        self.detection_rules = self._load_detection_rules()
    
    def _load_detection_rules(self) -> List[Dict]:
        """Load detection rules from configuration"""
        rules_file = "detection_rules.json"
        default_rules = [
            {
                "name": "Port Scanning",
                "pattern": "rapid_port_access",
                "severity": "medium",
                "action": "alert"
            },
            {
                "name": "SYN Flood",
                "pattern": "syn_without_ack",
                "severity": "high",
                "action": "block"
            },
            {
                "name": "DDoS Attack",
                "pattern": "high_packet_rate",
                "severity": "high",
                "action": "block"
            },
            {
                "name": "Brute Force",
                "pattern": "multiple_failed_auth",
                "severity": "medium",
                "action": "alert"
            }
        ]
        
        try:
            if os.path.exists(rules_file):
                with open(rules_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load rules: {e}")
        
        return default_rules
    
    def analyze_packet(self, packet) -> List[Dict]:
        """Analyze network packet for threats"""
        threats = []
        
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Update statistics
                self._update_ip_stats(src_ip, dst_ip)
                
                # Analyze based on protocol
                if TCP in packet:
                    threats.extend(self._analyze_tcp(packet, src_ip, dst_ip))
                elif UDP in packet:
                    threats.extend(self._analyze_udp(packet, src_ip, dst_ip))
                elif ICMP in packet:
                    threats.extend(self._analyze_icmp(packet, src_ip, dst_ip))
                
                # Check for anomalies
                threats.extend(self._check_anomalies(src_ip))
            
        except Exception as e:
            self.logger.error(f"Packet analysis error: {e}")
        
        return threats
    
    def _update_ip_stats(self, src_ip: str, dst_ip: str):
        """Update IP statistics"""
        current_time = time.time()
        
        # Initialize stats for source IP
        if src_ip not in self.ip_stats:
            self.ip_stats[src_ip] = {
                'packet_count': 0,
                'last_seen': current_time,
                'packet_timestamps': [],
                'accessed_ports': set(),
                'destinations': set()
            }
        
        stats = self.ip_stats[src_ip]
        stats['packet_count'] += 1
        stats['last_seen'] = current_time
        stats['packet_timestamps'].append(current_time)
        stats['destinations'].add(dst_ip)
        
        # Clean old timestamps (older than 5 minutes)
        cutoff = current_time - 300
        stats['packet_timestamps'] = [t for t in stats['packet_timestamps'] if t > cutoff]
    
    def _analyze_tcp(self, packet, src_ip: str, dst_ip: str) -> List[Dict]:
        """Analyze TCP packet"""
        threats = []
        tcp = packet[TCP]
        
        # Track port access
        self.ip_stats[src_ip]['accessed_ports'].add(tcp.dport)
        
        # Check for SYN flood
        if tcp.flags & 0x02:  # SYN flag
            if src_ip not in self.connection_stats:
                self.connection_stats[src_ip] = {'syn_sent': 0, 'syn_ack_received': 0}
            
            self.connection_stats[src_ip]['syn_sent'] += 1
            
            # Check SYN flood threshold
            syn_rate = self._calculate_syn_rate(src_ip)
            if syn_rate > self.thresholds['syn_flood']['syn_per_second']:
                threats.append({
                    'type': 'SYN Flood',
                    'source': src_ip,
                    'destination': dst_ip,
                    'severity': 'high',
                    'rate': syn_rate,
                    'description': f'SYN flood detected from {src_ip} at rate {syn_rate:.1f}/s'
                })
        
        # Check for port scanning
        accessed_ports = len(self.ip_stats[src_ip]['accessed_ports'])
        if accessed_ports > self.thresholds['port_scan']['unique_ports']:
            port_scan_rate = self._calculate_port_scan_rate(src_ip)
            if port_scan_rate > self.thresholds['port_scan']['ports_per_minute']:
                threats.append({
                    'type': 'Port Scan',
                    'source': src_ip,
                    'severity': 'medium',
                    'ports_accessed': accessed_ports,
                    'description': f'Port scan detected from {src_ip} ({accessed_ports} ports)'
                })
        
        return threats
    
    def _analyze_udp(self, packet, src_ip: str, dst_ip: str) -> List[Dict]:
        """Analyze UDP packet"""
        threats = []
        
        # Calculate UDP packet rate
        udp_rate = self._calculate_packet_rate(src_ip, 1)  # 1 second window
        if udp_rate > self.thresholds['dos_attack']['packets_per_second']:
            threats.append({
                'type': 'UDP Flood',
                'source': src_ip,
                'destination': dst_ip,
                'severity': 'high',
                'rate': udp_rate,
                'description': f'UDP flood detected from {src_ip} at rate {udp_rate:.1f}/s'
            })
        
        return threats
    
    def _analyze_icmp(self, packet, src_ip: str, dst_ip: str) -> List[Dict]:
        """Analyze ICMP packet"""
        threats = []
        
        # Calculate ICMP packet rate
        icmp_rate = self._calculate_packet_rate(src_ip, 1)  # 1 second window
        if icmp_rate > self.thresholds['dos_attack']['packets_per_second'] / 2:
            threats.append({
                'type': 'ICMP Flood',
                'source': src_ip,
                'destination': dst_ip,
                'severity': 'medium',
                'rate': icmp_rate,
                'description': f'ICMP flood detected from {src_ip} at rate {icmp_rate:.1f}/s'
            })
        
        return threats
    
    def _check_anomalies(self, src_ip: str) -> List[Dict]:
        """Check for anomalous behavior"""
        threats = []
        
        if src_ip in self.ip_stats:
            stats = self.ip_stats[src_ip]
            
            # Check for high packet rate
            packet_rate = self._calculate_packet_rate(src_ip, 
                                                     self.thresholds['dos_attack']['time_window'])
            if packet_rate > self.thresholds['dos_attack']['packets_per_second']:
                threats.append({
                    'type': 'DoS Attack',
                    'source': src_ip,
                    'severity': 'high',
                    'rate': packet_rate,
                    'description': f'DoS attack detected from {src_ip} at rate {packet_rate:.1f} packets/s'
                })
            
            # Check for multiple destinations (possible scanning)
            if len(stats['destinations']) > 10:
                threats.append({
                    'type': 'Network Scanning',
                    'source': src_ip,
                    'severity': 'medium',
                    'destinations': len(stats['destinations']),
                    'description': f'Network scanning detected from {src_ip} ({len(stats["destinations"])} destinations)'
                })
        
        return threats
    
    def _calculate_packet_rate(self, ip: str, window_seconds: float) -> float:
        """Calculate packet rate for IP within time window"""
        if ip not in self.ip_stats:
            return 0
        
        timestamps = self.ip_stats[ip]['packet_timestamps']
        if not timestamps:
            return 0
        
        cutoff = time.time() - window_seconds
        recent_packets = [t for t in timestamps if t > cutoff]
        
        if window_seconds > 0:
            return len(recent_packets) / window_seconds
        return 0
    
    def _calculate_syn_rate(self, ip: str) -> float:
        """Calculate SYN packet rate"""
        if ip not in self.connection_stats:
            return 0
        
        # Simplified calculation
        return self.connection_stats[ip].get('syn_sent', 0) / 10  # Last 10 seconds
    
    def _calculate_port_scan_rate(self, ip: str) -> float:
        """Calculate port scan rate"""
        if ip not in self.ip_stats:
            return 0
        
        accessed_ports = len(self.ip_stats[ip]['accessed_ports'])
        time_elapsed = time.time() - min(self.ip_stats[ip]['packet_timestamps']) if self.ip_stats[ip]['packet_timestamps'] else 1
        return accessed_ports / (time_elapsed / 60)  # Ports per minute
    
    def clear_old_stats(self, max_age: int = 600):
        """Clear statistics older than max_age seconds"""
        cutoff = time.time() - max_age
        ips_to_remove = []
        
        for ip, stats in self.ip_stats.items():
            if stats['last_seen'] < cutoff:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.ip_stats[ip]
        
        # Clean connection stats
        conn_ips_to_remove = []
        for ip in self.connection_stats:
            if ip not in self.ip_stats:
                conn_ips_to_remove.append(ip)
        
        for ip in conn_ips_to_remove:
            del self.connection_stats[ip]

class WebToolsSuite:
    """Comprehensive web testing and analysis tools"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = EnhancedLogger("WebTools")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def http_request(self, url: str, method: str = 'GET', 
                    options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform HTTP request with advanced features"""
        default_options = {
            'headers': {},
            'params': {},
            'data': {},
            'timeout': 10,
            'allow_redirects': True,
            'verify_ssl': True,
            'proxy': None,
            'auth': None
        }
        
        if options:
            default_options.update(options)
        
        result = {
            'url': url,
            'method': method,
            'success': False,
            'start_time': datetime.now().isoformat(),
            'duration': 0
        }
        
        start_time = time.time()
        
        try:
            # Prepare request
            request_kwargs = {
                'timeout': default_options['timeout'],
                'allow_redirects': default_options['allow_redirects'],
                'verify': default_options['verify_ssl']
            }
            
            if default_options['headers']:
                request_kwargs['headers'] = default_options['headers']
            
            if default_options['params']:
                request_kwargs['params'] = default_options['params']
            
            if default_options['proxy']:
                request_kwargs['proxies'] = {
                    'http': default_options['proxy'],
                    'https': default_options['proxy']
                }
            
            if default_options['auth']:
                request_kwargs['auth'] = default_options['auth']
            
            # Execute request
            if method.upper() == 'GET':
                response = self.session.get(url, **request_kwargs)
            elif method.upper() == 'POST':
                request_kwargs['data'] = default_options['data']
                response = self.session.post(url, **request_kwargs)
            elif method.upper() == 'HEAD':
                response = self.session.head(url, **request_kwargs)
            else:
                response = self.session.request(method, url, **request_kwargs)
            
            # Process response
            result.update({
                'success': True,
                'status_code': response.status_code,
                'reason': response.reason,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'encoding': response.encoding,
                'elapsed': response.elapsed.total_seconds(),
                'final_url': response.url,
                'history': [{
                    'url': resp.url,
                    'status_code': resp.status_code
                } for resp in response.history],
                'cookies': dict(response.cookies)
            })
            
            # Try to get content if not too large
            if len(response.content) < 1048576:  # 1MB limit
                try:
                    result['text'] = response.text[:5000]  # First 5000 chars
                except:
                    result['text'] = 'Unable to decode text content'
            
            # Security headers check
            security_headers = self._check_security_headers(response.headers)
            result['security_headers'] = security_headers
            
        except requests.exceptions.Timeout:
            result['error'] = f'Request timeout after {default_options["timeout"]} seconds'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection error'
        except requests.exceptions.TooManyRedirects:
            result['error'] = 'Too many redirects'
        except Exception as e:
            result['error'] = str(e)
        
        result['duration'] = time.time() - start_time
        result['end_time'] = datetime.now().isoformat()
        
        # Log to database
        self._log_web_request(result)
        
        return result
    
    def _check_security_headers(self, headers: Dict) -> Dict:
        """Check for security headers"""
        security_checks = {
            'strict_transport_security': {
                'header': 'Strict-Transport-Security',
                'recommended': 'max-age=31536000; includeSubDomains',
                'present': False,
                'value': None
            },
            'x_frame_options': {
                'header': 'X-Frame-Options',
                'recommended': 'DENY or SAMEORIGIN',
                'present': False,
                'value': None
            },
            'x_content_type_options': {
                'header': 'X-Content-Type-Options',
                'recommended': 'nosniff',
                'present': False,
                'value': None
            },
            'content_security_policy': {
                'header': 'Content-Security-Policy',
                'recommended': 'Present with proper directives',
                'present': False,
                'value': None
            }
        }
        
        for check_name, check_info in security_checks.items():
            header_name = check_info['header']
            if header_name in headers:
                check_info['present'] = True
                check_info['value'] = headers[header_name]
        
        return security_checks
    
    def _log_web_request(self, result: Dict):
        """Log web request to database"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        output_json = json.dumps({
            'status_code': result.get('status_code'),
            'headers': result.get('headers', {}),
            'security_headers': result.get('security_headers', {})
        })
        
        cursor.execute('''
            INSERT INTO web_requests 
            (tool, target, command, output, execution_time, status_code)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('http_request', result['url'], result['method'], 
              output_json, result['duration'], result.get('status_code')))
        
        conn.commit()
        conn.close()
    
    def dns_lookup(self, domain: str, record_type: str = 'A') -> Dict[str, Any]:
        """Perform DNS lookup"""
        result = {
            'domain': domain,
            'record_type': record_type,
            'success': False,
            'start_time': datetime.now().isoformat()
        }
        
        try:
            if record_type.upper() == 'A':
                answers = socket.gethostbyname_ex(domain)
                result['addresses'] = answers[2]
                result['aliases'] = answers[1]
                result['success'] = True
            else:
                # For other record types, use nslookup if available
                cmd = ['nslookup', '-type=' + record_type, domain]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                result['output'] = process.stdout
                result['error_output'] = process.stderr
                result['return_code'] = process.returncode
                result['success'] = process.returncode == 0
            
        except socket.gaierror as e:
            result['error'] = f'DNS lookup failed: {e}'
        except Exception as e:
            result['error'] = str(e)
        
        result['end_time'] = datetime.now().isoformat()
        return result
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        result = {
            'domain': domain,
            'success': False,
            'start_time': datetime.now().isoformat()
        }
        
        try:
            cmd = ['whois', domain]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            result['output'] = process.stdout
            result['error_output'] = process.stderr
            result['return_code'] = process.returncode
            result['success'] = process.returncode == 0
            
            # Parse WHOIS output
            parsed_info = self._parse_whois_output(process.stdout)
            result['parsed'] = parsed_info
            
        except Exception as e:
            result['error'] = str(e)
        
        result['end_time'] = datetime.now().isoformat()
        return result
    
    def _parse_whois_output(self, output: str) -> Dict[str, Any]:
        """Parse WHOIS output for common fields"""
        parsed = {}
        
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiration_date': r'Registry Expiry Date:\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'status': r'Status:\s*(.+)'
        }
        
        for field, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                parsed[field] = matches[0] if len(matches) == 1 else matches
        
        return parsed

class NetworkMonitor:
    """Real-time network monitoring with threat detection"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = EnhancedLogger("NetworkMonitor")
        self.threat_detector = ThreatDetectionSystem(db_manager)
        self.web_tools = WebToolsSuite(db_manager)
        
        self.is_monitoring = False
        self.sniffer_thread = None
        self.processor_thread = None
        self.stats_thread = None
        self.packet_queue = queue.Queue(maxsize=10000)
        
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'threats_detected': 0,
            'start_time': None,
            'bandwidth_in': 0,
            'bandwidth_out': 0
        }
        
        self.target_filter = None
    
    def start(self, interface: str = None, target_ip: str = None, 
              capture_filter: str = None) -> bool:
        """Start network monitoring"""
        if self.is_monitoring:
            self.logger.warning("Monitoring already active")
            return False
        
        self.is_monitoring = True
        self.stats['start_time'] = time.time()
        self.stats['total_packets'] = 0
        self.stats['threats_detected'] = 0
        
        # Set target filter
        if target_ip:
            self.target_filter = f"host {target_ip}"
        elif capture_filter:
            self.target_filter = capture_filter
        
        # Start threads
        self.sniffer_thread = threading.Thread(
            target=self._packet_capture,
            args=(interface,),
            daemon=True
        )
        
        self.processor_thread = threading.Thread(
            target=self._packet_processing,
            daemon=True
        )
        
        self.stats_thread = threading.Thread(
            target=self._stats_logging,
            daemon=True
        )
        
        self.sniffer_thread.start()
        self.processor_thread.start()
        self.stats_thread.start()
        
        self.logger.info(f"Network monitoring started on interface {interface or 'default'}")
        return True
    
    def stop(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
        # Wait for threads to finish
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=5)
        
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5)
        
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=5)
        
        self.logger.info("Network monitoring stopped")
    
    def _packet_capture(self, interface: str = None):
        """Capture network packets"""
        try:
            sniff(
                iface=interface,
                prn=self._packet_handler,
                filter=self.target_filter,
                store=0,
                stop_filter=lambda x: not self.is_monitoring
            )
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
    
    def _packet_handler(self, packet):
        """Handle captured packet"""
        try:
            self.packet_queue.put(packet, timeout=1)
        except queue.Full:
            self.logger.warning("Packet queue full, dropping packet")
    
    def _packet_processing(self):
        """Process captured packets"""
        while self.is_monitoring or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Packet processing error: {e}")
    
    def _process_packet(self, packet):
        """Process individual packet"""
        self.stats['total_packets'] += 1
        
        # Update protocol statistics
        if TCP in packet:
            self.stats['tcp_packets'] += 1
        elif UDP in packet:
            self.stats['udp_packets'] += 1
        elif ICMP in packet:
            self.stats['icmp_packets'] += 1
        
        # Detect threats
        threats = self.threat_detector.analyze_packet(packet)
        
        if threats:
            self.stats['threats_detected'] += len(threats)
            for threat in threats:
                self._handle_threat(threat, packet)
        
        # Update bandwidth stats (simplified)
        if IP in packet:
            packet_size = len(packet)
            if packet[IP].src.startswith('192.168.'):  # Internal IP
                self.stats['bandwidth_out'] += packet_size
            else:
                self.stats['bandwidth_in'] += packet_size
    
    def _handle_threat(self, threat: Dict, packet):
        """Handle detected threat"""
        self.logger.warning(f"Threat detected: {threat}")
        
        # Log to database
        self.db.log_intrusion(
            source_ip=threat.get('source'),
            dest_ip=threat.get('destination'),
            threat_type=threat['type'],
            severity=threat['severity'],
            packet_count=1,
            description=threat.get('description', ''),
            action_taken='logged'
        )
        
        # Take action based on severity
        if threat['severity'] == 'high':
            self._take_action(threat, packet)
    
    def _take_action(self, threat: Dict, packet):
        """Take action against threat"""
        # This is where you would implement blocking, alerting, etc.
        # For now, just log the action
        action = f"Blocked {threat['type']} from {threat.get('source')}"
        self.logger.info(action)
        
        # Update threat log with action taken
        self.db.log_threat(
            ip_address=threat.get('source'),
            threat_type=threat['type'],
            severity=threat['severity'],
            description=threat.get('description', ''),
            action_taken=action,
            evidence=str(packet.summary())
        )
    
    def _stats_logging(self):
        """Log statistics periodically"""
        while self.is_monitoring:
            time.sleep(60)  # Log every minute
            
            # Calculate rates
            uptime = time.time() - self.stats['start_time']
            if uptime > 0:
                packet_rate = self.stats['total_packets'] / uptime
            else:
                packet_rate = 0
            
            # Log to database
            stats_data = {
                'packets_processed': self.stats['total_packets'],
                'packet_rate': packet_rate,
                'tcp_count': self.stats['tcp_packets'],
                'udp_count': self.stats['udp_packets'],
                'icmp_count': self.stats['icmp_packets'],
                'threat_count': self.stats['threats_detected'],
                'bandwidth_in': self.stats['bandwidth_in'],
                'bandwidth_out': self.stats['bandwidth_out']
            }
            
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO network_stats 
                (packets_processed, packet_rate, tcp_count, udp_count, icmp_count, threat_count, bandwidth_in, bandwidth_out)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', tuple(stats_data.values()))
            conn.commit()
            conn.close()
            
            # Clear old threat detector stats
            self.threat_detector.clear_old_stats()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        if not self.stats['start_time']:
            return {'status': 'not_started'}
        
        uptime = time.time() - self.stats['start_time']
        
        return {
            'status': 'active' if self.is_monitoring else 'stopped',
            'uptime': uptime,
            'total_packets': self.stats['total_packets'],
            'packet_rate': self.stats['total_packets'] / uptime if uptime > 0 else 0,
            'tcp_packets': self.stats['tcp_packets'],
            'udp_packets': self.stats['udp_packets'],
            'icmp_packets': self.stats['icmp_packets'],
            'threats_detected': self.stats['threats_detected'],
            'bandwidth_in': self.stats['bandwidth_in'],
            'bandwidth_out': self.stats['bandwidth_out'],
            'target_filter': self.target_filter
        }

class TrafficGenerator:
    """Network traffic generation for testing"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = EnhancedLogger("TrafficGenerator")
        self.is_running = False
        self.threads = []
        
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available. Traffic generation disabled.")
    
    def generate_tcp_syn(self, target_ip: str, target_port: int = 80, 
                        count: int = 100, delay: float = 0.1) -> bool:
        """Generate TCP SYN packets"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy required for TCP SYN generation")
            return False
        
        def syn_flood():
            for i in range(count):
                if not self.is_running:
                    break
                
                src_port = random.randint(1024, 65535)
                packet = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags='S')
                send(packet, verbose=0)
                
                if delay > 0:
                    time.sleep(delay)
            
            self.logger.info(f"Sent {count} TCP SYN packets to {target_ip}:{target_port}")
        
        thread = threading.Thread(target=syn_flood, daemon=True)
        self.threads.append(thread)
        thread.start()
        return True
    
    def generate_udp_flood(self, target_ip: str, target_port: int = 53,
                          count: int = 100, delay: float = 0.05) -> bool:
        """Generate UDP flood"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy required for UDP flood")
            return False
        
        def udp_flood():
            for i in range(count):
                if not self.is_running:
                    break
                
                src_port = random.randint(1024, 65535)
                payload = secrets.token_bytes(random.randint(64, 512))
                packet = IP(dst=target_ip)/UDP(sport=src_port, dport=target_port)/payload
                send(packet, verbose=0)
                
                if delay > 0:
                    time.sleep(delay)
            
            self.logger.info(f"Sent {count} UDP packets to {target_ip}:{target_port}")
        
        thread = threading.Thread(target=udp_flood, daemon=True)
        self.threads.append(thread)
        thread.start()
        return True
    
    def generate_icmp_flood(self, target_ip: str, count: int = 100,
                           delay: float = 0.1) -> bool:
        """Generate ICMP flood"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy required for ICMP flood")
            return False
        
        def icmp_flood():
            for i in range(count):
                if not self.is_running:
                    break
                
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)
                
                if delay > 0:
                    time.sleep(delay)
            
            self.logger.info(f"Sent {count} ICMP packets to {target_ip}")
        
        thread = threading.Thread(target=icmp_flood, daemon=True)
        self.threads.append(thread)
        thread.start()
        return True
    
    def start_all(self, target_ip: str, duration: int = 30):
        """Start all traffic generation"""
        self.is_running = True
        
        # Start different types of traffic
        self.generate_tcp_syn(target_ip, count=duration*10, delay=0.05)
        self.generate_udp_flood(target_ip, count=duration*20, delay=0.02)
        self.generate_icmp_flood(target_ip, count=duration*5, delay=0.1)
        
        # Stop after duration
        def stop_timer():
            time.sleep(duration)
            self.stop()
        
        threading.Thread(target=stop_timer, daemon=True).start()
    
    def stop(self):
        """Stop all traffic generation"""
        self.is_running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.threads = []
        self.logger.info("All traffic generation stopped")

class TerminalInterface:
    """Command-line interface for the tool"""
    
    def __init__(self, scanner: EnhancedNetworkScanner, 
                 monitor: NetworkMonitor, web_tools: WebToolsSuite,
                 traffic_gen: TrafficGenerator):
        self.scanner = scanner
        self.monitor = monitor
        self.web_tools = web_tools
        self.traffic_gen = traffic_gen
        self.logger = EnhancedLogger("Terminal")
        
        self.commands = {
            'help': self.show_help,
            'scan': self.cmd_scan,
            'monitor': self.cmd_monitor,
            'traceroute': self.cmd_traceroute,
            'web': self.cmd_web,
            'traffic': self.cmd_traffic,
            'stats': self.cmd_stats,
            'report': self.cmd_report,
            'clear': self.cmd_clear,
            'exit': self.cmd_exit
        }
    
    def run(self):
        """Run the terminal interface"""
        print("\n" + "="*60)
        print("ACCURATE CYBER DEFENSE TERMINAL")
        print("="*60)
        print("Type 'help' for available commands\n")
        
        while True:
            try:
                command = input("cyberdefense> ").strip()
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if cmd in self.commands:
                    result = self.commands[cmd](args)
                    if result == "EXIT":
                        break
                else:
                    print(f"Unknown command: {cmd}. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"Error: {e}")
    
    def show_help(self, args=None):
        """Show help information"""
        help_text = """
Available Commands:

NETWORK SCANNING:
  scan ping <network>          - Ping sweep network (e.g., 192.168.1.0/24)
  scan ports <ip> [ports]      - Port scan (default: 1-1000)
  scan vuln <ip>               - Vulnerability scan
  scan info <ip>               - Get IP information
  
NETWORK MONITORING:
  monitor start [interface]    - Start network monitoring
  monitor stop                 - Stop monitoring
  monitor status               - Show monitoring status
  
NETWORK ANALYSIS:
  traceroute <target>          - Perform traceroute
  web http <url>               - HTTP request analysis
  web dns <domain>             - DNS lookup
  web whois <domain>           - WHOIS lookup
  
TRAFFIC GENERATION:
  traffic syn <ip> [port]      - Generate TCP SYN flood
  traffic udp <ip> [port]      - Generate UDP flood
  traffic icmp <ip>            - Generate ICMP flood
  traffic stop                 - Stop all traffic
  
REPORTING:
  stats                        - Show system statistics
  report threats [hours]       - Generate threat report
  report network [hours]       - Generate network report
  
SYSTEM:
  clear                        - Clear screen
  exit                         - Exit program
        """
        print(help_text)
        return ""
    
    def cmd_scan(self, args):
        """Handle scan commands"""
        if not args:
            print("Usage: scan <type> [options]")
            return ""
        
        scan_type = args[0].lower()
        
        if scan_type == 'ping' and len(args) > 1:
            network = args[1]
            print(f"Performing ping sweep on {network}...")
            hosts = self.scanner.ping_sweep(network)
            
            print(f"\nFound {len(hosts)} hosts:")
            for host in hosts:
                if host['alive']:
                    print(f"  {host['ip']} - {host['response_time']}ms")
            
        elif scan_type == 'ports' and len(args) > 1:
            target = args[1]
            ports = args[2] if len(args) > 2 else "1-1000"
            
            print(f"Scanning {target} ports {ports}...")
            result = self.scanner.port_scan(target, ports)
            
            if result['success']:
                print(f"\nOpen ports on {target}:")
                for port in result['open_ports']:
                    print(f"  {port['port']}/tcp - {port['service']}")
            else:
                print(f"Scan failed: {result.get('error')}")
        
        elif scan_type == 'vuln' and len(args) > 1:
            target = args[1]
            print(f"Scanning {target} for vulnerabilities...")
            result = self.scanner.vulnerability_scan(target)
            
            if result['success']:
                print(f"\nVulnerabilities found: {len(result['vulnerabilities'])}")
                for vuln in result['vulnerabilities'][:10]:
                    print(f"  • {vuln}")
            else:
                print(f"Scan failed: {result.get('error')}")
        
        elif scan_type == 'info' and len(args) > 1:
            ip = args[1]
            print(f"Getting information for {ip}...")
            info = self.scanner.get_ip_info(ip)
            
            print(f"\nInformation for {ip}:")
            if 'country' in info:
                print(f"  Location: {info.get('city', 'N/A')}, {info.get('country', 'N/A')}")
                print(f"  ISP: {info.get('isp', 'N/A')}")
                print(f"  Organization: {info.get('org', 'N/A')}")
            
            if info.get('threat_info', {}).get('is_malicious'):
                print(f"  ⚠️  This IP is flagged as malicious")
        
        else:
            print("Invalid scan command")
        
        return ""
    
    def cmd_monitor(self, args):
        """Handle monitoring commands"""
        if not args:
            print("Usage: monitor <start|stop|status>")
            return ""
        
        action = args[0].lower()
        
        if action == 'start':
            interface = args[1] if len(args) > 1 else None
            self.monitor.start(interface=interface)
            print("Network monitoring started")
        
        elif action == 'stop':
            self.monitor.stop()
            print("Network monitoring stopped")
        
        elif action == 'status':
            stats = self.monitor.get_stats()
            print(f"\nMonitoring Status: {stats['status']}")
            if stats['status'] == 'active':
                print(f"Uptime: {stats['uptime']:.0f}s")
                print(f"Packets: {stats['total_packets']}")
                print(f"Packet rate: {stats['packet_rate']:.1f}/s")
                print(f"Threats detected: {stats['threats_detected']}")
        
        return ""
    
    def cmd_traceroute(self, args):
        """Handle traceroute"""
        if not args:
            print("Usage: traceroute <target>")
            return ""
        
        target = args[0]
        result = self.scanner.traceroute.interactive_traceroute(target)
        print(result)
        return ""
    
    def cmd_web(self, args):
        """Handle web commands"""
        if len(args) < 2:
            print("Usage: web <http|dns|whois> <target>")
            return ""
        
        tool = args[0].lower()
        target = args[1]
        
        if tool == 'http':
            result = self.web_tools.http_request(target)
            print(f"\nHTTP Request to {target}:")
            print(f"Status: {result.get('status_code')} {result.get('reason')}")
            print(f"Time: {result.get('elapsed', 0):.3f}s")
            
            if 'security_headers' in result:
                print("\nSecurity Headers:")
                for check, info in result['security_headers'].items():
                    status = "✓" if info['present'] else "✗"
                    print(f"  {status} {info['header']}: {info.get('value', 'Missing')}")
        
        elif tool == 'dns':
            result = self.web_tools.dns_lookup(target)
            if result['success']:
                print(f"\nDNS Lookup for {target}:")
                if 'addresses' in result:
                    for addr in result['addresses']:
                        print(f"  {addr}")
            else:
                print(f"DNS lookup failed: {result.get('error')}")
        
        elif tool == 'whois':
            result = self.web_tools.whois_lookup(target)
            if result['success']:
                print(f"\nWHOIS for {target}:")
                if 'parsed' in result:
                    for key, value in result['parsed'].items():
                        print(f"  {key}: {value}")
            else:
                print(f"WHOIS lookup failed: {result.get('error')}")
        
        return ""
    
    def cmd_traffic(self, args):
        """Handle traffic generation"""
        if not args:
            print("Usage: traffic <syn|udp|icmp|stop> [ip] [port]")
            return ""
        
        action = args[0].lower()
        
        if action == 'stop':
            self.traffic_gen.stop()
            print("Traffic generation stopped")
            return ""
        
        if len(args) < 2:
            print(f"Usage: traffic {action} <ip> [port]")
            return ""
        
        target_ip = args[1]
        port = int(args[2]) if len(args) > 2 else 80
        
        if action == 'syn':
            self.traffic_gen.generate_tcp_syn(target_ip, port)
            print(f"Started TCP SYN flood to {target_ip}:{port}")
        
        elif action == 'udp':
            self.traffic_gen.generate_udp_flood(target_ip, port)
            print(f"Started UDP flood to {target_ip}:{port}")
        
        elif action == 'icmp':
            self.traffic_gen.generate_icmp_flood(target_ip)
            print(f"Started ICMP flood to {target_ip}")
        
        return ""
    
    def cmd_stats(self, args):
        """Show statistics"""
        db = self.scanner.db
        stats = db.get_statistics()
        
        print("\nSYSTEM STATISTICS")
        print("="*40)
        
        print(f"\nThreat Statistics (last 24h):")
        print(f"  Total threats: {stats['threats']['total']}")
        print(f"  High severity: {stats['threats']['high']}")
        print(f"  Medium severity: {stats['threats']['medium']}")
        print(f"  Low severity: {stats['threats']['low']}")
        
        print(f"\nNetwork Statistics:")
        print(f"  Total packets: {stats['network']['total_packets']:,}")
        print(f"  Avg packet rate: {stats['network']['avg_packet_rate']:.1f}/s")
        print(f"  Threats detected: {stats['network']['total_threats_detected']}")
        
        # System info
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        print(f"\nSystem Resources:")
        print(f"  CPU Usage: {cpu}%")
        print(f"  Memory Usage: {mem.percent}% ({mem.used/1024/1024:.0f}MB)")
        print(f"  Disk Usage: {disk.percent}%")
        
        return ""
    
    def cmd_report(self, args):
        """Generate reports"""
        if not args:
            print("Usage: report <threats|network> [hours]")
            return ""
        
        report_type = args[0].lower()
        hours = int(args[1]) if len(args) > 1 else 24
        
        if report_type == 'threats':
            self._generate_threat_report(hours)
        elif report_type == 'network':
            self._generate_network_report(hours)
        
        return ""
    
    def _generate_threat_report(self, hours: int):
        """Generate threat report"""
        db = self.scanner.db
        threats = db.get_recent_intrusions(limit=100, hours=hours)
        
        filename = f"threat_report_{int(time.time())}.txt"
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(f"THREAT REPORT - Last {hours} hours\n")
            f.write("="*50 + "\n\n")
            
            if not threats:
                f.write("No threats detected in this period.\n")
            else:
                f.write(f"Total threats: {len(threats)}\n\n")
                
                # Group by threat type
                threats_by_type = {}
                for threat in threats:
                    ttype = threat['threat_type']
                    if ttype not in threats_by_type:
                        threats_by_type[ttype] = []
                    threats_by_type[ttype].append(threat)
                
                for ttype, type_threats in threats_by_type.items():
                    f.write(f"\n{ttype.upper()} ({len(type_threats)}):\n")
                    f.write("-"*30 + "\n")
                    
                    for threat in type_threats[:10]:  # Show first 10 of each type
                        f.write(f"  {threat['timestamp']} - {threat['source_ip']}")
                        if threat['dest_ip']:
                            f.write(f" → {threat['dest_ip']}")
                        f.write(f" - {threat['severity']}\n")
                        if threat['description']:
                            f.write(f"    {threat['description']}\n")
        
        print(f"Threat report saved to {filepath}")
    
    def _generate_network_report(self, hours: int):
        """Generate network report"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:00', timestamp) as hour,
                SUM(packets_processed) as packets,
                AVG(packet_rate) as avg_rate,
                SUM(threat_count) as threats
            FROM network_stats 
            WHERE timestamp > datetime('now', ?)
            GROUP BY strftime('%Y-%m-%d %H:00', timestamp)
            ORDER BY hour
        ''', (f'-{hours} hours',))
        
        results = cursor.fetchall()
        conn.close()
        
        filename = f"network_report_{int(time.time())}.txt"
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(f"NETWORK REPORT - Last {hours} hours\n")
            f.write("="*50 + "\n\n")
            
            if not results:
                f.write("No network data in this period.\n")
            else:
                total_packets = sum(row[1] for row in results)
                total_threats = sum(row[3] for row in results)
                
                f.write(f"Total packets: {total_packets:,}\n")
                f.write(f"Total threats detected: {total_threats}\n\n")
                
                f.write("Hourly Breakdown:\n")
                f.write("Hour               Packets    Avg Rate  Threats\n")
                f.write("-"*50 + "\n")
                
                for row in results:
                    f.write(f"{row[0]:<18} {row[1]:>9,} {row[2]:>10.1f}/s {row[3]:>7}\n")
        
        print(f"Network report saved to {filepath}")
    
    def cmd_clear(self, args):
        """Clear screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""
    
    def cmd_exit(self, args):
        """Exit program"""
        print("\nStopping all services...")
        self.monitor.stop()
        self.traffic_gen.stop()
        print("Goodbye!")
        return "EXIT"

class GUIInterface:
    """Graphical user interface"""
    
    def __init__(self, root):
        self.root = root
        self.logger = EnhancedLogger("GUI")
        
        # Initialize components
        self.db = DatabaseManager()
        self.scanner = EnhancedNetworkScanner(self.db)
        self.monitor = NetworkMonitor(self.db)
        self.web_tools = WebToolsSuite(self.db)
        self.traffic_gen = TrafficGenerator(self.db)
        
        self.current_theme = "dark"
        self.setup_gui()
        
        # Start periodic updates
        self.update_interval = 2000  # ms
        self.update_dashboard()
    
    def setup_gui(self):
        """Setup the main GUI"""
        if not GUI_AVAILABLE:
            self.logger.error("GUI not available")
            return
        
        self.root.title("Accurate Cyber Defense Cyber Drill Tool ")
        self.root.geometry("1400x900")
        
        # Create menu
        self.create_menu()
        
        # Create main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_monitor_tab()
        self.create_web_tools_tab()
        self.create_traffic_tab()
        self.create_reports_tab()
        
        # Apply theme
        self.apply_theme()
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        theme_menu = tk.Menu(view_menu, tearoff=0)
        for theme_name in THEMES.keys():
            theme_menu.add_command(label=theme_name.title(), 
                                 command=lambda t=theme_name: self.change_theme(t))
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Terminal Mode", command=self.open_terminal)
        tools_menu.add_command(label="Database Backup", command=self.backup_database)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Status panels
        status_frame = ttk.LabelFrame(tab, text="System Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create status labels
        self.status_labels = {}
        status_grid = ttk.Frame(status_frame)
        status_grid.pack(fill=tk.X, padx=5, pady=5)
        
        status_items = [
            ("CPU Usage:", "cpu"),
            ("Memory Usage:", "memory"),
            ("Disk Usage:", "disk"),
            ("Network:", "network"),
            ("Monitoring:", "monitoring"),
            ("Threats (24h):", "threats")
        ]
        
        for i, (label, key) in enumerate(status_items):
            row = i // 3
            col = i % 3
            
            frame = ttk.Frame(status_grid)
            frame.grid(row=row, column=col, sticky=tk.W, padx=20, pady=10)
            
            ttk.Label(frame, text=label, width=15).pack(side=tk.LEFT)
            self.status_labels[key] = ttk.Label(frame, text="N/A", width=15)
            self.status_labels[key].pack(side=tk.LEFT)
        
        # Recent threats
        threats_frame = ttk.LabelFrame(tab, text="Recent Threats", padding=10)
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for threats
        columns = ('Time', 'Source', 'Destination', 'Type', 'Severity')
        self.threats_tree = ttk.Treeview(threats_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_scanner_tab(self):
        """Create network scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Network Scanner")
        
        # Target input
        input_frame = ttk.LabelFrame(tab, text="Target Configuration", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.scan_target = ttk.Entry(input_frame, width=30)
        self.scan_target.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Ports:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.scan_ports = ttk.Entry(input_frame, width=15)
        self.scan_ports.grid(row=0, column=3, padx=5, pady=5)
        self.scan_ports.insert(0, "1-1000")
        
        # Scan buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        buttons = [
            ("Ping Sweep", self.run_ping_sweep),
            ("Port Scan", self.run_port_scan),
            ("Vulnerability Scan", self.run_vuln_scan),
            ("Traceroute", self.run_traceroute),
            ("Get Info", self.run_ip_info)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(button_frame, text=text, command=command).grid(
                row=0, column=i, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(tab, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.scan_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.scan_results.pack(fill=tk.BOTH, expand=True)
    
    def create_monitor_tab(self):
        """Create network monitor tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Network Monitor")
        
        # Monitor controls
        control_frame = ttk.LabelFrame(tab, text="Monitoring Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.monitor_interface = ttk.Entry(control_frame, width=20)
        self.monitor_interface.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.monitor_filter = ttk.Entry(control_frame, width=30)
        self.monitor_filter.grid(row=0, column=3, padx=5, pady=5)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        self.start_monitor_btn = ttk.Button(button_frame, text="Start Monitoring", 
                                          command=self.start_monitoring)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn = ttk.Button(button_frame, text="Stop Monitoring",
                                          command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        # Statistics display
        stats_frame = ttk.LabelFrame(tab, text="Real-time Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.monitor_stats = scrolledtext.ScrolledText(stats_frame, wrap=tk.WORD, height=15)
        self.monitor_stats.pack(fill=tk.BOTH, expand=True)
    
    def create_web_tools_tab(self):
        """Create web tools tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Web Tools")
        
        # URL input
        url_frame = ttk.LabelFrame(tab, text="URL Analysis", padding=10)
        url_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.web_url = ttk.Entry(url_frame, width=50)
        self.web_url.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Tool buttons
        tool_frame = ttk.Frame(url_frame)
        tool_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        tools = [
            ("HTTP Request", self.run_http_request),
            ("DNS Lookup", self.run_dns_lookup),
            ("WHOIS Lookup", self.run_whois_lookup)
        ]
        
        for i, (text, command) in enumerate(tools):
            ttk.Button(tool_frame, text=text, command=command).grid(
                row=0, column=i, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(tab, text="Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.web_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.web_results.pack(fill=tk.BOTH, expand=True)
    
    def create_traffic_tab(self):
        """Create traffic generation tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Traffic Generator")
        
        # Target configuration
        target_frame = ttk.LabelFrame(tab, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(target_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.traffic_target = ttk.Entry(target_frame, width=20)
        self.traffic_target.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.traffic_port = ttk.Entry(target_frame, width=10)
        self.traffic_port.grid(row=0, column=3, padx=5, pady=5)
        self.traffic_port.insert(0, "80")
        
        # Traffic types
        traffic_frame = ttk.LabelFrame(tab, text="Traffic Types", padding=10)
        traffic_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.traffic_buttons = {}
        traffic_types = [
            ("TCP SYN Flood", "syn"),
            ("UDP Flood", "udp"),
            ("ICMP Flood", "icmp")
        ]
        
        for i, (text, ttype) in enumerate(traffic_types):
            btn = ttk.Button(traffic_frame, text=text, 
                           command=lambda tt=ttype: self.start_traffic(tt))
            btn.grid(row=0, column=i, padx=10)
            self.traffic_buttons[ttype] = btn
        
        stop_btn = ttk.Button(traffic_frame, text="Stop All Traffic", 
                            command=self.stop_traffic)
        stop_btn.grid(row=0, column=3, padx=10)
        
        # Status display
        status_frame = ttk.LabelFrame(tab, text="Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.traffic_status = scrolledtext.ScrolledText(status_frame, wrap=tk.WORD, height=10)
        self.traffic_status.pack(fill=tk.BOTH, expand=True)
    
    def create_reports_tab(self):
        """Create reports tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Reports")
        
        # Report generation
        gen_frame = ttk.LabelFrame(tab, text="Generate Reports", padding=10)
        gen_frame.pack(fill=tk.X, padx=10, pady=5)
        
        report_types = [
            ("Threat Report", self.generate_threat_report),
            ("Network Report", self.generate_network_report),
            ("Full Security Report", self.generate_full_report)
        ]
        
        for i, (text, command) in enumerate(report_types):
            ttk.Button(gen_frame, text=text, command=command).grid(
                row=0, column=i, padx=10, pady=5)
        
        # Report display
        display_frame = ttk.LabelFrame(tab, text="Generated Reports", padding=10)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.report_display = scrolledtext.ScrolledText(display_frame, wrap=tk.WORD)
        self.report_display.pack(fill=tk.BOTH, expand=True)
    
    def apply_theme(self):
        """Apply current theme"""
        theme = THEMES[self.current_theme]
        
        style = ttk.Style()
        
        # Configure colors
        colors = [
            ('TFrame', 'background', theme['bg']),
            ('TLabel', 'background', theme['bg']),
            ('TLabel', 'foreground', theme['fg']),
            ('TLabelframe', 'background', theme['bg']),
            ('TLabelframe.Label', 'background', theme['bg']),
            ('TLabelframe.Label', 'foreground', theme['fg'])
        ]
        
        for element, property_name, color in colors:
            style.configure(element, **{property_name: color})
    
    def change_theme(self, theme_name):
        """Change GUI theme"""
        if theme_name in THEMES:
            self.current_theme = theme_name
            self.apply_theme()
    
    def update_dashboard(self):
        """Update dashboard information"""
        try:
            # Update system status
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            self.status_labels['cpu'].config(text=f"{cpu}%")
            self.status_labels['memory'].config(text=f"{mem.percent}%")
            self.status_labels['disk'].config(text=f"{disk.percent}%")
            
            # Update monitoring status
            stats = self.monitor.get_stats()
            if stats['status'] == 'active':
                self.status_labels['monitoring'].config(text="Active")
                self.status_labels['network'].config(
                    text=f"{stats['packet_rate']:.1f}/s")
            else:
                self.status_labels['monitoring'].config(text="Inactive")
                self.status_labels['network'].config(text="N/A")
            
            # Update threat count
            db_stats = self.db.get_statistics()
            self.status_labels['threats'].config(
                text=str(db_stats['threats']['total']))
            
            # Update threats tree
            self.update_threats_tree()
            
            # Update monitor stats if active
            if stats['status'] == 'active':
                self.update_monitor_stats(stats)
            
        except Exception as e:
            self.logger.error(f"Dashboard update error: {e}")
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)
    
    def update_threats_tree(self):
        """Update threats treeview"""
        # Clear current items
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Get recent threats
        threats = self.db.get_recent_intrusions(limit=20)
        
        # Add to treeview
        for threat in threats:
            self.threats_tree.insert('', 'end', values=(
                threat['timestamp'][11:19],  # Time only
                threat['source_ip'],
                threat['dest_ip'] or '',
                threat['threat_type'],
                threat['severity']
            ))
    
    def update_monitor_stats(self, stats):
        """Update monitor statistics display"""
        self.monitor_stats.delete(1.0, tk.END)
        
        stats_text = f"Monitoring Status: {stats['status'].upper()}\n"
        stats_text += f"Uptime: {stats['uptime']:.0f} seconds\n"
        stats_text += f"Total Packets: {stats['total_packets']:,}\n"
        stats_text += f"Packet Rate: {stats['packet_rate']:.1f}/s\n"
        stats_text += f"TCP Packets: {stats['tcp_packets']:,}\n"
        stats_text += f"UDP Packets: {stats['udp_packets']:,}\n"
        stats_text += f"ICMP Packets: {stats['icmp_packets']:,}\n"
        stats_text += f"Threats Detected: {stats['threats_detected']}\n"
        stats_text += f"Bandwidth In: {stats['bandwidth_in']/1024:.1f} KB\n"
        stats_text += f"Bandwidth Out: {stats['bandwidth_out']/1024:.1f} KB\n"
        
        self.monitor_stats.insert(1.0, stats_text)
    
    def run_ping_sweep(self):
        """Run ping sweep"""
        target = self.scan_target.get().strip()
        if not target:
            self.show_error("Please enter a target network")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Running ping sweep on {target}...\n")
        
        def run_scan():
            hosts = self.scanner.ping_sweep(target)
            self.scan_results.insert(tk.END, f"\nFound {len(hosts)} hosts:\n")
            for host in hosts:
                if host['alive']:
                    self.scan_results.insert(tk.END, 
                        f"  {host['ip']} - {host['response_time']}ms\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_port_scan(self):
        """Run port scan"""
        target = self.scan_target.get().strip()
        ports = self.scan_ports.get().strip()
        
        if not target:
            self.show_error("Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Scanning {target} ports {ports}...\n")
        
        def run_scan():
            result = self.scanner.port_scan(target, ports)
            if result['success']:
                self.scan_results.insert(tk.END, f"\nOpen ports on {target}:\n")
                for port in result['open_ports']:
                    self.scan_results.insert(tk.END,
                        f"  {port['port']}/tcp - {port['service']}\n")
            else:
                self.scan_results.insert(tk.END, f"\nError: {result.get('error')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_vuln_scan(self):
        """Run vulnerability scan"""
        target = self.scan_target.get().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        if not NMAP_AVAILABLE:
            self.show_error("Nmap not available")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Scanning {target} for vulnerabilities...\n")
        
        def run_scan():
            result = self.scanner.vulnerability_scan(target)
            if result['success']:
                vulns = result.get('vulnerabilities', [])
                self.scan_results.insert(tk.END, f"\nVulnerabilities found: {len(vulns)}\n")
                for vuln in vulns[:20]:  # Limit display
                    self.scan_results.insert(tk.END, f"  • {vuln}\n")
            else:
                self.scan_results.insert(tk.END, f"\nError: {result.get('error')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_traceroute(self):
        """Run traceroute"""
        target = self.scan_target.get().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Traceroute to {target}...\n")
        
        def run_trace():
            result = self.scanner.traceroute.perform_traceroute(target)
            if result['success']:
                self.scan_results.insert(tk.END, f"\nTraceroute completed:\n")
                for hop in result['hops']:
                    self.scan_results.insert(tk.END,
                        f"  {hop['hop']:>3}  {hop['host']:30}  {hop.get('rtt', 'N/A'):10}\n")
            else:
                self.scan_results.insert(tk.END, f"\nError: {result.get('error')}\n")
            self.scan_results.see(tk.END)
        
        threading.Thread(target=run_trace, daemon=True).start()
    
    def run_ip_info(self):
        """Get IP information"""
        target = self.scan_target.get().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Getting information for {target}...\n")
        
        def get_info():
            info = self.scanner.get_ip_info(target)
            self.scan_results.insert(tk.END, f"\nInformation for {target}:\n")
            
            if 'country' in info:
                self.scan_results.insert(tk.END, f"  Location: {info.get('city', 'N/A')}, {info.get('country', 'N/A')}\n")
                self.scan_results.insert(tk.END, f"  ISP: {info.get('isp', 'N/A')}\n")
                self.scan_results.insert(tk.END, f"  Organization: {info.get('org', 'N/A')}\n")
            
            if info.get('hostname'):
                self.scan_results.insert(tk.END, f"  Hostname: {info['hostname']}\n")
            
            if info.get('threat_info', {}).get('is_malicious'):
                self.scan_results.insert(tk.END, "  ⚠️  This IP is flagged as malicious\n")
            
            self.scan_results.see(tk.END)
        
        threading.Thread(target=get_info, daemon=True).start()
    
    def start_monitoring(self):
        """Start network monitoring"""
        interface = self.monitor_interface.get().strip() or None
        capture_filter = self.monitor_filter.get().strip() or None
        
        if self.monitor.start(interface=interface, capture_filter=capture_filter):
            self.start_monitor_btn.config(state=tk.DISABLED)
            self.stop_monitor_btn.config(state=tk.NORMAL)
            self.log_message("Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitor.stop()
        self.start_monitor_btn.config(state=tk.NORMAL)
        self.stop_monitor_btn.config(state=tk.DISABLED)
        self.log_message("Network monitoring stopped")
    
    def run_http_request(self):
        """Run HTTP request"""
        url = self.web_url.get().strip()
        if not url:
            self.show_error("Please enter a URL")
            return
        
        self.web_results.delete(1.0, tk.END)
        self.web_results.insert(tk.END, f"Requesting {url}...\n")
        
        def run_request():
            result = self.web_tools.http_request(url)
            
            self.web_results.insert(tk.END, f"\nHTTP Response:\n")
            self.web_results.insert(tk.END, f"  Status: {result.get('status_code')} {result.get('reason')}\n")
            self.web_results.insert(tk.END, f"  Time: {result.get('elapsed', 0):.3f}s\n")
            self.web_results.insert(tk.END, f"  Final URL: {result.get('final_url')}\n")
            
            if 'security_headers' in result:
                self.web_results.insert(tk.END, f"\nSecurity Headers:\n")
                for check, info in result['security_headers'].items():
                    status = "✓" if info['present'] else "✗"
                    self.web_results.insert(tk.END, 
                        f"  {status} {info['header']}: {info.get('value', 'Missing')}\n")
            
            self.web_results.see(tk.END)
        
        threading.Thread(target=run_request, daemon=True).start()
    
    def run_dns_lookup(self):
        """Run DNS lookup"""
        domain = self.web_url.get().strip()
        if not domain:
            self.show_error("Please enter a domain")
            return
        
        self.web_results.delete(1.0, tk.END)
        self.web_results.insert(tk.END, f"DNS lookup for {domain}...\n")
        
        def run_lookup():
            result = self.web_tools.dns_lookup(domain)
            
            if result['success']:
                self.web_results.insert(tk.END, f"\nDNS Results:\n")
                if 'addresses' in result:
                    for addr in result['addresses']:
                        self.web_results.insert(tk.END, f"  {addr}\n")
            else:
                self.web_results.insert(tk.END, f"\nError: {result.get('error')}\n")
            
            self.web_results.see(tk.END)
        
        threading.Thread(target=run_lookup, daemon=True).start()
    
    def run_whois_lookup(self):
        """Run WHOIS lookup"""
        domain = self.web_url.get().strip()
        if not domain:
            self.show_error("Please enter a domain")
            return
        
        self.web_results.delete(1.0, tk.END)
        self.web_results.insert(tk.END, f"WHOIS lookup for {domain}...\n")
        
        def run_lookup():
            result = self.web_tools.whois_lookup(domain)
            
            if result['success']:
                self.web_results.insert(tk.END, f"\nWHOIS Results:\n")
                if 'parsed' in result:
                    for key, value in result['parsed'].items():
                        self.web_results.insert(tk.END, f"  {key}: {value}\n")
            else:
                self.web_results.insert(tk.END, f"\nError: {result.get('error')}\n")
            
            self.web_results.see(tk.END)
        
        threading.Thread(target=run_lookup, daemon=True).start()
    
    def start_traffic(self, traffic_type):
        """Start traffic generation"""
        target = self.traffic_target.get().strip()
        if not target:
            self.show_error("Please enter a target IP")
            return
        
        port_text = self.traffic_port.get().strip()
        try:
            port = int(port_text)
        except ValueError:
            self.show_error("Invalid port number")
            return
        
        self.traffic_status.delete(1.0, tk.END)
        
        if traffic_type == 'syn':
            self.traffic_gen.generate_tcp_syn(target, port)
            self.traffic_status.insert(tk.END, f"Started TCP SYN flood to {target}:{port}\n")
        elif traffic_type == 'udp':
            self.traffic_gen.generate_udp_flood(target, port)
            self.traffic_status.insert(tk.END, f"Started UDP flood to {target}:{port}\n")
        elif traffic_type == 'icmp':
            self.traffic_gen.generate_icmp_flood(target)
            self.traffic_status.insert(tk.END, f"Started ICMP flood to {target}\n")
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.traffic_gen.stop()
        self.traffic_status.insert(tk.END, "All traffic generation stopped\n")
    
    def generate_threat_report(self):
        """Generate threat report"""
        threats = self.db.get_recent_intrusions(limit=100, hours=24)
        
        self.report_display.delete(1.0, tk.END)
        self.report_display.insert(tk.END, "THREAT REPORT - Last 24 hours\n")
        self.report_display.insert(tk.END, "="*50 + "\n\n")
        
        if not threats:
            self.report_display.insert(tk.END, "No threats detected in this period.\n")
        else:
            self.report_display.insert(tk.END, f"Total threats: {len(threats)}\n\n")
            
            # Group by threat type
            threats_by_type = {}
            for threat in threats:
                ttype = threat['threat_type']
                if ttype not in threats_by_type:
                    threats_by_type[ttype] = []
                threats_by_type[ttype].append(threat)
            
            for ttype, type_threats in threats_by_type.items():
                self.report_display.insert(tk.END, f"{ttype.upper()} ({len(type_threats)}):\n")
                self.report_display.insert(tk.END, "-"*30 + "\n")
                
                for threat in type_threats[:10]:
                    self.report_display.insert(tk.END, 
                        f"  {threat['timestamp']} - {threat['source_ip']}")
                    if threat['dest_ip']:
                        self.report_display.insert(tk.END, f" → {threat['dest_ip']}")
                    self.report_display.insert(tk.END, f" - {threat['severity']}\n")
                    if threat['description']:
                        self.report_display.insert(tk.END, f"    {threat['description']}\n")
        
        self.log_message("Threat report generated")
    
    def generate_network_report(self):
        """Generate network report"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:00', timestamp) as hour,
                SUM(packets_processed) as packets,
                AVG(packet_rate) as avg_rate,
                SUM(threat_count) as threats
            FROM network_stats 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY strftime('%Y-%m-%d %H:00', timestamp)
            ORDER BY hour
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        self.report_display.delete(1.0, tk.END)
        self.report_display.insert(tk.END, "NETWORK REPORT - Last 24 hours\n")
        self.report_display.insert(tk.END, "="*50 + "\n\n")
        
        if not results:
            self.report_display.insert(tk.END, "No network data in this period.\n")
        else:
            total_packets = sum(row[1] for row in results)
            total_threats = sum(row[3] for row in results)
            
            self.report_display.insert(tk.END, f"Total packets: {total_packets:,}\n")
            self.report_display.insert(tk.END, f"Total threats detected: {total_threats}\n\n")
            
            self.report_display.insert(tk.END, "Hourly Breakdown:\n")
            self.report_display.insert(tk.END, "Hour               Packets    Avg Rate  Threats\n")
            self.report_display.insert(tk.END, "-"*50 + "\n")
            
            for row in results:
                self.report_display.insert(tk.END,
                    f"{row[0]:<18} {row[1]:>9,} {row[2]:>10.1f}/s {row[3]:>7}\n")
        
        self.log_message("Network report generated")
    
    def generate_full_report(self):
        """Generate full report"""
        self.generate_threat_report()
        threat_report = self.report_display.get(1.0, tk.END)
        
        self.generate_network_report()
        network_report = self.report_display.get(1.0, tk.END)
        
        self.report_display.delete(1.0, tk.END)
        self.report_display.insert(tk.END, "FULL SECURITY REPORT\n")
        self.report_display.insert(tk.END, "="*60 + "\n\n")
        
        # Add system info
        self.report_display.insert(tk.END, "SYSTEM INFORMATION\n")
        self.report_display.insert(tk.END, "-"*30 + "\n")
        self.report_display.insert(tk.END, f"Report Time: {datetime.now()}\n")
        self.report_display.insert(tk.END, f"Hostname: {socket.gethostname()}\n")
        self.report_display.insert(tk.END, f"OS: {platform.system()} {platform.release()}\n\n")
        
        # Add reports
        self.report_display.insert(tk.END, network_report + "\n")
        self.report_display.insert(tk.END, threat_report)
        
        self.log_message("Full security report generated")
    
    def new_session(self):
        """Create new session"""
        if messagebox.askyesno("New Session", "Start a new monitoring session?"):
            self.monitor.stop()
            self.traffic_gen.stop()
            self.log_message("New session started")
    
    def save_session(self):
        """Save current session"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                session_data = {
                    'scan_target': self.scan_target.get(),
                    'scan_ports': self.scan_ports.get(),
                    'web_url': self.web_url.get(),
                    'traffic_target': self.traffic_target.get(),
                    'traffic_port': self.traffic_port.get(),
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(file_path, 'w') as f:
                    json.dump(session_data, f, indent=4)
                
                self.log_message(f"Session saved to {file_path}")
            except Exception as e:
                self.show_error(f"Failed to save session: {e}")
    
    def load_session(self):
        """Load saved session"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    session_data = json.load(f)
                
                self.scan_target.delete(0, tk.END)
                self.scan_target.insert(0, session_data.get('scan_target', ''))
                
                self.scan_ports.delete(0, tk.END)
                self.scan_ports.insert(0, session_data.get('scan_ports', '1-1000'))
                
                self.web_url.delete(0, tk.END)
                self.web_url.insert(0, session_data.get('web_url', ''))
                
                self.traffic_target.delete(0, tk.END)
                self.traffic_target.insert(0, session_data.get('traffic_target', ''))
                
                self.traffic_port.delete(0, tk.END)
                self.traffic_port.insert(0, session_data.get('traffic_port', '80'))
                
                self.log_message(f"Session loaded from {file_path}")
            except Exception as e:
                self.show_error(f"Failed to load session: {e}")
    
    def backup_database(self):
        """Backup database"""
        backup_file = self.db.backup_database()
        if backup_file:
            self.log_message(f"Database backed up to {backup_file}")
        else:
            self.show_error("Database backup failed")
    
    def open_terminal(self):
        """Open terminal interface"""
        def run_terminal():
            terminal = TerminalInterface(
                self.scanner, self.monitor, self.web_tools, self.traffic_gen
            )
            terminal.run()
        
        threading.Thread(target=run_terminal, daemon=True).start()
    
    def log_message(self, message: str):
        """Log message to status"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.traffic_status.insert(tk.END, f"[{timestamp}] {message}\n")
        self.traffic_status.see(tk.END)
    
    def show_error(self, message: str):
        """Show error message"""
        messagebox.showerror("Error", message)

class TelegramBotHandler:
    """Telegram bot integration"""
    
    def __init__(self, db_manager: DatabaseManager, 
                 scanner: EnhancedNetworkScanner,
                 monitor: NetworkMonitor,
                 web_tools: WebToolsSuite):
        self.db = db_manager
        self.scanner = scanner
        self.monitor = monitor
        self.web_tools = web_tools
        self.logger = EnhancedLogger("TelegramBot")
        
        self.telegram_token = None
        self.telegram_chat_id = None
        self.load_config()
    
    def load_config(self):
        """Load Telegram configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
        except Exception as e:
            self.logger.error(f"Config load error: {e}")
    
    def send_message(self, message: str) -> bool:
        """Send message via Telegram"""
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=30)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Telegram send error: {e}")
            return False
    
    def send_alert(self, threat_info: Dict):
        """Send threat alert"""
        message = f"🚨 <b>THREAT DETECTED</b>\n\n"
        message += f"Type: {threat_info.get('type')}\n"
        message += f"Source: {threat_info.get('source')}\n"
        message += f"Severity: {threat_info.get('severity')}\n"
        message += f"Description: {threat_info.get('description')}\n"
        
        self.send_message(message)

class AccurateCyberDefense:
    """Main application class"""
    
    def __init__(self):
        self.logger = EnhancedLogger("Main")
        self.setup_directories()
        self.print_banner()
        
        # Initialize core components
        self.db = DatabaseManager()
        self.scanner = EnhancedNetworkScanner(self.db)
        self.monitor = NetworkMonitor(self.db)
        self.web_tools = WebToolsSuite(self.db)
        self.traffic_gen = TrafficGenerator(self.db)
        self.telegram_bot = TelegramBotHandler(
            self.db, self.scanner, self.monitor, self.web_tools
        )
        
        # Check dependencies
        self.check_dependencies()
    
    def setup_directories(self):
        """Setup required directories"""
        for directory in [REPORT_DIR, LOG_DIR, CACHE_DIR, BACKUP_DIR]:
            os.makedirs(directory, exist_ok=True)
    
    def print_banner(self):
        """Print application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║          🛡️  ACCURATE CYBER DEFENSE SUITE v2.0 🛡️                   ║
║                                                                      ║
║      Network Security Monitoring • Intrusion Detection System        ║
║      Advanced Scanning • Traffic Analysis • Threat Intelligence      ║
║                                                                      ║
║   Version: 2.0.1                  Author: Ian Carter Kulani          ║
║   Community: https://github.com/Accurate-Cyber-Defense               ║
║                                                                      ║
║   Features:                                                          ║
║   • Real-time Network Monitoring & Threat Detection                  ║
║   • Advanced Port & Vulnerability Scanning                           ║
║   • Web Security Testing & Analysis                                  ║
║   • Network Traffic Generation & Testing                             ║
║   • Comprehensive Reporting & Logging                                ║
║   • GUI & CLI Interfaces                                             ║
║   • Telegram Integration for Alerts                                  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def check_dependencies(self):
        """Check required dependencies"""
        self.logger.info("Checking dependencies...")
        
        missing_deps = []
        
        if not NMAP_AVAILABLE:
            missing_deps.append("python-nmap (for advanced scanning)")
        
        if not SCAPY_AVAILABLE:
            missing_deps.append("scapy (for packet manipulation)")
        
        if not GUI_AVAILABLE:
            missing_deps.append("tkinter (for GUI interface)")
        
        if missing_deps:
            self.logger.warning("Missing optional dependencies:")
            for dep in missing_deps:
                self.logger.warning(f"  - {dep}")
            self.logger.warning("Some features may be limited.")
        
        # Check for required system tools
        required_tools = ['ping', 'traceroute', 'whois']
        for tool in required_tools:
            if not shutil.which(tool):
                self.logger.warning(f"System tool '{tool}' not found in PATH")
    
    def run_gui(self):
        """Run graphical user interface"""
        if not GUI_AVAILABLE:
            self.logger.error("GUI not available. Please install tkinter.")
            return
        
        try:
            root = tk.Tk()
            app = GUIInterface(root)
            
            def on_closing():
                self.monitor.stop()
                self.traffic_gen.stop()
                root.quit()
                root.destroy()
            
            root.protocol("WM_DELETE_WINDOW", on_closing)
            root.mainloop()
            
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            print(f"Failed to start GUI: {e}")
            print("Falling back to terminal mode...")
            self.run_terminal()
    
    def run_terminal(self):
        """Run terminal interface"""
        terminal = TerminalInterface(
            self.scanner, self.monitor, self.web_tools, self.traffic_gen
        )
        terminal.run()
    
    def run(self, mode: str = None):
        """Run the application in specified mode"""
        if not mode:
            # Interactive mode selection
            print("\nSelect mode:")
            print("  1. GUI Mode (Graphical Interface)")
            print("  2. Terminal Mode (Command Line)")
            print("  3. Exit")
            
            while True:
                choice = input("\nSelect mode (1-3): ").strip()
                if choice == '1':
                    mode = 'gui'
                    break
                elif choice == '2':
                    mode = 'terminal'
                    break
                elif choice == '3':
                    print("👋 Thank you for using Accurate Cyber Defense!")
                    return
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
        
        if mode.lower() == 'gui':
            self.run_gui()
        elif mode.lower() == 'terminal':
            self.run_terminal()
        else:
            print(f"Unknown mode: {mode}")
            self.run_terminal()

def main():
    """Main entry point"""
    try:
        # Parse command line arguments
        mode = None
        if len(sys.argv) > 1:
            if sys.argv[1] in ['--gui', '-g']:
                mode = 'gui'
            elif sys.argv[1] in ['--terminal', '-t', '--cli']:
                mode = 'terminal'
            elif sys.argv[1] in ['--help', '-h']:
                print("Usage: python accurate_cyber_defense.py [OPTION]")
                print("\nOptions:")
                print("  --gui, -g      Start in GUI mode")
                print("  --terminal, -t Start in terminal mode")
                print("  --help, -h     Show this help message")
                return
        
        # Create and run application
        app = AccurateCyberDefense()
        app.run(mode)
        
    except KeyboardInterrupt:
        print("\n\n👋 Thank you for using Accurate Cyber Defense!")
    except Exception as e:
        print(f"❌ Application error: {e}")
        logging.error(f"Application crash: {e}", exc_info=True)

if __name__ == "__main__":
    main()