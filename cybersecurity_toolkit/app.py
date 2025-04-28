from flask import Flask, render_template, request, jsonify
import socket
import ssl
import hashlib
import platform
import psutil
import dns.resolver
import whois
import json
from datetime import datetime
import os
import re
import struct
import threading
import time

app = Flask(__name__)

# System Information Gatherer
def get_system_info():
    try:
        system_info = {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_connections": len(psutil.net_connections()),
            "running_processes": len(psutil.pids())
        }
        return system_info
    except Exception as e:
        return {"error": str(e)}

# Malware Scanner
def scan_file(file_path):
    try:
        results = {
            "file_info": {},
            "hash_analysis": {},
            "pattern_analysis": {}
        }
        
        # File information
        file_stats = os.stat(file_path)
        results["file_info"] = {
            "size": file_stats.st_size,
            "created": datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            "modified": datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Hash analysis
        with open(file_path, 'rb') as f:
            file_content = f.read()
            results["hash_analysis"] = {
                "md5": hashlib.md5(file_content).hexdigest(),
                "sha1": hashlib.sha1(file_content).hexdigest(),
                "sha256": hashlib.sha256(file_content).hexdigest()
            }
        
        # Pattern analysis
        suspicious_patterns = [
            r"eval\s*\(",
            r"base64_decode\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"shell_exec\s*\("
        ]
        
        pattern_matches = {}
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, file_content.decode('utf-8', errors='ignore'))
            if matches:
                pattern_matches[pattern] = len(matches)
        
        results["pattern_analysis"] = pattern_matches
        return results
    except Exception as e:
        return {"error": str(e)}

# Network Packet Sniffer
class PacketSniffer:
    def __init__(self):
        self.sniffing = False
        self.packets = []
        
    def start_sniffing(self, interface=None, count=10):
        try:
            self.sniffing = True
            self.packets = []
            
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            if interface:
                s.bind((interface, 0))
            
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            for _ in range(count):
                if not self.sniffing:
                    break
                    
                packet = s.recvfrom(65565)
                self.packets.append({
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "source": packet[1][0],
                    "data": packet[0].hex()
                })
                
            s.close()
            return self.packets
        except Exception as e:
            return {"error": str(e)}
    
    def stop_sniffing(self):
        self.sniffing = False

# DNS Resolver
def resolve_dns(domain):
    try:
        results = {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "whois": {}
        }
        
        # A Records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            results["a_records"] = [str(record) for record in a_records]
        except:
            pass
            
        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results["mx_records"] = [str(record) for record in mx_records]
        except:
            pass
            
        # NS Records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results["ns_records"] = [str(record) for record in ns_records]
        except:
            pass
            
        # TXT Records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results["txt_records"] = [str(record) for record in txt_records]
        except:
            pass
            
        # WHOIS
        try:
            w = whois.whois(domain)
            results["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except:
            pass
            
        return results
    except Exception as e:
        return {"error": str(e)}

# SSL/TLS Checker
def check_ssl(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                results = {
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert['version'],
                    "serialNumber": cert['serialNumber'],
                    "notBefore": cert['notBefore'],
                    "notAfter": cert['notAfter'],
                    "subjectAltName": cert.get('subjectAltName', []),
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()
                }
                
                return results
    except Exception as e:
        return {"error": str(e)}

# Port Scanner
def scan_ports(host, start_port=1, end_port=1024):
    try:
        open_ports = []
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports.append({
                    "port": port,
                    "service": service,
                    "status": "open"
                })
            sock.close()
        return open_ports
    except Exception as e:
        return {"error": str(e)}

# File Hash Generator
def generate_hashes(data, is_file=False):
    try:
        if is_file:
            with open(data, 'rb') as f:
                content = f.read()
        else:
            content = data.encode()
            
        return {
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "sha512": hashlib.sha512(content).hexdigest()
        }
    except Exception as e:
        return {"error": str(e)}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/system-info')
def system_info():
    return jsonify(get_system_info())

@app.route('/scan-file', methods=['POST'])
def scan_file_route():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"})
    
    temp_path = os.path.join('uploads', file.filename)
    file.save(temp_path)
    results = scan_file(temp_path)
    os.remove(temp_path)
    return jsonify(results)

@app.route('/start-sniffing', methods=['POST'])
def start_sniffing():
    data = request.json
    interface = data.get('interface')
    count = data.get('count', 10)
    sniffer = PacketSniffer()
    results = sniffer.start_sniffing(interface, count)
    return jsonify(results)

@app.route('/stop-sniffing', methods=['POST'])
def stop_sniffing():
    sniffer = PacketSniffer()
    sniffer.stop_sniffing()
    return jsonify({"status": "stopped"})

@app.route('/dns-resolve', methods=['POST'])
def dns_resolve():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "No domain provided"})
    return jsonify(resolve_dns(domain))

@app.route('/ssl-check', methods=['POST'])
def ssl_check():
    data = request.json
    domain = data.get('domain')
    port = data.get('port', 443)
    if not domain:
        return jsonify({"error": "No domain provided"})
    return jsonify(check_ssl(domain, port))

@app.route('/port-scan', methods=['POST'])
def port_scan():
    data = request.json
    host = data.get('host')
    start_port = data.get('start_port', 1)
    end_port = data.get('end_port', 1024)
    if not host:
        return jsonify({"error": "No host provided"})
    return jsonify(scan_ports(host, start_port, end_port))

@app.route('/generate-hash', methods=['POST'])
def generate_hash():
    data = request.json
    content = data.get('content')
    is_file = data.get('is_file', False)
    if not content:
        return jsonify({"error": "No content provided"})
    return jsonify(generate_hashes(content, is_file))

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True) 