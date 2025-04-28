from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, session
import requests
import json
import pandas as pd
import re
import os
import hashlib
from werkzeug.utils import secure_filename
import base64
import time
import codecs
import csv
import io
import math
from collections import Counter
import urllib.parse
import html
from datetime import datetime
import sys
sys.path.append('threatintelligenceplatform')
from threatintelligenceplatform.app import app as threat_app
from threatintelligenceplatform.threat_intelligence import threat_bp
import platform
import psutil
import socket
import ssl
import dns
import whois

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Set a secret key for session management

# Register the threat intelligence blueprint
app.register_blueprint(threat_bp)

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# List of VirusTotal API keys (add multiple keys here)
API_KEYS = [
    "ddf12f573c2891adcaab881ddb75079bf3aa3141c4c9eb165794e523167fc071",
    "1a628d053b9cdb10169de5bb0fb6f1f83e05d972788a43763c54ceb22fbce659",
    "8d6b76c60f21fdf378efc21d390e3615699b4cff3d59d8ccf2f1a4c8dcdfe680",
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507"
]

# Dictionary to track API usage per key with timestamp
api_usage = {
    key: {
        'count': 0,
        'last_reset': datetime.now(),
        'daily_limit': 500,
        'rate_limit_reset': None,
        'is_valid': None,
        'validation_message': None,
        'last_request_time': None,
        'min_request_interval': 30,  # Increased to 30 seconds
        'consecutive_failures': 0,
        'last_failure_time': None
    } for key in API_KEYS
}

# Threat Intelligence Platform API Configuration
THREAT_API_KEY = "at_rY2D12FSf75R5RSlLAIHZrS3Az1US"
THREAT_BASE_URL_V1 = "https://api.threatintelligenceplatform.com/v1/"
THREAT_BASE_URL_V2 = "https://api.threatintelligenceplatform.com/v2/"

def get_available_api_key():
    for key in API_KEYS:
        if api_usage[key]['count'] < api_usage[key]['daily_limit']:  # Daily limit per key
            return key
    return None

def check_hash(hash_value):
    api_key = get_available_api_key()
    if not api_key:
        return {"error": "API limit reached for all keys"}
    
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        api_usage[api_key]['count'] += 1
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            return {
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "filename": attributes.get("meaningful_name", attributes.get("name", "Unknown")),
                "details": attributes.get("last_analysis_results", {})
            }
        else:
            return {"error": f"API request failed with status code {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_ip(ip_address):
    api_key = get_available_api_key()
    if not api_key:
        return {"error": "API limit reached for all keys"}
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        api_usage[api_key]['count'] += 1
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            # Extract AS owner and country information
            as_owner = attributes.get("as_owner", "Unknown")
            country = attributes.get("country", "Unknown")
            
            # If as_owner is not available, try to get it from network information
            if as_owner == "Unknown" and "network" in attributes:
                as_owner = attributes.get("network", {}).get("as_owner", "Unknown")
            
            return {
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "as_owner": as_owner,
                "country": country,
                "details": attributes.get("last_analysis_results", {})
            }
        else:
            return {"error": f"API request failed with status code {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def extract_ips(text):
    # More precise IP pattern that validates each octet
    ip_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # Find all matches and remove duplicates while preserving order
    matches = re.findall(ip_pattern, text)
    seen = set()
    unique_ips = []
    for ip in matches:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    
    return unique_ips

def read_ips_from_file(file_path):
    try:
        df = pd.read_excel(file_path)
        ips = []
        for column in df.columns:
            ips.extend(extract_ips(df[column].astype(str)))
        return ips
    except Exception as e:
        return []

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to encode URL in base64 (as required by VirusTotal)
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# Function to check URL reputation
def check_url(url):
    api_key = get_available_api_key()
    if not api_key:
        return {"url": url, "status": "Error", "malicious": 0, "suspicious": 0, "harmless": 0, "details": "API Limit Exceeded"}

    # Clean the URL if needed
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    url_vt = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-apikey": api_key}
    data = {"url": url}

    try:
        # First, submit the URL for scanning
        response = requests.post(url_vt, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            url_id = result["data"]["id"]
            
            # Wait a moment for the scan to complete
            time.sleep(2)
            
            # Fetch detailed report using the URL ID
            report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            report_response = requests.get(report_url, headers=headers)
            
            if report_response.status_code == 200:
                data = report_response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("stats", {})
                
                api_usage[api_key]['count'] += 1
                
                # Extract more detailed information
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
                # Get the title or category if available
                title = attributes.get("title", "Unknown")
                if title == "Unknown":
                    title = attributes.get("categories", ["Unknown"])[0] if attributes.get("categories") else "Unknown"
                
                # Determine reputation status
                status = "Safe"
                if malicious > 0:
                    status = "Malicious"
                elif suspicious > 0:
                    status = "Suspicious"
                elif harmless > 0:
                    status = "Safe"
                else:
                    status = "Unknown"
                
                return {
                    "url": url,
                    "status": status,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "details": title
                }
            else:
                # Try to get more information from the error response
                error_details = "Unknown error"
                try:
                    error_data = report_response.json()
                    error_details = error_data.get("error", {}).get("message", "Unknown error")
                except:
                    error_details = f"HTTP {report_response.status_code}"
                
                return {
                    "url": url, 
                    "status": "Error", 
                    "malicious": 0, 
                    "suspicious": 0, 
                    "harmless": 0, 
                    "details": f"Failed to get report: {error_details}"
                }
        else:
            # Try to get more information from the error response
            error_details = "Unknown error"
            try:
                error_data = response.json()
                error_details = error_data.get("error", {}).get("message", "Unknown error")
            except:
                error_details = f"HTTP {response.status_code}"
            
            return {
                "url": url, 
                "status": "Error", 
                "malicious": 0, 
                "suspicious": 0, 
                "harmless": 0, 
                "details": f"Failed to submit URL: {error_details}"
            }
    except Exception as e:
        return {
            "url": url, 
            "status": "Error", 
            "malicious": 0, 
            "suspicious": 0, 
            "harmless": 0, 
            "details": f"Exception: {str(e)}"
        }

    return {
        "url": url, 
        "status": "Error", 
        "malicious": 0, 
        "suspicious": 0, 
        "harmless": 0, 
        "details": "Not Found"
    }

# CyberChef functions
def process_cyberchef_operation(operation, data):
    """Process a single operation on the input data"""
    try:
        if operation == 'base64-encode':
            return base64.b64encode(data.encode('utf-8')).decode('utf-8')
        elif operation == 'base64-decode':
            return base64.b64decode(data.encode('utf-8')).decode('utf-8')
        elif operation == 'url-encode':
            return urllib.parse.quote_plus(data)
        elif operation == 'url-decode':
            return urllib.parse.unquote_plus(data)
        elif operation == 'hex-encode':
            return data.encode('utf-8').hex()
        elif operation == 'hex-decode':
            return bytes.fromhex(data).decode('utf-8')
        elif operation == 'reverse':
            return data[::-1]
        elif operation == 'to-uppercase':
            return data.upper()
        elif operation == 'to-lowercase':
            return data.lower()
        elif operation == 'md5':
            return hashlib.md5(data.encode('utf-8')).hexdigest()
        elif operation == 'sha1':
            return hashlib.sha1(data.encode('utf-8')).hexdigest()
        elif operation == 'sha256':
            return hashlib.sha256(data.encode('utf-8')).hexdigest()
        elif operation == 'rot13':
            return codecs.encode(data, 'rot_13')
        elif operation == 'binary-encode':
            return ' '.join(format(ord(c), '08b') for c in data)
        elif operation == 'binary-decode':
            return ''.join(chr(int(b, 2)) for b in data.split())
        elif operation == 'json-prettify':
            return json.dumps(json.loads(data), indent=2)
        elif operation == 'json-minify':
            return json.dumps(json.loads(data), separators=(',', ':'))
        elif operation == 'html-encode':
            return html.escape(data)
        elif operation == 'html-decode':
            return html.unescape(data)
        elif operation == 'csv-to-json':
            csv_data = csv.DictReader(io.StringIO(data))
            return json.dumps([row for row in csv_data], indent=2)
        elif operation == 'text-stats':
            chars = len(data)
            words = len(data.split())
            lines = len(data.splitlines()) or 1
            return json.dumps({
                'characters': chars,
                'words': words,
                'lines': lines
            }, indent=2)
        else:
            raise ValueError(f"Unknown operation: {operation}")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format")
    except csv.Error:
        raise ValueError("Invalid CSV format")
    except Exception as e:
        raise ValueError(f"Operation failed: {str(e)}")

def calculate_entropy(data):
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy

# CyberChef routes
@app.route('/cyberchef')
def cyberchef():
    return send_from_directory('Cyberchef/static', 'index.html')

@app.route('/cyberchef/operations', methods=['GET'])
def get_cyberchef_operations():
    """Return list of available operations"""
    operations = [
        {'id': 'base64-encode', 'name': 'Base64 Encode'},
        {'id': 'base64-decode', 'name': 'Base64 Decode'},
        {'id': 'url-encode', 'name': 'URL Encode'},
        {'id': 'url-decode', 'name': 'URL Decode'},
        {'id': 'hex-encode', 'name': 'Hex Encode'},
        {'id': 'hex-decode', 'name': 'Hex Decode'},
        {'id': 'reverse', 'name': 'Reverse'},
        {'id': 'to-uppercase', 'name': 'To Uppercase'},
        {'id': 'to-lowercase', 'name': 'To Lowercase'},
        {'id': 'md5', 'name': 'MD5 Hash'},
        {'id': 'sha1', 'name': 'SHA-1 Hash'},
        {'id': 'sha256', 'name': 'SHA-256 Hash'},
        {'id': 'rot13', 'name': 'ROT13 Cipher'},
        {'id': 'binary-encode', 'name': 'Binary Encode'},
        {'id': 'binary-decode', 'name': 'Binary Decode'},
        {'id': 'json-prettify', 'name': 'JSON Prettify'},
        {'id': 'json-minify', 'name': 'JSON Minify'},
        {'id': 'html-encode', 'name': 'HTML Encode'},
        {'id': 'html-decode', 'name': 'HTML Decode'},
        {'id': 'csv-to-json', 'name': 'CSV to JSON'},
        {'id': 'text-stats', 'name': 'Text Statistics'}
    ]
    return jsonify(operations)

@app.route('/cyberchef/bake', methods=['POST'])
def cyberchef_bake():
    data = request.get_json()
    
    if not data or 'input' not in data or 'operations' not in data:
        return jsonify({'error': 'Invalid request format'}), 400
    
    input_data = data['input']
    operations = data['operations']
    
    result = input_data
    
    try:
        for operation in operations:
            result = process_cyberchef_operation(operation, result)
            
        return jsonify({'output': result})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/')
def index():
    return render_template('index.html', 
                         tools=[
                             {'name': 'Hash Checker', 'url': '/hash-checker'},
                             {'name': 'IP Checker', 'url': '/ip-checker'},
                             {'name': 'File Checker', 'url': '/file-checker'},
                             {'name': 'URL Checker', 'url': '/url-checker'},
                             {'name': 'CyberChef', 'url': '/cyberchef'},
                             {'name': 'OWASP Calculator', 'url': '/owasp-calculator'},
                             {'name': 'Log Analyzer', 'url': '/log-analyzer'},
                             {'name': 'Threat Intelligence', 'url': '/threat-intelligence'},
                             {'name': 'Cybersecurity Toolkit', 'url': '/cybersecurity-toolkit'}
                         ])

@app.route('/styles.css')
def serve_css():
    return send_from_directory('.', 'styles.css')

@app.route('/script.js')
def serve_js():
    return send_from_directory('.', 'script.js')

@app.route('/hash-checker')
def hash_checker():
    return render_template('hash-checker.html')

@app.route('/ip-checker')
def ip_checker():
    return render_template('ip-checker.html')

@app.route('/file-checker')
def file_checker():
    return render_template('file-checker.html')

@app.route('/url-checker')
def url_checker():
    return render_template('url-checker.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    if filename.startswith('hash-checker'):
        return send_from_directory('Hash Reputation Checker/static', filename)
    elif filename.startswith('ip-checker'):
        return send_from_directory('IP Reputation Checker/static', filename)
    elif filename.startswith('file-checker'):
        return send_from_directory('File Reputation Checker/static', filename)
    elif filename.startswith('owasp/'):
        return send_from_directory('static', filename)
    elif filename.startswith('cyberchef/'):
        return send_from_directory('Cyberchef/static', filename)
    elif filename.startswith('threatintelligenceplatform/'):
        return send_from_directory('threatintelligenceplatform/static', filename)
    return send_from_directory('static', filename)

@app.route('/process_hash', methods=['POST'])
def process_hash():
    input_text = request.form.get('input_text')
    if not input_text:
        return jsonify({"error": "No hash provided"})
    
    # Split the input by newlines and filter out empty lines
    hashes = [h.strip() for h in input_text.split('\n') if h.strip()]
    if not hashes:
        return jsonify({"error": "No valid hashes provided"})
    
    results = []
    for hash_value in hashes:
        result = check_hash(hash_value)
        if "error" not in result:
            result['hash'] = hash_value
        results.append(result)
    
    # Save results to Excel with timestamp
    if results:
        timestamp = int(time.time())
        filename = f'hash_scan_results_{timestamp}.xlsx'
        df = pd.DataFrame(results)
        df.to_excel(os.path.join(UPLOAD_FOLDER, filename), index=False)
        session['last_hash_scan_file'] = filename
    
    return jsonify(results)

@app.route('/process_ips', methods=['POST'])
def process_ips():
    try:
        app.logger.info('Received process_ips request')
        input_text = request.form.get('input_text', '').strip()
        app.logger.info(f'Input text: {input_text}')
        
        if not input_text:
            app.logger.info('No input text provided')
            return jsonify({'results': []})

        ip_list = extract_ips(input_text)
        app.logger.info(f'Extracted IPs: {ip_list}')
        
        if not ip_list:
            app.logger.info('No valid IPs found')
            return jsonify({'results': []})

        results = []
        for idx, ip in enumerate(ip_list, 1):
            app.logger.info(f'Processing IP {idx}: {ip}')
            result = check_ip(ip)
            app.logger.info(f'Result for IP {ip}: {result}')
            
            if isinstance(result, dict) and 'error' not in result:
                formatted_result = {
                    'id': idx,
                    'ip': ip,
                    'malicious': result.get('malicious', 0),
                    'suspicious': result.get('suspicious', 0),
                    'as_owner': result.get('as_owner', 'Unknown'),
                    'country': result.get('country', 'Unknown')
                }
                results.append(formatted_result)
                app.logger.info(f'Formatted result: {formatted_result}')

        # Save results to a unique file with timestamp
        if results:
            timestamp = int(time.time())
            filename = f'ip_scan_results_{timestamp}.xlsx'
            df = pd.DataFrame(results)
            df.to_excel(os.path.join(UPLOAD_FOLDER, filename), index=False)
            # Store the filename in session
            session['last_ip_scan_file'] = filename

        app.logger.info(f'Final results: {results}')
        response = {'results': results}
        app.logger.info(f'Sending response: {response}')
        return jsonify(response)
    except Exception as e:
        app.logger.error(f'Error in process_ips: {str(e)}')
        return jsonify({'results': []})

@app.route('/upload_ip', methods=['POST'])
def upload_ip():
    try:
        app.logger.info('Received upload_ip request')
        if 'file' not in request.files:
            app.logger.info('No file in request')
            return jsonify({'results': []})
            
        file = request.files['file']
        app.logger.info(f'Received file: {file.filename}')
        
        if file.filename == '':
            app.logger.info('Empty filename')
            return jsonify({'results': []})
            
        if not file.filename.endswith(('.txt', '.csv', '.xlsx', '.xls')):
            app.logger.info(f'Invalid file type: {file.filename}')
            return jsonify({'results': []})

        # Process the file based on its type
        if file.filename.endswith(('.xlsx', '.xls')):
            app.logger.info('Processing Excel file')
            # Save the uploaded Excel file temporarily
            file_path = os.path.join(UPLOAD_FOLDER, 'temp_upload.xlsx')
            file.save(file_path)
            try:
                # Read IPs from Excel file
                df = pd.read_excel(file_path)
                content = '\n'.join(df.astype(str).values.flatten())
                ip_list = extract_ips(content)
                app.logger.info(f'Extracted IPs from Excel: {ip_list}')
            finally:
                # Clean up temporary file
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            app.logger.info('Processing text/CSV file')
            content = file.read().decode('utf-8')
            ip_list = extract_ips(content)
            app.logger.info(f'Extracted IPs from text: {ip_list}')
        
        if not ip_list:
            app.logger.info('No valid IPs found in file')
            return jsonify({'results': []})

        results = []
        for idx, ip in enumerate(ip_list, 1):
            app.logger.info(f'Processing IP {idx}: {ip}')
            result = check_ip(ip)
            app.logger.info(f'Result for IP {ip}: {result}')
            
            if isinstance(result, dict) and 'error' not in result:
                formatted_result = {
                    'id': idx,
                    'ip': ip,
                    'malicious': result.get('malicious', 0),
                    'suspicious': result.get('suspicious', 0),
                    'as_owner': result.get('as_owner', 'Unknown'),
                    'country': result.get('country', 'Unknown')
                }
                results.append(formatted_result)
                app.logger.info(f'Formatted result: {formatted_result}')

        # Save results to a unique file with timestamp
        if results:
            timestamp = int(time.time())
            filename = f'ip_scan_results_{timestamp}.xlsx'
            df = pd.DataFrame(results)
            df.to_excel(os.path.join(UPLOAD_FOLDER, filename), index=False)
            # Store the filename in session
            session['last_ip_scan_file'] = filename

        app.logger.info(f'Final results: {results}')
        response = {'results': results}
        app.logger.info(f'Sending response: {response}')
        return jsonify(response)
    except Exception as e:
        app.logger.error(f'Error in upload_ip: {str(e)}')
        return jsonify({'results': []})

@app.route('/download_ip')
def download_ip():
    try:
        # Get the filename from session
        filename = session.get('last_ip_scan_file')
        if not filename:
            return jsonify({'error': 'No scan results available'}), 404

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'Results file not found'}), 404

        return send_file(
            file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='ip_scan_results.xlsx'
        )
    except Exception as e:
        app.logger.error(f'Error in download_ip: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"})
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"})
            
        if not file.filename.endswith('.xlsx'):
            return jsonify({"error": "Only Excel files are supported"})
        
        try:
            # Save the uploaded file
            file_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
            file.save(file_path)
            
            # Read hashes from the file
            df = pd.read_excel(file_path)
            hashes = []
            
            # Try to find the column containing hashes
            for column in df.columns:
                # Check if the column contains hash-like strings
                column_hashes = df[column].astype(str).str.strip()
                # Filter for valid hash lengths (MD5: 32, SHA1: 40, SHA256: 64)
                valid_hashes = column_hashes[column_hashes.str.match(r'^[a-fA-F0-9]{32,64}$')]
                if not valid_hashes.empty:
                    hashes = valid_hashes.tolist()
                    break
            
            if not hashes:
                return jsonify({"error": "No valid hashes found in the Excel file"})
            
            # Check each hash
            results = []
            for hash_value in hashes:
                result = check_hash(hash_value)
                if "error" not in result:
                    result['hash'] = hash_value
                    # Ensure all numeric values are integers
                    result['malicious'] = int(result.get('malicious', 0))
                    result['suspicious'] = int(result.get('suspicious', 0))
                    result['harmless'] = int(result.get('harmless', 0))
                    result['undetected'] = int(result.get('undetected', 0))
                results.append(result)
            
            # Save results to Excel with timestamp
            if results:
                timestamp = int(time.time())
                filename = f'hash_scan_results_{timestamp}.xlsx'
                df = pd.DataFrame(results)
                df.to_excel(os.path.join(UPLOAD_FOLDER, filename), index=False)
                session['last_hash_scan_file'] = filename
            
            return jsonify(results)
        finally:
            # Clean up the uploaded file
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/download')
def download():
    try:
        # Get the filename from session
        filename = session.get('last_hash_scan_file')
        if not filename:
            return jsonify({'error': 'No scan results available'}), 404

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'Results file not found'}), 404

        return send_file(
            file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='hash_scan_results.xlsx'
        )
    except Exception as e:
        app.logger.error(f'Error in download: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"})
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"})
            
        # Save the file temporarily
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Calculate file hash
        file_hash = calculate_file_hash(file_path)
        
        # Check file hash against VirusTotal
        result = check_hash(file_hash)
        
        # Add filename and hash to result
        if isinstance(result, dict) and 'error' not in result:
            result['filename'] = filename
            result['hash'] = file_hash
            
            # Save results to Excel with timestamp
            timestamp = int(time.time())
            results_filename = f'file_scan_results_{timestamp}.xlsx'
            df = pd.DataFrame([{
                'filename': filename,
                'hash': file_hash,
                'malicious': result.get('malicious', 0),
                'suspicious': result.get('suspicious', 0),
                'harmless': result.get('harmless', 0),
                'undetected': result.get('undetected', 0)
            }])
            df.to_excel(os.path.join(UPLOAD_FOLDER, results_filename), index=False)
            session['last_file_scan_file'] = results_filename
        
        # Clean up the temporary file
        os.remove(file_path)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/download_file')
def download_file():
    try:
        # Get the filename from session
        filename = session.get('last_file_scan_file')
        if not filename:
            return jsonify({'error': 'No scan results available'}), 404

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'Results file not found'}), 404
            
        return send_file(
            file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='file_scan_results.xlsx'
        )
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/process_urls', methods=['POST'])
def process_urls():
    input_text = request.form.get('input_text', '').strip()
    if not input_text:
        return jsonify({'results': []})

    urls = [url.strip() for url in input_text.split('\n') if url.strip()]
    
    results = []
    for url in urls:
        try:
            result = check_url(url)
            results.append(result)
        except Exception as e:
            results.append({
                "url": url, 
                "status": "Error", 
                "malicious": 0, 
                "suspicious": 0, 
                "harmless": 0, 
                "details": f"Processing error: {str(e)}"
            })
    
    # Save results to Excel with timestamp
    if results:
        timestamp = int(time.time())
        filename = f'url_scan_results_{timestamp}.xlsx'
        df = pd.DataFrame(results)
        df.to_excel(os.path.join(UPLOAD_FOLDER, filename), index=False)
        session['last_url_scan_file'] = filename
    
    return jsonify(results)

@app.route('/upload_urls', methods=['POST'])
def upload_urls():
    if 'file' not in request.files:
        return jsonify({'results': []})
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'results': []})
        
    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'results': []})
    
    try:
        # Save the file temporarily
        file_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(file_path)
        
        # Read URLs from the Excel file
        df = pd.read_excel(file_path)
        
        # Check if 'URL' column exists, otherwise try to find a column that might contain URLs
        url_column = None
        if 'URL' in df.columns:
            url_column = 'URL'
        else:
            # Try to find a column that might contain URLs
            for column in df.columns:
                # Check if the column contains strings that look like URLs
                sample_values = df[column].dropna().astype(str).head(5).tolist()
                if any('http' in val or 'www.' in val for val in sample_values):
                    url_column = column
                    break
        
        if not url_column:
            return jsonify({'results': [], 'error': 'No URL column found in the file'})
        
        # Extract URLs from the identified column
        urls = df[url_column].dropna().astype(str).tolist()
        
        # Process each URL
        results = []
        for url in urls:
            try:
                result = check_url(url.strip())
                results.append(result)
            except Exception as e:
                results.append({
                    "url": url, 
                    "status": "Error", 
                    "malicious": 0, 
                    "suspicious": 0, 
                    "harmless": 0, 
                    "details": f"Processing error: {str(e)}"
                })
        
        # Save results to Excel with timestamp
        if results:
            timestamp = int(time.time())
            filename = f'url_scan_results_{timestamp}.xlsx'
            df = pd.DataFrame(results)
            df.to_excel(os.path.join(UPLOAD_FOLDER, filename), index=False)
            session['last_url_scan_file'] = filename
        
        # Clean up the temporary file
        try:
            os.remove(file_path)
        except:
            pass
        
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error processing file: {str(e)}")
        return jsonify({'results': [], 'error': str(e)})

@app.route('/download_urls')
def download_urls():
    try:
        # Get the filename from session
        filename = session.get('last_url_scan_file')
        if not filename:
            return jsonify({'error': 'No scan results available'}), 404

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'Results file not found'}), 404

        return send_file(
            file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='url_scan_results.xlsx'
        )
    except Exception as e:
        app.logger.error(f'Error in download_urls: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/owasp-calculator')
def owasp_calculator():
    # Chart configuration for the risk matrix
    chart_config = {
        'riskLevels': {
            'low': {'min': 0, 'max': 3, 'color': '#4CAF50'},
            'medium': {'min': 3, 'max': 6, 'color': '#FFC107'},
            'high': {'min': 6, 'max': 9, 'color': '#F44336'}
        },
        'matrixLabels': {
            'x': ['Low', 'Medium', 'High'],
            'y': ['Low', 'Medium', 'High']
        }
    }
    return render_template('owasp/index.html', chart_config=chart_config)

@app.route('/log-analyzer')
def log_analyzer():
    return render_template('log-analyzer.html')

def make_threat_api_call(base_url, endpoint, params=None):
    """Make an API call to the Threat Intelligence Platform"""
    headers = {"Authorization": THREAT_API_KEY}
    url = base_url + endpoint
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API call failed: {str(e)}")
        return {"error": f"API call failed: {str(e)}"}
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}"}

@app.route('/threat-intelligence', methods=['GET', 'POST'])
def threat_intelligence():
    if request.method == 'POST':
        domain = request.form['domainName']
        infrastructure_data = make_threat_api_call(THREAT_BASE_URL_V1, "infrastructureAnalysis", {"domainName": domain})
        ssl_chain_data = make_threat_api_call(THREAT_BASE_URL_V1, "sslCertificatesChain", {"domainName": domain})
        ssl_config_data = make_threat_api_call(THREAT_BASE_URL_V1, "sslConfiguration", {"domainName": domain})
        malware_check_data = make_threat_api_call(THREAT_BASE_URL_V1, "malwareCheck", {"domainName": domain})
        connected_domains_data = make_threat_api_call(THREAT_BASE_URL_V1, "connectedDomains", {"domainName": domain})
        reputation_v1_data = make_threat_api_call(THREAT_BASE_URL_V1, "reputation", {"domainName": domain, "mode": "fast"})
        reputation_v2_data = make_threat_api_call(THREAT_BASE_URL_V2, "reputation", {"domainName": domain})

        return render_template(
            'threatintelligenceplatform/index.html',
            infrastructure=infrastructure_data,
            ssl_chain=ssl_chain_data,
            ssl_config=ssl_config_data,
            malware_check=malware_check_data,
            connected_domains=connected_domains_data,
            reputation_v1=reputation_v1_data,
            reputation_v2=reputation_v2_data,
            domain=domain
        )
    return render_template('threatintelligenceplatform/index.html')

# Cybersecurity Toolkit Functions
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

def scan_file(file_path):
    try:
        results = {
            "file_info": {},
            "hash_analysis": {},
            "pattern_analysis": {}
        }
        
        file_stats = os.stat(file_path)
        results["file_info"] = {
            "size": file_stats.st_size,
            "created": datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            "modified": datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
            results["hash_analysis"] = {
                "md5": hashlib.md5(file_content).hexdigest(),
                "sha1": hashlib.sha1(file_content).hexdigest(),
                "sha256": hashlib.sha256(file_content).hexdigest()
            }
        
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

class PacketSniffer:
    def __init__(self):
        self.sniffing = False
        self.packets = []
        
    def start_sniffing(self, interface=None, count=10):
        try:
            self.sniffing = True
            self.packets = []
            
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

def resolve_dns(domain):
    try:
        results = {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "whois": {}
        }
        
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            results["a_records"] = [str(record) for record in a_records]
        except:
            pass
            
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results["mx_records"] = [str(record) for record in mx_records]
        except:
            pass
            
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results["ns_records"] = [str(record) for record in ns_records]
        except:
            pass
            
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results["txt_records"] = [str(record) for record in txt_records]
        except:
            pass
            
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

# Cybersecurity Toolkit Routes
@app.route('/cybersecurity-toolkit')
def cybersecurity_toolkit():
    return render_template('cybersecurity_toolkit.html')

@app.route('/cybersecurity/system-info')
def system_info():
    return jsonify(get_system_info())

@app.route('/cybersecurity/scan-file', methods=['POST'])
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

@app.route('/cybersecurity/start-sniffing', methods=['POST'])
def start_sniffing():
    data = request.json
    interface = data.get('interface')
    count = data.get('count', 10)
    sniffer = PacketSniffer()
    results = sniffer.start_sniffing(interface, count)
    return jsonify(results)

@app.route('/cybersecurity/stop-sniffing', methods=['POST'])
def stop_sniffing():
    sniffer = PacketSniffer()
    sniffer.stop_sniffing()
    return jsonify({"status": "stopped"})

@app.route('/cybersecurity/dns-resolve', methods=['POST'])
def dns_resolve():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "No domain provided"})
    return jsonify(resolve_dns(domain))

@app.route('/cybersecurity/ssl-check', methods=['POST'])
def ssl_check():
    data = request.json
    domain = data.get('domain')
    port = data.get('port', 443)
    if not domain:
        return jsonify({"error": "No domain provided"})
    return jsonify(check_ssl(domain, port))

@app.route('/cybersecurity/port-scan', methods=['POST'])
def port_scan():
    data = request.json
    host = data.get('host')
    start_port = data.get('start_port', 1)
    end_port = data.get('end_port', 1024)
    if not host:
        return jsonify({"error": "No host provided"})
    return jsonify(scan_ports(host, start_port, end_port))

@app.route('/cybersecurity/generate-hash', methods=['POST'])
def generate_hash():
    data = request.json
    content = data.get('content')
    is_file = data.get('is_file', False)
    if not content:
        return jsonify({"error": "No content provided"})
    return jsonify(generate_hashes(content, is_file))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 