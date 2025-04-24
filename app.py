from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, session, make_response
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
import nmap
import urllib3
import ssl
import socket
import concurrent.futures
import dns.resolver
import whois
from datetime import datetime
import threading
import subprocess
from urllib.parse import urljoin, urlparse, unquote
import OpenSSL
import warnings
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
from sql_injection import SQLInjectionTester
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from xss_scanner import XssTester
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Disable SSL warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)
urllib3.disable_warnings()

app = Flask(__name__, static_url_path='', static_folder='static')
app.secret_key = os.urandom(24)  # Set a secret key for session management

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# VirusTotal API keys
API_KEYS = [
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507"
]

# Dictionary to track API usage
api_usage = {key: 0 for key in API_KEYS}

# Global thread pool for reuse
thread_pool = ThreadPoolExecutor(max_workers=10)

# Cache for DNS and WHOIS lookups
dns_cache = {}
whois_cache = {}

def get_available_api_key():
    for key in API_KEYS:
        if api_usage[key] < 500:  # Daily limit per key
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
        api_usage[api_key] += 1
        
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
        api_usage[api_key] += 1
        
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
                
                api_usage[api_key] += 1
                
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
    return render_template('index.html', tools=[
        {'name': 'Hash Reputation Checker', 'url': '/hash-checker', 'icon': 'fas fa-hashtag'},
        {'name': 'IP Reputation Checker', 'url': '/ip-checker', 'icon': 'fas fa-network-wired'},
        {'name': 'File Reputation Checker', 'url': '/file-checker', 'icon': 'fas fa-file'},
        {'name': 'URL Reputation Checker', 'url': '/url-checker', 'icon': 'fas fa-link'},
        {'name': 'OWASP Risk Rating Calculator', 'url': '/owasp-calculator', 'icon': 'fas fa-shield-alt'}
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
    return send_from_directory('.', filename)

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

# Web Vulnerability Scanner Functions
@lru_cache(maxsize=100)
def get_dns_info(hostname):
    logger.info(f"Starting DNS lookup for {hostname}")
    try:
        result = {}
        
        # Get A records
        logger.info("Looking up A records...")
        try:
            a_records = dns.resolver.resolve(hostname, 'A')
            result['A_records'] = [str(r) for r in a_records]
            logger.info(f"Found {len(result['A_records'])} A records")
        except Exception as e:
            logger.error(f"Error getting A records: {e}")
            result['A_records'] = []
        
        # Get MX records
        logger.info("Looking up MX records...")
        try:
            mx_records = dns.resolver.resolve(hostname, 'MX')
            result['MX_records'] = [str(r) for r in mx_records]
            logger.info(f"Found {len(result['MX_records'])} MX records")
        except Exception as e:
            logger.error(f"Error getting MX records: {e}")
            result['MX_records'] = []
            
        # Get NS records
        logger.info("Looking up NS records...")
        try:
            ns_records = dns.resolver.resolve(hostname, 'NS')
            result['NS_records'] = [str(r) for r in ns_records]
            logger.info(f"Found {len(result['NS_records'])} NS records")
        except Exception as e:
            logger.error(f"Error getting NS records: {e}")
            result['NS_records'] = []
            
        result['status'] = 'success'
        return result
    except Exception as e:
        logger.error(f"DNS lookup error: {e}")
        return {'status': 'error', 'message': str(e)}

@lru_cache(maxsize=100)
def get_whois_info(hostname):
    """Get WHOIS information for a domain with improved error handling and field processing"""
    logger.info(f"Starting WHOIS lookup for {hostname}")
    try:
        # Remove any protocol prefixes and paths
        hostname = hostname.split('://')[1].split('/')[0] if '://' in hostname else hostname
        logger.info(f"Cleaned hostname for WHOIS lookup: {hostname}")
        
        w = whois.whois(hostname)
        if not w or not w.domain_name:
            logger.error(f"No WHOIS data found for {hostname}")
            return {
                'status': 'error',
                'message': f'No WHOIS information found for {hostname}'
            }
            
        # Format dates with proper error handling
        def format_date(date_value):
            try:
                if isinstance(date_value, list):
                    return [d.strftime('%Y-%m-%d %H:%M:%S') if d else None for d in date_value]
                elif date_value:
                    return date_value.strftime('%Y-%m-%d %H:%M:%S')
                return None
            except Exception as e:
                logger.warning(f"Error formatting date {date_value}: {e}")
                return str(date_value) if date_value else None
        
        # Extract and clean WHOIS data
        whois_data = {
            'domain_name': w.domain_name if isinstance(w.domain_name, str) else str(w.domain_name[0]) if isinstance(w.domain_name, list) and w.domain_name else None,
            'registrar': w.registrar,
            'creation_date': format_date(w.creation_date),
            'expiration_date': format_date(w.expiration_date),
            'updated_date': format_date(w.updated_date),
            'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
            'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            'emails': w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
            'dnssec': w.dnssec,
            'org': w.org,
            'country': w.country,
            'state': w.state,
            'city': w.city,
            'address': w.address,
            'zipcode': w.zipcode
        }
        
        # Clean None values and empty lists
        whois_data = {k: v for k, v in whois_data.items() if v is not None and v != []}
        
        # Add registration status check
        days_until_expiry = None
        if whois_data.get('expiration_date'):
            try:
                expiry_date = datetime.strptime(whois_data['expiration_date'], '%Y-%m-%d %H:%M:%S')
                days_until_expiry = (expiry_date - datetime.now()).days
                whois_data['days_until_expiry'] = days_until_expiry
                
                if days_until_expiry < 30:
                    whois_data['warning'] = f'Domain expires in {days_until_expiry} days'
            except Exception as e:
                logger.warning(f"Error calculating expiration: {e}")
        
        result = {
            'status': 'success',
            'data': whois_data,
            'raw_text': w.text
        }
        
        logger.info(f"Successfully retrieved WHOIS data for {hostname}")
        return result
        
    except whois.parser.PywhoisError as e:
        error_msg = str(e)
        logger.error(f"WHOIS parser error for {hostname}: {error_msg}")
        return {
            'status': 'error',
            'message': f'Failed to parse WHOIS data: {error_msg}'
        }
    except Exception as e:
        error_msg = str(e)
        logger.error(f"WHOIS lookup error for {hostname}: {error_msg}")
        return {
            'status': 'error',
            'message': f'Failed to retrieve WHOIS information: {error_msg}'
        }

def scan_headers(url):
    logger.info(f"Starting header scan for {url}")
    try:
        logger.info("Sending request to get headers...")
        response = requests.get(url, verify=False, timeout=10)
        headers = dict(response.headers)
        logger.info(f"Received {len(headers)} headers")
        
        # Check for security headers
        security_headers = {
            'X-Frame-Options': 'Prevents clickjacking',
            'X-XSS-Protection': 'XSS protection',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Content-Security-Policy': 'Controls resources browser can load',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features'
        }
        
        missing_headers = []
        present_headers = []
        
        for header, description in security_headers.items():
            if header in headers:
                logger.info(f"Found security header: {header}")
                present_headers.append({
                    'header': header,
                    'value': headers[header],
                    'description': description
                })
            else:
                logger.warning(f"Missing security header: {header}")
                missing_headers.append({
                    'header': header,
                    'description': description
                })
                
        return {
            'status': 'success',
            'present_headers': present_headers,
            'missing_headers': missing_headers,
            'all_headers': headers
        }
    except requests.exceptions.Timeout:
        logger.error("Header scan timed out")
        return {'status': 'error', 'message': 'Request timed out'}
    except requests.exceptions.SSLError as e:
        logger.error(f"SSL Error during header scan: {e}")
        return {'status': 'error', 'message': 'SSL verification failed'}
    except Exception as e:
        logger.error(f"Header scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def scan_ssl(url):
    logger.info(f"Starting SSL scan for {url}")
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        logger.info(f"Parsed hostname: {hostname}")
        
        logger.info("Creating SSL context...")
        context = ssl.create_default_context()
        
        logger.info("Establishing connection...")
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                logger.info("SSL connection established, getting certificate info...")
                cert = ssock.getpeercert()
                
        # Analyze certificate
        logger.info("Analyzing certificate...")
        result = {
            'status': 'success',
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'version': cert.get('version'),
            'serialNumber': cert.get('serialNumber'),
            'notBefore': cert.get('notBefore'),
            'notAfter': cert.get('notAfter'),
            'subjectAltName': cert.get('subjectAltName', []),
        }
        
        # Check certificate expiration
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (not_after - datetime.now()).days
        result['days_until_expiry'] = days_until_expiry
        
        if days_until_expiry < 30:
            logger.warning(f"Certificate expires soon: {days_until_expiry} days")
            result['warnings'] = [f'Certificate expires in {days_until_expiry} days']
        else:
            logger.info(f"Certificate valid for {days_until_expiry} days")
            
        return result
        
    except socket.timeout:
        logger.error("SSL scan timed out")
        return {'status': 'error', 'message': 'Connection timed out'}
    except ssl.SSLError as e:
        logger.error(f"SSL Error: {e}")
        return {'status': 'error', 'message': f'SSL Error: {str(e)}'}
    except Exception as e:
        logger.error(f"SSL scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def check_common_vulnerabilities(url):
    """Check for common vulnerabilities"""
    try:
        vulnerabilities = []
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Get the main page
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Check for sensitive information exposure
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'api_key': r'(?i)(api[_-]?key|access[_-]?token)["\']?\s*[:=]\s*["\']?\w+["\']?'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, response.text)
            if matches:
                vulnerabilities.append({
                    'type': 'Information Exposure',
                    'severity': 'High',
                    'description': f'Potential {pattern_name} found in page source',
                    'element': f'Found {len(matches)} instances'
                })

        # 2. Check for forms security
        forms = soup.find_all('form')
        for form in forms:
            # Check form method
            if not form.get('method'):
                vulnerabilities.append({
                    'type': 'Form Security',
                    'severity': 'Medium',
                    'description': 'Form missing method attribute',
                    'element': str(form)[:200]
                })
            
            # Check for password fields over HTTP
            if url.startswith('http://') and form.find('input', {'type': 'password'}):
                vulnerabilities.append({
                    'type': 'Form Security',
                    'severity': 'High',
                    'description': 'Password form submitted over HTTP',
                    'element': str(form)[:200]
                })
            
            # Check for autocomplete on sensitive fields
            sensitive_inputs = form.find_all('input', {'type': ['password', 'email', 'tel', 'credit-card']})
            for input_field in sensitive_inputs:
                if not input_field.get('autocomplete') == 'off':
                    vulnerabilities.append({
                        'type': 'Form Security',
                        'severity': 'Medium',
                        'description': f'Sensitive {input_field["type"]} field without autocomplete=off',
                        'element': str(input_field)
                    })

        # 3. Check for mixed content
        if url.startswith('https://'):
            mixed_content = []
            for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
                src = tag.get('src') or tag.get('href')
                if src and src.startswith('http://'):
                    mixed_content.append(src)
            
            if mixed_content:
                vulnerabilities.append({
                    'type': 'Mixed Content',
                    'severity': 'Medium',
                    'description': 'Loading resources over HTTP on HTTPS page',
                    'element': f'Found {len(mixed_content)} insecure resources'
                })

        # 4. Check for common sensitive files
        sensitive_files = [
            '.git/config', '.env', 'wp-config.php', 'config.php',
            'settings.php', '.htaccess', 'web.config', 'phpinfo.php',
            'backup.sql', 'database.sql', '.DS_Store', 'credentials.txt',
            '.svn/entries', '.hg/hgrc', 'composer.json', 'package.json'
        ]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for file in sensitive_files:
                test_url = urljoin(url, file)
                futures[executor.submit(requests.head, test_url, verify=False, timeout=5)] = file
            
            for future in as_completed(futures):
                try:
                    response = future.result()
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Sensitive File',
                            'severity': 'High',
                            'description': f'Potentially sensitive file accessible: {futures[future]}',
                            'element': urljoin(url, futures[future])
                        })
                except:
                    continue

        # 5. Check for directory listing
        common_dirs = ['images/', 'uploads/', 'backup/', 'admin/', 'temp/', 'files/']
        for dir_path in common_dirs:
            try:
                test_url = urljoin(url, dir_path)
                response = requests.get(test_url, verify=False, timeout=5)
                if 'Index of' in response.text or 'Directory listing' in response.text:
                    vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'Medium',
                        'description': f'Directory listing enabled for: {dir_path}',
                        'element': test_url
                    })
            except:
                continue

        # 6. Check for security headers
        security_headers = {
            'X-Frame-Options': 'clickjacking protection',
            'X-Content-Type-Options': 'MIME-sniffing protection',
            'Content-Security-Policy': 'resource loading control',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Referrer-Policy': 'referrer information control'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'description': f'Missing {header} header ({description})',
                    'element': f'Current headers: {", ".join(response.headers.keys())}'
                })

        # 7. Check for version disclosure
        version_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime']
        for header in version_headers:
            if header in response.headers:
                vulnerabilities.append({
                    'type': 'Version Disclosure',
                    'severity': 'Low',
                    'description': f'Server revealing version information via {header} header',
                    'element': f'{header}: {response.headers[header]}'
                })

        return {
            'status': 'success',
            'vulnerabilities': vulnerabilities,
            'total_checks': len(patterns) + 7,  # Number of different check categories
            'forms_analyzed': len(forms)
        }
    except Exception as e:
        logger.error(f"Vulnerability scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def check_sql_injection(url):
    try:
        tester = SQLInjectionTester()
        result = tester.test_url(url)
        return {
            'status': 'success',
            'vulnerable': result['vulnerable'],
            'payloads': result.get('payloads', []),
            'evidence': result.get('evidence', [])
        }
    except Exception as e:
        logger.error(f"SQL injection scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def check_csrf(url):
    try:
        response = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for CSRF tokens
        csrf_tokens = soup.find_all('input', {'name': lambda x: x and ('csrf' in x.lower() or 'token' in x.lower())})
        
        # Check for SameSite cookie attribute
        cookies = response.cookies
        samesite_secure = any('SameSite' in str(cookie) and 'Secure' in str(cookie) for cookie in cookies)
        
        vulnerabilities = []
        if not csrf_tokens:
            vulnerabilities.append('No CSRF tokens found in forms')
        if not samesite_secure:
            vulnerabilities.append('Missing SameSite cookie attribute')
            
        return {
            'status': 'success',
            'vulnerabilities': vulnerabilities,
            'csrf_tokens_found': len(csrf_tokens) > 0,
            'samesite_secure': samesite_secure
        }
    except Exception as e:
        logger.error(f"CSRF scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def check_xss(url):
    try:
        tester = XssTester()
        result = tester.test_url(url)
        return {
            'status': 'success',
            'vulnerable': result['vulnerable'],
            'payloads': result.get('payloads', []),
            'evidence': result.get('evidence', [])
        }
    except Exception as e:
        logger.error(f"XSS scan error: {e}")
        return {'status': 'error', 'message': str(e)}

def analyze_discovery_files(base_url):
    try:
        result = {
            'robots_txt': None,
            'sitemap_xml': None,
            'common_files': []
        }
        
        # Check robots.txt
        try:
            robots_url = urljoin(base_url, 'robots.txt')
            response = requests.get(robots_url, verify=False, timeout=5)
            if response.status_code == 200:
                result['robots_txt'] = {
                    'content': response.text,
                    'disallowed_paths': re.findall(r'Disallow:\s*(.*)', response.text)
                }
        except:
            pass
            
        # Check sitemap.xml
        try:
            sitemap_url = urljoin(base_url, 'sitemap.xml')
            response = requests.get(sitemap_url, verify=False, timeout=5)
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                urls = []
                for url in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                    loc = url.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc is not None:
                        urls.append(loc.text)
                result['sitemap_xml'] = urls
        except:
            pass
            
        # Check common files
        common_files = [
            'crossdomain.xml', 'clientaccesspolicy.xml',
            '.git/HEAD', '.svn/entries', '.env',
            'phpinfo.php', 'test.php'
        ]
        
        for file in common_files:
            try:
                file_url = urljoin(base_url, file)
                response = requests.get(file_url, verify=False, timeout=5)
                if response.status_code == 200:
                    result['common_files'].append({
                        'file': file,
                        'url': file_url,
                        'status': response.status_code
                    })
            except:
                continue
                
        return {
            'status': 'success',
            'discovery': result
        }
    except Exception as e:
        logger.error(f"Discovery scan error: {e}")
        return {'status': 'error', 'message': str(e)}

# Add new routes for web vulnerability scanner
@app.route('/web-scanner')
def web_scanner():
    return render_template('web_scanner/index.html')

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    try:
        data = request.get_json()
        url = data.get('url')
        categories = data.get('categories', [])

        if not url:
            logger.error("No URL provided")
            return jsonify({'error': 'URL is required'}), 400
        if not categories:
            logger.error("No scan categories selected")
            return jsonify({'error': 'At least one scan category is required'}), 400

        logger.info(f"Starting scan for URL: {url}")
        logger.info(f"Selected categories: {categories}")

        # Initialize results dictionary
        results = {
            'target_url': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scans_performed': categories,
            'scan_summary': {
                'total_scans': len(categories),
                'completed_scans': 0,
                'failed_scans': 0
            }
        }

        # Parse URL for hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        logger.info(f"Parsed hostname: {hostname}")

        # Define timeouts for different scan types
        TIMEOUT_SECONDS = {
            'headers': 30,
            'ssl': 30,
            'dns': 20,
            'whois': 20,
            'vuln': 45,
            'csrf': 30,
            'sql': 45,
            'xss': 45,
            'discovery': 30
        }

        # Use ThreadPoolExecutor for concurrent scans
        with ThreadPoolExecutor(max_workers=3) as executor:  # Reduced max_workers to prevent overload
            futures = {}
            
            # Queue up all requested scans with timeouts
            for category in categories:
                logger.info(f"Queuing {category} scan...")
                timeout = TIMEOUT_SECONDS.get(category, 30)
                
                try:
                    if category == 'headers':
                        future = executor.submit(timeout_wrapper, scan_headers, timeout, url)
                    elif category == 'ssl':
                        future = executor.submit(timeout_wrapper, scan_ssl, timeout, url)
                    elif category == 'dns':
                        future = executor.submit(timeout_wrapper, get_dns_info, timeout, hostname)
                    elif category == 'whois':
                        future = executor.submit(timeout_wrapper, get_whois_info, timeout, hostname)
                    elif category == 'vuln':
                        future = executor.submit(timeout_wrapper, check_common_vulnerabilities, timeout, url)
                    elif category == 'csrf':
                        future = executor.submit(timeout_wrapper, check_csrf, timeout, url)
                    elif category == 'sql':
                        future = executor.submit(timeout_wrapper, check_sql_injection, timeout, url)
                    elif category == 'xss':
                        future = executor.submit(timeout_wrapper, check_xss, timeout, url)
                    elif category == 'discovery':
                        future = executor.submit(timeout_wrapper, analyze_discovery_files, timeout, url)
                    
                    futures[future] = category
                    logger.info(f"Queued {category} scan with {timeout}s timeout")
                except Exception as e:
                    logger.error(f"Error queuing {category} scan: {str(e)}")
                    results[f"{category}_scan"] = {
                        'status': 'error',
                        'message': f"Failed to start scan: {str(e)}"
                    }
                    results['scan_summary']['failed_scans'] += 1

            # Process results as they complete
            for future in as_completed(futures):
                category = futures[future]
                scan_type = f"{category}_scan"
                
                try:
                    logger.info(f"Processing results for {category}...")
                    result = future.result()
                    
                    if isinstance(result, dict) and result.get('status') == 'timeout':
                        logger.error(f"❌ {category} scan timed out after {TIMEOUT_SECONDS[category]} seconds")
                        results[scan_type] = {
                            'status': 'error',
                            'message': f"Scan timed out after {TIMEOUT_SECONDS[category]} seconds"
                        }
                        results['scan_summary']['failed_scans'] += 1
                    else:
                        results[scan_type] = result
                        if result.get('status') == 'success':
                            logger.info(f"✓ {category} scan completed successfully")
                            results['scan_summary']['completed_scans'] += 1
                        else:
                            logger.error(f"✗ {category} scan failed: {result.get('message', 'Unknown error')}")
                            results['scan_summary']['failed_scans'] += 1
                    
                except concurrent.futures.TimeoutError:
                    logger.error(f"❌ {category} scan timed out")
                    results[scan_type] = {
                        'status': 'error',
                        'message': 'Scan timed out'
                    }
                    results['scan_summary']['failed_scans'] += 1
                except Exception as e:
                    logger.error(f"Error in {category} scan: {str(e)}")
                    results[scan_type] = {
                        'status': 'error',
                        'message': str(e)
                    }
                    results['scan_summary']['failed_scans'] += 1

        # Add overall scan status
        success_rate = (
            results['scan_summary']['completed_scans'] / 
            results['scan_summary']['total_scans'] * 100
        ) if results['scan_summary']['total_scans'] > 0 else 0
        
        results['scan_summary']['success_rate'] = success_rate
        logger.info(f"Scan completed with {success_rate:.1f}% success rate")

        return jsonify(results)

    except Exception as e:
        error_msg = f"Error in scan endpoint: {str(e)}"
        logger.error(error_msg)
        return jsonify({
            'error': str(e),
            'scan_summary': {
                'total_scans': len(categories) if categories else 0,
                'completed_scans': 0,
                'failed_scans': 1,
                'success_rate': 0
            }
        }), 500

@app.route('/web-scanner/export-pdf', methods=['POST'])
def export_web_scan_pdf():
    try:
        scan_data = request.get_json()
        if not scan_data:
            return jsonify({"error": "Missing scan data"}), 400

        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=A4,
                                leftMargin=1.5*cm, rightMargin=1.5*cm,
                                topMargin=1.5*cm, bottomMargin=1.5*cm)
        styles = getSampleStyleSheet()
        escape = html.escape

        # Define custom styles
        styles.add(ParagraphStyle(name='ReportTitle', parent=styles['h1'], alignment=TA_CENTER, fontSize=24, spaceAfter=1*cm, textColor=colors.darkblue))
        styles.add(ParagraphStyle(name='SectionTitle', parent=styles['h2'], fontSize=16, spaceBefore=0.8*cm, spaceAfter=0.3*cm, textColor=colors.darkslategray, keepWithNext=1))
        styles.add(ParagraphStyle(name='SubTitle', parent=styles['h3'], fontSize=12, spaceBefore=0.5*cm, spaceAfter=0.2*cm, textColor=colors.darkslategray, keepWithNext=1))
        styles.add(ParagraphStyle(name='NormalRight', parent=styles['Normal'], alignment=TA_RIGHT))
        # --> New/Modified Styles Start <--
        styles.add(ParagraphStyle(name='SmallNormal', parent=styles['Normal'], fontSize=9, leading=11))
        styles.add(ParagraphStyle(name='SmallCode', parent=styles['Code'], fontSize=8, leading=10, wordWrap='CJK', backColor=colors.whitesmoke, borderPadding=(2,2,2,2)))
        styles.add(ParagraphStyle(name='HeaderName', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10))
        styles.add(ParagraphStyle(name='HeaderValue', parent=styles['Code'], fontSize=9, leading=11, wordWrap='CJK'))
        
        # Modify the existing 'Code' style for general code blocks
        code_style = styles['Code']
        code_style.wordWrap = 'CJK'
        code_style.fontSize = 9
        code_style.leading = 11
        code_style.backColor = colors.whitesmoke
        code_style.borderColor = colors.lightgrey
        code_style.borderWidth = 0.5
        code_style.borderPadding = (5,5,5,5)
        
        # Define Issue styles with distinct colors and borders
        styles.add(ParagraphStyle(name='IssueHigh', parent=styles['Normal'], 
                                backColor=colors.Color(255/255, 210/255, 210/255), # Light red background
                                borderColor=colors.red, borderWidth=0.5, borderPadding=(5,5,5,5), 
                                spaceAfter=3, leading=12))
        styles.add(ParagraphStyle(name='IssueMedium', parent=styles['Normal'], 
                                backColor=colors.Color(255/255, 240/255, 200/255), # Light orange background
                                borderColor=colors.orange, borderWidth=0.5, borderPadding=(5,5,5,5), 
                                spaceAfter=3, leading=12))
        styles.add(ParagraphStyle(name='IssueLow', parent=styles['Normal'], 
                                backColor=colors.Color(210/255, 230/255, 255/255), # Light blue background
                                borderColor=colors.blue, borderWidth=0.5, borderPadding=(5,5,5,5), 
                                spaceAfter=3, leading=12))
        styles.add(ParagraphStyle(name='IssueInfo', parent=styles['Normal'], 
                                backColor=colors.Color(220/255, 220/255, 220/255), # Light grey background
                                borderColor=colors.grey, borderWidth=0.5, borderPadding=(5,5,5,5), 
                                spaceAfter=3, leading=12))

        
        # Add custom Text styles
        styles.add(ParagraphStyle(name='SuccessText', parent=styles['Normal'], textColor=colors.darkgreen))
        styles.add(ParagraphStyle(name='ErrorText', parent=styles['Normal'], textColor=colors.red))
        styles.add(ParagraphStyle(name='WarningText', parent=styles['Normal'], textColor=colors.darkorange))
        styles.add(ParagraphStyle(name='Remediation', parent=styles['SmallNormal'], textColor=colors.darkblue, 
                                leftIndent=1*cm, bulletIndent=0.5*cm, firstLineIndent=0, spaceBefore=2, spaceAfter=2))
        # --> New/Modified Styles End <--

        # Build Story
        story = []
        
        # ---- Report Header ----
        story.append(Paragraph("Web Vulnerability Scan Report", styles['ReportTitle']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['NormalRight']))
        story.append(Spacer(1, 0.5*cm))

        # ---- Executive Summary ----
        story.append(Paragraph("Executive Summary", styles['SectionTitle']))
        story.append(Paragraph(f"<b>Target URL:</b> {escape(scan_data.get('target_url', 'N/A'))}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan Timestamp:</b> {escape(scan_data.get('timestamp', 'N/A'))}", styles['Normal']))
        
        # Calculate summary stats (crude risk level based on high severity findings)
        high_severity_count = 0
        # Count high severity from headers_scan (missing headers)
        if scan_data.get('headers_scan', {}).get('status') == 'success':
            missing_headers = scan_data['headers_scan'].get('missing_headers', [])
            # Define which missing headers are considered high severity
            high_severity_headers = ['Content-Security-Policy', 'Strict-Transport-Security'] 
            high_severity_count += sum(1 for h in missing_headers if h.get('header') in high_severity_headers)
        
        # Count high severity from ssl_scan (warnings)
        if scan_data.get('ssl_scan', {}).get('status') == 'success':
             ssl_warnings = scan_data['ssl_scan'].get('warnings', [])
             high_severity_count += sum(1 for w in ssl_warnings if 'critical' in w.lower() or 'weak' in w.lower() or 'expired' in w.lower())
        
        # Count high severity from vuln_scan
        if scan_data.get('vuln_scan', {}).get('status') == 'success':
             vulnerabilities = scan_data['vuln_scan'].get('vulnerabilities', [])
             high_severity_count += sum(1 for v in vulnerabilities if v.get('severity') == 'High')
        
        # Count high severity from SQLi, XSS, CSRF
        if scan_data.get('sql_scan', {}).get('vulnerable'): high_severity_count += 1
        if scan_data.get('xss_scan', {}).get('vulnerable'): high_severity_count += 1
        if scan_data.get('csrf_scan', {}).get('status') == 'success':
             forms = scan_data['csrf_scan'].get('forms', [])
             high_severity_count += sum(1 for f in forms if not f.get('has_token'))
             
        # Count high severity from discovery scan
        if scan_data.get('discovery_scan', {}).get('status') == 'success':
            files_found = scan_data['discovery_scan'].get('files', [])
            high_severity_count += sum(1 for f in files_found if f.get('severity') == 'High')


        risk_level = "Low"
        risk_color = colors.darkgreen
        if high_severity_count > 5: # Example threshold for High risk
            risk_level = "High"
            risk_color = colors.red
        elif high_severity_count > 0: # Example threshold for Medium risk
            risk_level = "Medium"
            risk_color = colors.orange
            
        story.append(Paragraph(f"<b>Overall Risk Level:</b> <font color='{risk_color.hex() if hasattr(risk_color, 'hex') else risk_color}'>{risk_level}</font>", styles['Normal']))
        story.append(Paragraph(f"<b>High Severity Findings Count:</b> {high_severity_count}", styles['Normal']))
        story.append(Paragraph(f"<b>Scans Performed:</b> {escape(', '.join(scan_data.get('scans_performed', [])))}", styles['Normal']))
        scan_summary = scan_data.get('scan_summary', {})
        story.append(Paragraph(f"<b>Scan Status:</b> {scan_summary.get('completed_scans', 0)} completed, {scan_summary.get('failed_scans', 0)} failed.", styles['Normal']))
        story.append(Paragraph("<i>Note: This report provides an automated assessment. Findings should be manually verified and risk assessed based on specific business context.</i>", styles['SmallNormal']))
        story.append(Spacer(1, 0.5*cm))


        # ---- Helper to add sections ----
        def add_section(title, data, render_func):
            if data:
                story.append(Paragraph(escape(title), styles['SectionTitle']))
                if data.get('status') == 'success':
                    try:
                        render_func(data)
                    except Exception as render_e:
                        logger.error(f"Error rendering PDF section '{title}': {render_e}", exc_info=True)
                        story.append(Paragraph(f"Error rendering section: {escape(str(render_e))}", styles['ErrorText']))
                else:
                    story.append(Paragraph(f"Scan failed: {escape(data.get('message', 'Unknown error'))}", styles['ErrorText']))
                story.append(Spacer(1, 0.5*cm))

        # Render Functions per Section
        def render_headers(data):
            present_headers = data.get('present_headers', [])
            missing_headers = data.get('missing_headers', [])
            all_headers = data.get('all_headers', {})

            if present_headers or missing_headers:
                 story.append(Paragraph("Security Header Analysis:", styles['SubTitle']))
                 if missing_headers:
                      story.append(Paragraph("<b>Missing/Recommended Security Headers:</b>", styles['Normal']))
                      for header in missing_headers:
                           # Determine severity based on header name (can be refined)
                           sev = 'High' if header.get('header') in ['Content-Security-Policy', 'Strict-Transport-Security'] else 'Medium' if header.get('header') in ['X-Frame-Options', 'X-Content-Type-Options'] else 'Low'
                           style_name = {'High': 'IssueHigh', 'Medium': 'IssueMedium', 'Low': 'IssueLow'}.get(sev, 'IssueLow')
                           desc = header.get('description', 'Recommendation description missing.')
                           story.append(Paragraph(f"<b>{escape(header.get('header', 'Unknown Header'))} ({escape(sev)}):</b> Missing", styles[style_name]))
                           story.append(Paragraph(f"<i>Importance:</i> {escape(desc)}", styles['SmallNormal']))
                           
                           # Add simple remediation advice
                           if header.get('header') == 'Content-Security-Policy':
                               story.append(Paragraph("<i>Remediation: Implement a strict CSP defining allowed sources for scripts, styles, images, etc. Start with a basic policy and refine it. Use tools like CSP Evaluator.</i>", styles['Remediation']))
                           elif header.get('header') == 'Strict-Transport-Security':
                               story.append(Paragraph("<i>Remediation: Implement HSTS (e.g., `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`) to enforce HTTPS. Ensure the entire site fully supports HTTPS before enabling `includeSubDomains` or submitting for preload.</i>", styles['Remediation']))
                           elif header.get('header') == 'X-Frame-Options':
                               story.append(Paragraph("<i>Remediation: Set to 'DENY' to prevent framing entirely, or 'SAMEORIGIN' to allow framing only by the site itself. Helps prevent clickjacking.</i>", styles['Remediation']))
                           elif header.get('header') == 'X-Content-Type-Options':
                               story.append(Paragraph("<i>Remediation: Set to 'nosniff' to prevent browsers from MIME-sniffing the content-type away from the declared one, mitigating certain attacks.</i>", styles['Remediation']))
                           elif header.get('header') == 'Referrer-Policy':
                               story.append(Paragraph("<i>Remediation: Set a policy like 'strict-origin-when-cross-origin' or 'no-referrer' to control how much referrer information is sent with requests.</i>", styles['Remediation']))
                           elif header.get('header') == 'Permissions-Policy':
                               story.append(Paragraph("<i>Remediation: Define a Permissions-Policy (formerly Feature-Policy) to explicitly enable or disable browser features like camera, microphone, geolocation for the site and embedded content.</i>", styles['Remediation']))
                           else:
                               story.append(Paragraph(f"<i>Remediation: Research and implement the '{escape(header.get('header', ''))}' header according to best practices for your application stack.</i>", styles['Remediation']))
                           story.append(Spacer(1, 0.1*cm))
                      story.append(Spacer(1, 0.2*cm))
                 
                 if present_headers:
                      story.append(Paragraph("<b>Present Security Headers:</b>", styles['Normal']))
                      for header in present_headers:
                           story.append(Paragraph(f"<b>{escape(header.get('header', ''))}:</b>", styles['HeaderName']))
                           # Use HeaderValue style for better code-like formatting of the value
                           story.append(Paragraph(escape(header.get('value', '')), styles['HeaderValue'])) 
                           story.append(Paragraph(f"<i>Purpose:</i> {escape(header.get('description', ''))}", styles['SmallNormal']))
                           story.append(Spacer(1, 0.1*cm))
                      story.append(Spacer(1, 0.2*cm))
            else:
                 story.append(Paragraph("Security header information not available in scan results.", styles['WarningText']))


            if all_headers:
                 story.append(Paragraph("All Received HTTP Headers:", styles['SubTitle']))
                 header_data = [['Header Name', 'Header Value']]
                 # Sort headers alphabetically for consistency
                 for name, value in sorted(all_headers.items()):
                      # Wrap long header values using Paragraph
                      wrapped_value = Paragraph(escape(value), styles['SmallCode']) 
                      header_data.append([Paragraph(escape(name), styles['SmallNormal']), wrapped_value])
                 
                 from reportlab.platypus import Table, TableStyle
                 # from reportlab.lib import colors # Already imported
                 
                 table = Table(header_data, colWidths=[5*cm, 10*cm], repeatRows=1)
                 table.setStyle(TableStyle([
                       ('BACKGROUND', (0,0), (-1,0), colors.grey),
                       ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                       ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                       ('VALIGN', (0,0), (-1,-1), 'TOP'),
                       ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                       ('FONTSIZE', (0,0), (-1,0), 10),
                       ('BOTTOMPADDING', (0,0), (-1,0), 8),
                       ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
                       ('GRID', (0,0), (-1,-1), 1, colors.darkgrey),
                       ('LEFTPADDING', (0,0), (-1,-1), 5),
                       ('RIGHTPADDING', (0,0), (-1,-1), 5),
                       ('TOPPADDING', (0,0), (-1,-1), 5),
                       ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                       # Apply SmallNormal and SmallCode styles to cells
                       # ('FONTNAME', (0,1), (0,-1), 'Helvetica'), # Handled by Paragraph style
                       # ('FONTSIZE', (0,1), (-1,-1), 9), # Handled by Paragraph style
                 ]))
                 story.append(table)
            else:
                 story.append(Paragraph("List of all received headers not available in scan results.", styles['WarningText']))

        def render_ssl(data):
            story.append(Paragraph(f"<b>Subject:</b> {escape(str(data.get('subject', 'N/A')))}", styles['Normal']))
            story.append(Paragraph(f"<b>Issuer:</b> {escape(str(data.get('issuer', 'N/A')))}", styles['Normal']))
            story.append(Paragraph(f"<b>Valid From (UTC):</b> {escape(data.get('notBefore', 'N/A'))}", styles['Normal']))
            story.append(Paragraph(f"<b>Valid Until (UTC):</b> {escape(data.get('notAfter', 'N/A'))}", styles['Normal']))
            
            expiry_days = data.get('days_until_expiry')
            expiry_text = f"{expiry_days} days" if expiry_days is not None else "N/A"
            expiry_style = styles['Normal']
            if expiry_days is not None and expiry_days < 30: expiry_style = styles['WarningText']
            if expiry_days is not None and expiry_days < 0: expiry_style = styles['ErrorText']
            story.append(Paragraph(f"<b>Days Until Expiry:</b> {escape(expiry_text)}", expiry_style))
            if expiry_days is not None and expiry_days < 0:
                story.append(Paragraph("<i>Warning: Certificate has expired!</i>", styles['Remediation']))
            elif expiry_days is not None and expiry_days < 30:
                 story.append(Paragraph("<i>Warning: Certificate expires soon. Plan for renewal.</i>", styles['Remediation']))
            
            story.append(Paragraph(f"<b>Serial Number:</b> {escape(data.get('serialNumber', 'N/A'))}", styles['Normal']))
            story.append(Paragraph(f"<b>Certificate Version:</b> {escape(str(data.get('version', 'N/A')))}", styles['Normal']))
            # Add Signature Algorithm if available in data
            sig_alg = data.get('signatureAlgorithm') 
            if sig_alg: story.append(Paragraph(f"<b>Signature Algorithm:</b> {escape(sig_alg)}", styles['Normal']))
            
            sans = data.get('subjectAltName', [])
            if sans:
                 story.append(Paragraph("<b>Subject Alternative Names (SANs):</b>", styles['SubTitle']))
                 san_list = []
                 for san_type, san_value in sans:
                      san_list.append(f"&nbsp;&nbsp;&nbsp;&nbsp;&bull; {escape(san_type)}: {escape(san_value)}")
                 story.append(Paragraph("<br/>".join(san_list), styles['SmallNormal']))
                 story.append(Spacer(1, 0.1*cm))
            else:
                 story.append(Paragraph("No Subject Alternative Names (SANs) found.", styles['SmallNormal']))

            if data.get('warnings'):
                story.append(Paragraph("SSL/TLS Configuration Warnings:", styles['SubTitle']))
                warning_list = []
                for warning in data['warnings']:
                    # Add specific remediation hints based on warning text (can be expanded)
                    remediation_hint = ""
                    if "weak cipher" in warning.lower():
                         remediation_hint = "Disable weak cipher suites on the server."
                    elif "protocol" in warning.lower():
                         remediation_hint = "Disable outdated protocols (SSLv3, TLS 1.0, TLS 1.1) on the server."
                    elif "certificate chain" in warning.lower():
                         remediation_hint = "Ensure the complete and correct certificate chain is served."
                    elif "expires" in warning.lower(): # Covered above, but good to have hint here too
                         remediation_hint = "Renew the SSL/TLS certificate."
                         
                    warning_list.append(f"• {escape(warning)}")
                    if remediation_hint:
                         warning_list.append(f"&nbsp;&nbsp;<i>Remediation Hint: {escape(remediation_hint)}</i>")
                         
                story.append(Paragraph("<br/>".join(warning_list), styles['WarningText']))
                story.append(Spacer(1, 0.2*cm))
                story.append(Paragraph("<i>General Remediation: Review server TLS configuration thoroughly (protocols, cipher suites, key exchange parameters, certificate chain). Use tools like SSL Labs Server Test (ssllabs.com/ssltest/) for a comprehensive external analysis.</i>", styles['Remediation']))

            else:
                 story.append(Paragraph("No significant SSL/TLS configuration warnings found during this scan.", styles['SuccessText']))

        def render_dns(data):
            found = False
            errors = []
            for type, records in data.get('records', {}).items():
                if records:
                    record_str = str(records[0]) 
                    if not record_str.startswith('Error:'):
                        found = True
                        story.append(Paragraph(f"{escape(type)} Records:", styles['SubTitle']))
                        for record in records:
                             story.append(Paragraph(escape(str(record)), styles['Code']))
                        story.append(Spacer(1, 0.1*cm))
                    else:
                        errors.append((type, record_str))
            if not found:
                story.append(Paragraph("No standard DNS records found.", styles['Normal']))
            if errors:
                 story.append(Paragraph(f"DNS Lookup Errors:", styles['SubTitle']))
                 for type, err_msg in errors:
                     story.append(Paragraph(f"<b>{escape(type)}:</b> {escape(err_msg)}", styles['WarningText']))

        def render_whois(data):
            w_data = data.get('data', {}) # Changed from whois_info to data as per get_whois_info
            if not w_data:
                 story.append(Paragraph("No WHOIS data available or lookup failed.", styles['WarningText']))
                 # Include error message if lookup failed
                 if data.get('message'): 
                      story.append(Paragraph(f"Error: {escape(data.get('message'))}", styles['ErrorText']))
                 return

            story.append(Paragraph("Parsed WHOIS Information:", styles['SubTitle']))
            
            whois_table_data = [['Field', 'Value']]
            # Define a preferred order for common fields
            preferred_order = [
                'domain_name', 'registrar', 'org', 'creation_date', 'expiration_date', 
                'updated_date', 'status', 'name_servers', 'emails', 'dnssec', 
                'address', 'city', 'state', 'zipcode', 'country'
            ]
            
            displayed_keys = set()
            
            # Display preferred fields first
            for field in preferred_order:
                if field in w_data:
                    value = w_data[field]
                    field_display = escape(field.replace('_', ' ').title())
                    value_display = ''
                    if isinstance(value, list):
                         value_display = '<br/>'.join([f"&bull; {escape(str(item))}" for item in value])
                         value_display = Paragraph(value_display, styles['SmallNormal'])
                    elif value is not None:
                         value_display = Paragraph(escape(str(value)), styles['SmallNormal'])
                    else:
                         value_display = Paragraph("N/A", styles['SmallNormal'])
                         
                    whois_table_data.append([Paragraph(field_display, styles['SmallNormal']), value_display])
                    displayed_keys.add(field)

            # Display remaining fields alphabetically
            for field, value in sorted(w_data.items()):
                if field not in displayed_keys and field not in ['warning', 'days_until_expiry']: # Don't repeat or show internal fields
                    field_display = escape(field.replace('_', ' ').title())
                    value_display = ''
                    if isinstance(value, list):
                         value_display = '<br/>'.join([f"&bull; {escape(str(item))}" for item in value])
                         value_display = Paragraph(value_display, styles['SmallNormal'])
                    elif value is not None:
                         value_display = Paragraph(escape(str(value)), styles['SmallNormal'])
                    else:
                         value_display = Paragraph("N/A", styles['SmallNormal'])
                         
                    whois_table_data.append([Paragraph(field_display, styles['SmallNormal']), value_display])

            # Add specific warnings/notes if present
            if 'warning' in w_data:
                 whois_table_data.append([Paragraph("Expiration Warning", styles['WarningText']), Paragraph(escape(w_data['warning']), styles['WarningText'])])
            if 'days_until_expiry' in w_data:
                 expiry_days = w_data['days_until_expiry']
                 expiry_style = styles['Normal']
                 if expiry_days < 30: expiry_style = styles['WarningText']
                 if expiry_days < 0: expiry_style = styles['ErrorText']
                 whois_table_data.append([Paragraph("Days Until Expiry", styles['SmallNormal']), Paragraph(str(expiry_days), expiry_style)])


            if len(whois_table_data) > 1: # Only show table if there is data
                from reportlab.platypus import Table, TableStyle
                table = Table(whois_table_data, colWidths=[5*cm, 10*cm], repeatRows=1)
                table.setStyle(TableStyle([
                       ('BACKGROUND', (0,0), (-1,0), colors.grey),
                       ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                       ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                       ('VALIGN', (0,0), (-1,-1), 'TOP'),
                       ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'), # Header row bold
                       ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'), # Field names bold
                       ('GRID', (0,0), (-1,-1), 0.5, colors.darkgrey),
                       ('LEFTPADDING', (0,0), (-1,-1), 5),
                       ('TOPPADDING', (0,0), (-1,-1), 3),
                       ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                 ]))
                story.append(table)
            else:
                story.append(Paragraph("No structured WHOIS data fields found.", styles['Normal']))

            raw = data.get('raw_text')
            if raw:
                story.append(Spacer(1, 0.3*cm))
                story.append(Paragraph("Raw WHOIS Data:", styles['SubTitle']))
                # Limit raw data display in PDF to avoid excessive length
                raw_display = escape(raw[:3000]) + ('...' if len(raw) > 3000 else '')
                story.append(Paragraph(raw_display, styles['SmallCode']))
            else:
                 story.append(Paragraph("Raw WHOIS text not available.", styles['SmallNormal']))

        def render_vuln(data):
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                 story.append(Paragraph("Common Page Analysis Findings:", styles['SubTitle']))
                 # Add summary stats if available in the data structure
                 total_checks = data.get('total_checks', 'N/A')
                 forms_analyzed = data.get('forms_analyzed', 'N/A')
                 story.append(Paragraph(f"(Total Checks Performed: {total_checks}, Forms Analyzed: {forms_analyzed})", styles['SmallNormal']))
                 story.append(Spacer(1, 0.2*cm))

                 for vuln in vulnerabilities:
                    # Normalize severity for consistent casing
                    sev = vuln.get('severity', 'Low').capitalize() 
                    style_name = {'High': 'IssueHigh', 'Medium': 'IssueMedium', 'Low': 'IssueLow'}.get(sev, 'IssueLow')
                    
                    # Use the defined style for the main finding line
                    story.append(Paragraph(f"<b>Type:</b> {escape(vuln.get('type', 'Unknown'))} ({escape(sev)})", styles[style_name]))
                    # Use SmallNormal for the description for better spacing
                    story.append(Paragraph(f"<b>Description:</b> {escape(vuln.get('description', 'No description provided.'))}", styles['SmallNormal']))
                    if vuln.get('element'):
                         el_display = escape(str(vuln.get('element')))
                         story.append(Paragraph(f"<b>Evidence/Element:</b>", styles['SmallNormal']))
                         # Use SmallCode for code-like elements
                         story.append(Paragraph(el_display[:1000] + ('...' if len(el_display) > 1000 else ''), styles['SmallCode'])) 

                    # Simple Remediation hints based on vulnerability type
                    vuln_type = vuln.get('type', '')
                    if 'Form Security' in vuln_type:
                         story.append(Paragraph("<i>Remediation: Ensure forms use POST for sensitive data, enforce HTTPS, implement anti-CSRF tokens (see CSRF section), set appropriate `autocomplete` attributes (e.g., 'off' for passwords, 'new-password' for registration), and validate data server-side.</i>", styles['Remediation']))
                    elif 'Information Exposure' in vuln_type:
                         story.append(Paragraph("<i>Remediation: Carefully review page source, JavaScript, and server responses to ensure sensitive information (API keys, credentials, PII patterns) is not inadvertently exposed client-side. Implement server-side controls.</i>", styles['Remediation']))
                    elif 'Mixed Content' in vuln_type:
                         story.append(Paragraph("<i>Remediation: Ensure all resources (images, scripts, CSS, iframes) are loaded exclusively over HTTPS on HTTPS pages. Use Content Security Policy (CSP) with `upgrade-insecure-requests` directive.</i>", styles['Remediation']))
                    elif 'Sensitive File' in vuln_type:
                         # Try to extract the specific file mentioned - CORRECTED REGEX (Removed trailing backslash)
                         file_match = re.search(r'file accessible: (\S+)|/(\S+)', vuln.get('description', ''))
                         file_name = "sensitive files"
                         if file_match:
                             # Group 1 matches 'file accessible: PATH', Group 2 matches '/PATH'
                             file_name = file_match.group(1) or file_match.group(2) or "sensitive files"
                         story.append(Paragraph(f"<i>Remediation: Block public access to sensitive configuration files, backup files, source code repositories (`{escape(file_name)}`, etc.) using web server access control rules (e.g., .htaccess, web.config, Nginx location blocks).</i>", styles['Remediation']))
                    elif 'Directory Listing' in vuln_type:
                         story.append(Paragraph("<i>Remediation: Disable directory listing/indexing in web server configuration (e.g., `Options -Indexes` in Apache, `autoindex off;` in Nginx).</i>", styles['Remediation']))
                    elif 'Missing Security Header' in vuln_type:
                          # Extract header name if possible
                          header_match = re.search(r'Missing (.*?) header', vuln.get('description', ''))
                          header_name = header_match.group(1) if header_match else "the specific security header"
                          story.append(Paragraph(f"<i>Remediation: Implement {escape(header_name)} with appropriate directives. Refer to the dedicated Security Headers section for detailed recommendations.</i>", styles['Remediation']))
                    elif 'Version Disclosure' in vuln_type:
                          # Extract header name if possible
                          header_match = re.search(r'via (.*?) header', vuln.get('element', ''))
                          header_name = header_match.group(1) if header_match else "server-identifying headers"
                          story.append(Paragraph(f"<i>Remediation: Configure the web server (e.g., Apache, Nginx, IIS) to suppress or minimize version information revealed in HTTP headers like `{escape(header_name)}`.</i>", styles['Remediation']))
                    else: # Generic fallback
                        story.append(Paragraph("<i>Remediation: Investigate the finding based on the type and description. Consult security best practices for the specific technology or pattern involved.</i>", styles['Remediation']))

                    story.append(Spacer(1, 0.2*cm))
            else:
                story.append(Paragraph("No common page vulnerabilities (like sensitive file exposure, directory listing, basic form issues, version disclosure) were identified during this scan.", styles['SuccessText']))

        def render_csrf(data):
             if data.get('vulnerabilities'):
                 for vuln in data['vulnerabilities']:
                    sev = vuln.get('severity', 'low').lower()
                    style_name = {'high': 'IssueHigh', 'medium': 'IssueMedium', 'low': 'IssueLow'}.get(sev, 'IssueLow')
                    el = f"<br/>Form Element:<br/><code>{escape(vuln.get('element', ''))[:200]}...</code>" if vuln.get('element') else ""
                    story.append(Paragraph(f"<b>{escape(vuln.get('type', ''))}:</b> {escape(vuln.get('description', ''))} <b>({escape(vuln.get('severity', ''))})</b>{el}", styles[style_name]))
             else:
                 story.append(Paragraph("No POST forms found missing potential CSRF tokens.", styles['SuccessText']))

        def render_sqli(data):
            is_vuln = data.get('vulnerable', False)
            status_text = "Potential SQL Injection Detected!" if is_vuln else "No SQL Injection Detected (Based on Tested Payloads)"
            status_style = styles['ErrorText'] if is_vuln else styles['SuccessText']
            story.append(Paragraph(f"<b>Overall SQLi Status:</b> {status_text}", status_style))
            
            details = data.get('details', '') # This field might not exist in the new structure
            if details: story.append(Paragraph(f"<b>Scanner Details:</b> {escape(details)}", styles['Normal']))

            tests = data.get('payloads', []) # Assuming payloads list contains test info now
            vulnerable_payloads_found = False
            if tests:
                story.append(Paragraph("SQL Injection Test Details:", styles['SubTitle']))
                for test in tests:
                    # Determine if this specific test indicated vulnerability
                    test_vuln = test.get('vulnerable', False) # Need a flag per test if available
                    test_style = styles['IssueHigh'] if test_vuln else styles['IssueInfo']
                    test_status = "Vulnerable" if test_vuln else "Not Vulnerable"
                    if test_vuln: vulnerable_payloads_found = True
                    
                    story.append(Paragraph(f"<b>Test Type:</b> {escape(test.get('type', 'N/A'))} - {test_status}", test_style))
                    if test.get('parameter'): story.append(Paragraph(f"<b>Parameter Tested:</b> {escape(test.get('parameter'))}", styles['SmallNormal']))
                    if test.get('form_details'): story.append(Paragraph(f"<b>Form Tested:</b> {escape(test.get('form_details'))}", styles['SmallNormal']))
                    story.append(Paragraph(f"<b>Payload Used:</b>", styles['SmallNormal']))
                    story.append(Paragraph(escape(test.get('payload', '')), styles['SmallCode']))
                    if test.get('evidence'): # Show evidence if found
                        story.append(Paragraph(f"<b>Evidence/Response Snippet:</b>", styles['SmallNormal']))
                        story.append(Paragraph(escape(test.get('evidence', ''))[:500] + '...', styles['SmallCode']))
                        
                    story.append(Spacer(1, 0.2*cm))
            
            # If the overall status is vulnerable but no specific tests marked as such, add a note
            if is_vuln and not vulnerable_payloads_found and tests:
                 story.append(Paragraph("<i>Note: Overall status indicates vulnerability, but specific payload details might be missing. Review server logs and scanner output if available.</i>", styles['WarningText']))
                 
            if is_vuln:
                 story.append(Paragraph("<b>Remediation:</b>", styles['SubTitle']))
                 story.append(Paragraph("• Use Parameterized Queries (Prepared Statements) for ALL database interactions. This is the most effective defense.", styles['Remediation'], bulletText='•'))
                 story.append(Paragraph("• Validate and strictly sanitize all user-supplied input (URLs, form fields, headers) on the server-side before using it in queries.", styles['Remediation'], bulletText='•'))
                 story.append(Paragraph("• Apply the Principle of Least Privilege: Ensure the web application database user has only the minimum necessary permissions.", styles['Remediation'], bulletText='•'))
                 story.append(Paragraph("• Implement proper error handling that does not reveal detailed database errors to the user.", styles['Remediation'], bulletText='•'))
            else:
                story.append(Paragraph("<i>Note: Automated scans may not find all SQLi vulnerabilities, especially complex or blind ones. Manual testing and code review are recommended.</i>", styles['SmallNormal']))

        def render_xss(data):
            is_vuln = data.get('vulnerable', False)
            status_text = "Potential Cross-Site Scripting (XSS) Detected!" if is_vuln else "No XSS Detected (Based on Tested Payloads)"
            status_style = styles['ErrorText'] if is_vuln else styles['SuccessText']
            story.append(Paragraph(f"<b>Overall XSS Status:</b> {status_text}", status_style))

            tests = data.get('payloads', []) # Assuming payloads list contains test info now
            vulnerable_payloads_found = False
            if tests:
                story.append(Paragraph("XSS Test Details:", styles['SubTitle']))
                for test in tests:
                     test_vuln = test.get('vulnerable', False) # Need a flag per test if available
                     sev = "High" if test_vuln else "Info"
                     style_name = 'IssueHigh' if test_vuln else 'IssueInfo'
                     test_status = "Vulnerable" if test_vuln else "Not Vulnerable"
                     if test_vuln: vulnerable_payloads_found = True
                     
                     story.append(Paragraph(f"<b>Test Point:</b> {escape(test.get('type', 'N/A'))} ({test_status} - {sev})", style_name))
                     if test.get('parameter'): story.append(Paragraph(f"<b>Parameter/Location:</b> {escape(test.get('parameter'))}", styles['SmallNormal']))
                     if test.get('form_details'): story.append(Paragraph(f"<b>Form Tested:</b> {escape(test.get('form_details'))}", styles['SmallNormal']))
                     story.append(Paragraph(f"<b>Payload Tested:</b>", styles['SmallNormal']))
                     story.append(Paragraph(escape(test.get('payload', '')), styles['SmallCode']))
                     if test.get('evidence'): # Show evidence if found
                         story.append(Paragraph(f"<b>Evidence (e.g., Reflection in Response):</b>", styles['SmallNormal']))
                         story.append(Paragraph(escape(test.get('evidence', ''))[:500] + '...', styles['SmallCode']))
                         
                     story.append(Spacer(1, 0.2*cm))
            
            # If the overall status is vulnerable but no specific tests marked as such, add a note
            if is_vuln and not vulnerable_payloads_found and tests:
                 story.append(Paragraph("<i>Note: Overall status indicates vulnerability, but specific payload details might be missing. Review server logs and scanner output if available.</i>", styles['WarningText']))

            if is_vuln:
                 story.append(Paragraph("<b>Remediation:</b>", styles['SubTitle']))
                 story.append(Paragraph("• Implement Context-Aware Output Encoding for ALL user-supplied data displayed on the page. Use standard libraries designed for this (e.g., OWASP ESAPI, framework-specific functions).", styles['Remediation'], bulletText='•'))
                 story.append(Paragraph("• Use a strong Content Security Policy (CSP) to restrict where scripts can be loaded from and executed.", styles['Remediation'], bulletText='•'))
                 story.append(Paragraph("• Validate and sanitize user input on the server-side based on expected format and content.", styles['Remediation'], bulletText='•'))
                 story.append(Paragraph("• Set the `HttpOnly` flag on session cookies to prevent access via JavaScript.", styles['Remediation'], bulletText='•'))
                 story.append(Paragraph("• Keep frameworks and libraries up-to-date, as they often include XSS protections.", styles['Remediation'], bulletText='•'))
            else:
                 story.append(Paragraph("<i>Note: Automated scans may miss certain types of XSS (e.g., DOM-based, stored XSS requiring complex interaction). Manual testing and code review are recommended.</i>", styles['SmallNormal']))

        def render_discovery(data):
             discovery_data = data.get('discovery', {}) # Assuming results are nested under 'discovery'
             files_data = discovery_data.get('common_files', [])
             robots_data = discovery_data.get('robots_txt')
             sitemap_data = discovery_data.get('sitemap_xml')

             if not files_data and not robots_data and not sitemap_data:
                  story.append(Paragraph("No specific discovery files (e.g., robots.txt, sitemap.xml, common sensitive files) were found or analyzed.", styles['Normal']))
                  return

             story.append(Paragraph("Discovery File Analysis:", styles['SectionTitle']))

             # Robots.txt Analysis
             story.append(Paragraph("Robots.txt Analysis:", styles['SubTitle']))
             if robots_data:
                 story.append(Paragraph("Status: Found", styles['SuccessText']))
                 disallowed = robots_data.get('disallowed_paths', [])
                 if disallowed:
                     story.append(Paragraph(f"<b>Disallowed Paths ({len(disallowed)}):</b>", styles['Normal']))
                     # Display first few disallowed paths
                     display_paths = disallowed[:10]
                     paths_html = "<br/>".join([f"&nbsp;&nbsp;&nbsp;&nbsp;&bull; {escape(p)}" for p in display_paths])
                     if len(disallowed) > 10: paths_html += "<br/>&nbsp;&nbsp;&nbsp;&nbsp;... (and more)"
                     story.append(Paragraph(paths_html, styles['SmallNormal']))
                     story.append(Paragraph("<i>Note: Review disallowed paths. While intended for crawlers, they can sometimes reveal administrative or sensitive areas.</i>", styles['Remediation']))
                 else:
                     story.append(Paragraph("No 'Disallow' directives found.", styles['SmallNormal']))
                 
                 # Optionally show raw content snippet
                 if robots_data.get('content'):
                     story.append(Paragraph("<b>Raw Content Snippet:</b>", styles['SmallNormal']))
                     content_display = escape(robots_data['content'])
                     story.append(Paragraph(content_display[:500] + ('...' if len(content_display)>500 else ''), styles['SmallCode']))
             else:
                 story.append(Paragraph("Status: robots.txt not found or accessible.", styles['Normal']))
             story.append(Spacer(1, 0.3*cm))
             
             # Sitemap.xml Analysis
             story.append(Paragraph("Sitemap.xml Analysis:", styles['SubTitle']))
             if sitemap_data:
                 story.append(Paragraph("Status: Found and Parsed", styles['SuccessText']))
                 urls = sitemap_data # Assuming sitemap_data is the list of URLs directly
                 if urls:
                     story.append(Paragraph(f"<b>URLs Found ({len(urls)}):</b>", styles['Normal']))
                     # Display first few URLs
                     display_urls = urls[:20]
                     urls_html = "<br/>".join([f"&nbsp;&nbsp;&nbsp;&nbsp;&bull; {escape(u)}" for u in display_urls])
                     if len(urls) > 20: urls_html += f"<br/>&nbsp;&nbsp;&nbsp;&nbsp;... (and {len(urls) - 20} more)"
                     story.append(Paragraph(urls_html, styles['SmallCode'])) # Use code style for URLs
                     story.append(Paragraph("<i>Note: Sitemaps list URLs intended for indexing. Review for any unintentionally exposed pages or sensitive information within listed URLs.</i>", styles['Remediation']))
                 else:
                     story.append(Paragraph("No URLs found within the sitemap.", styles['SmallNormal']))
             else:
                 story.append(Paragraph("Status: sitemap.xml not found or could not be parsed.", styles['Normal']))
             story.append(Spacer(1, 0.3*cm))

             # Common Sensitive Files Check
             if files_data:
                 story.append(Paragraph("Common Sensitive File Checks:", styles['SubTitle']))
                 vulnerable_files_found = False
                 for file_info in files_data:
                     if file_info.get('status') == 200:
                         vulnerable_files_found = True
                         # Determine severity (can be refined)
                         sev = 'High' if any(f in file_info.get('file', '') for f in ['.git', '.svn', '.env', '.sql', 'config']) else 'Medium'
                         style_name = {'High': 'IssueHigh', 'Medium': 'IssueMedium'}.get(sev, 'IssueMedium')
                         story.append(Paragraph(f"<b>File Found:</b> {escape(file_info.get('file', 'N/A'))} ({sev})", style_name))
                         story.append(Paragraph(f"<b>URL:</b> {escape(file_info.get('url', 'N/A'))}", styles['SmallCode']))
                         story.append(Paragraph("<i>Description: This file might expose sensitive configuration, source code, or credentials.</i>", styles['SmallNormal']))
                         story.append(Paragraph("<i>Remediation: Ensure this file is not publicly accessible. Configure server access controls (e.g., deny rules in .htaccess, web.config, Nginx) to block access.</i>", styles['Remediation']))
                         story.append(Spacer(1, 0.2*cm))
                 
                 if not vulnerable_files_found:
                     story.append(Paragraph("No common sensitive files (like .git, .env, config files) were found accessible during this scan.", styles['SuccessText']))
             else:
                  # Only mention if scan was attempted but no files listed (might indicate error higher up)
                  if 'discovery' in scan_data.get('scans_performed', []):
                     story.append(Paragraph("Common sensitive file check results not available.", styles['Normal']))

        # Add sections based on scan data present in the JSON
        scan_render_map = {
            'header_scan': ("Security Headers", render_headers),
            'ssl_scan': ("SSL/TLS Information", render_ssl),
            'dns_info': ("DNS Information", render_dns),
            'whois_info': ("WHOIS Information", render_whois),
            'vulnerability_scan': ("Page Analysis", render_vuln),
            'csrf_scan': ("CSRF Protection Analysis", render_csrf),
            'sql_injection_scan': ("SQL Injection Analysis", render_sqli),
            'xss_scan': ("Cross-Site Scripting (XSS) Analysis", render_xss),
            'discovery_scan': ("Discovery Files", render_discovery)
        }
        
        for scan_key, (title, render_func) in scan_render_map.items():
            if scan_key in scan_data:
                 add_section(title, scan_data.get(scan_key), render_func)
        
        # ---- Add sections based on scan data present in the JSON ----
        # Define the order and mapping
        scan_render_map = [
            ('headers_scan', "Security Headers Analysis", render_headers),
            ('ssl_scan', "SSL/TLS Configuration", render_ssl),
            ('dns_scan', "DNS Information", render_dns), # Use dns_scan key
            ('whois_scan', "WHOIS Information", render_whois), # Use whois_scan key
            ('vuln_scan', "Common Vulnerability Analysis", render_vuln), # Use vuln_scan key
            ('csrf_scan', "CSRF Protection Analysis", render_csrf),
            ('sql_scan', "SQL Injection Analysis", render_sqli), # Use sql_scan key
            ('xss_scan', "Cross-Site Scripting (XSS) Analysis", render_xss),
            ('discovery_scan', "Discovery File Analysis", render_discovery)
        ]
        
        # Helper function remains the same, but call it within the loop below
        def add_section_content(title, data, render_func):
            story.append(Paragraph(escape(title), styles['SectionTitle']))
            if isinstance(data, dict) and data.get('status') == 'success':
                try:
                    render_func(data)
                except Exception as render_e:
                    logger.error(f"Error rendering PDF section '{title}': {render_e}", exc_info=True)
                    story.append(Paragraph(f"Error rendering section content: {escape(str(render_e))}", styles['ErrorText']))
            elif isinstance(data, dict) and data.get('status') == 'error':
                story.append(Paragraph(f"Scan failed: {escape(data.get('message', 'Unknown error'))}", styles['ErrorText']))
            elif isinstance(data, dict) and data.get('status') == 'timeout':
                story.append(Paragraph(f"Scan timed out.", styles['WarningText']))
            else:
                story.append(Paragraph(f"Could not determine scan status or data format is unexpected for {title}.", styles['WarningText']))
                logger.warning(f"Unexpected data format for section '{title}': {data}")
            story.append(Spacer(1, 0.5*cm))

        # Iterate and add sections if data exists
        for scan_key, title, render_func in scan_render_map:
             scan_result_data = scan_data.get(scan_key)
             scan_performed = scan_key.replace('_scan', '') in scan_data.get('scans_performed', [])
             
             if scan_result_data:
                  story.append(PageBreak()) # Start each major section on a new page
                  add_section_content(title, scan_result_data, render_func)
             elif scan_performed:
                 # Add a note if scan was performed but no data key exists (might indicate error or old format)
                 story.append(PageBreak())
                 story.append(Paragraph(escape(title), styles['SectionTitle']))
                 story.append(Paragraph(f"Note: Scan for '{title}' was performed, but detailed results key ('{scan_key}') was not found in the final data. The scan might have failed unexpectedly or the results structure is different.", styles['WarningText']))
                 story.append(Spacer(1, 0.5*cm))

        
        # ---- Build the PDF with Page Numbers ----
        def add_page_number(canvas, doc):
            "Add the page number to the bottom center of each page." # Docstring added
            page_num = canvas.getPageNumber()
            text = f"Page {page_num}"
            canvas.saveState()
            canvas.setFont('Helvetica', 9)
            canvas.setFillColor(colors.grey)
            # Position at bottom center
            canvas.drawCentredString(A4[0] / 2, 1.5*cm, text) 
            canvas.restoreState()

        # Pass the function to the build method
        doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)


        pdf_bytes = pdf_buffer.getvalue()
        pdf_buffer.close()

        # Create filename
        target_host = urlparse(scan_data.get('target_url', '')).hostname or 'scan'
        # Use current time for timestamp if scan timestamp is missing
        scan_timestamp = scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        timestamp_str = scan_timestamp.replace(':', '-').replace(' ', '_')
        filename = f"{target_host}_{timestamp_str}_report.pdf"

        # Create response
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"PDF Export Error (ReportLab): {e}", exc_info=True)
        return jsonify({"error": f"Failed to generate PDF report using ReportLab: {str(e)}"}), 500

# Add timeout wrapper function at the top of the file
def timeout_wrapper(func, timeout_seconds, *args, **kwargs):
    """Wrapper function to add timeout to any scan function"""
    try:
        with concurrent.futures.ThreadPoolExecutor(1) as executor:
            future = executor.submit(func, *args, **kwargs)
            return future.result(timeout=timeout_seconds)
    except concurrent.futures.TimeoutError:
        return {'status': 'timeout', 'message': f'Operation timed out after {timeout_seconds} seconds'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 