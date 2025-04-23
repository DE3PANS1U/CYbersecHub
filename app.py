from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
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

app = Flask(__name__)

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# VirusTotal API keys
API_KEYS = [
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507"
]

# Dictionary to track API usage
api_usage = {key: 0 for key in API_KEYS}

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
    
    # Save results to Excel
    df = pd.DataFrame(results)
    df.to_excel('hash_scan_results.xlsx', index=False)
    
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
            file_path = 'temp_upload.xlsx'
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

        # Save results to Excel for download
        if results:
            app.logger.info('Saving results to Excel')
            df = pd.DataFrame(results)
            df.to_excel('ip_scan_results.xlsx', index=False)

        app.logger.info(f'Final results: {results}')
        response = {'results': results}
        app.logger.info(f'Sending response: {response}')
        return jsonify(response)
    except Exception as e:
        app.logger.error(f'Error in upload_ip: {str(e)}')
        return jsonify({'results': []})

@app.route('/download_ip')
def download_ip():
    return send_file('ip_scan_results.xlsx', as_attachment=True)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"})
    
    if not file.filename.endswith('.xlsx'):
        return jsonify({"error": "Only Excel files are supported"})
    
    try:
        # Save the uploaded file
        file_path = 'uploaded.xlsx'
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
            else:
                result['hash'] = hash_value
            results.append(result)
        
        # Save results to Excel
        df = pd.DataFrame(results)
        # Convert numeric columns to integers
        numeric_columns = ['malicious', 'suspicious', 'harmless', 'undetected']
        for col in numeric_columns:
            if col in df.columns:
                df[col] = df[col].fillna(0).astype(int)
        df.to_excel('hash_scan_results.xlsx', index=False)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/download')
def download():
    return send_file('hash_scan_results.xlsx', as_attachment=True)

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
            
            # Save results to Excel for download
            df = pd.DataFrame([{
                'filename': filename,
                'hash': file_hash,
                'malicious': result.get('malicious', 0),
                'suspicious': result.get('suspicious', 0),
                'harmless': result.get('harmless', 0),
                'undetected': result.get('undetected', 0)
            }])
            df.to_excel('file_scan_results.xlsx', index=False)
        
        # Clean up the temporary file
        os.remove(file_path)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/download_file')
def download_file():
    try:
        if not os.path.exists('file_scan_results.xlsx'):
            return jsonify({"error": "No results available to download"}), 404
            
        return send_file(
            'file_scan_results.xlsx',
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
    
    # Save results to Excel
    try:
        df = pd.DataFrame(results)
        df.to_excel('url_scan_results.xlsx', index=False)
    except Exception as e:
        app.logger.error(f"Error saving results to Excel: {str(e)}")
    
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
        
        # Save results to Excel
        try:
            df = pd.DataFrame(results)
            df.to_excel('url_scan_results.xlsx', index=False)
        except Exception as e:
            app.logger.error(f"Error saving results to Excel: {str(e)}")
        
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
    return send_file('url_scan_results.xlsx', as_attachment=True)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 