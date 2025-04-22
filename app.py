from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import requests
import json
import pandas as pd
import re
import os
import hashlib
from werkzeug.utils import secure_filename

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

@app.route('/')
def index():
    return render_template('index.html')

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
    return render_template('File Reputation Checker/templates/index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    if filename.startswith('hash-checker'):
        return send_from_directory('Hash Reputation Checker/static', filename)
    elif filename.startswith('ip-checker'):
        return send_from_directory('IP Reputation Checker/static', filename)
    elif filename.startswith('file-checker'):
        return send_from_directory('File Reputation Checker/static', filename)
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
    if 'files' not in request.files:
        return jsonify({"error": "No files provided"})
    
    files = request.files.getlist('files')
    if not files:
        return jsonify({"error": "No files selected"})
    
    results = []
    for file in files:
        if file.filename == '':
            continue
        
        # Save the uploaded file
        file_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(file_path)
        
        try:
            # Calculate hash and check reputation
            hash_value = calculate_file_hash(file_path)
            result = check_hash(hash_value)
            result['filename'] = file.filename
            result['hash'] = hash_value
            results.append(result)
        except Exception as e:
            results.append({
                "filename": file.filename,
                "error": str(e)
            })
        finally:
            # Clean up the uploaded file
            try:
                os.remove(file_path)
            except:
                pass
    
    # Save results to Excel
    df = pd.DataFrame(results)
    df.to_excel('file_scan_results.xlsx', index=False)
    
    return jsonify(results)

@app.route('/download_file')
def download_file():
    return send_file('file_scan_results.xlsx', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 