from flask import Flask, request, jsonify, render_template, send_file
import requests
import json
import pandas as pd
import re
import time
import os

app = Flask(__name__)

# List of API keys (modify accordingly)
API_KEYS = [
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507",
    "e3e42d3ebb396d5c2f7f505ab1885bf7820474737caf6fba602eee27cdcecaa8",
    "1a628d053b9cdb10169de5bb0fb6f1f83e05d972788a43763c54ceb22fbce659",
    "ddf12f573c2891adcaab881ddb75079bf3aa3141c4c9eb165794e523167fc071"
]  # Replace with actual API keys # Replace with actual API keys

# Dictionary to track API usage per key
api_usage = {key: 0 for key in API_KEYS}

# Function to get available API key
def get_available_api_key():
    for key, count in api_usage.items():
        if count < 500:  # Daily limit per key
            return key
    return None

# Function to extract IP addresses
def extract_ips(input_text):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return ip_pattern.findall(input_text)

# Function to check IP reputation
def check_ip(ip):
    api_key = get_available_api_key()
    if not api_key:
        return {
            "ip": ip,
            "malicious": 0,
            "suspicious": 0,
            "as_owner": "Error",
            "country": "Error"
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            api_usage[api_key] += 1
            return {
                "ip": ip,
                "malicious": attributes.get('last_analysis_stats', {}).get('malicious', 0),
                "suspicious": attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                "as_owner": attributes.get('as_owner', 'Unknown'),
                "country": attributes.get('country', 'Unknown')
            }
    except Exception as e:
        print(f"Error checking IP {ip}: {str(e)}")
    
    return {
        "ip": ip,
        "malicious": 0,
        "suspicious": 0,
        "as_owner": "Error",
        "country": "Error"
    }

# Function to process uploaded file
def read_ips_from_file(file_path):
    try:
        if file_path.endswith('.xlsx'):
            df = pd.read_excel(file_path)
        elif file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        else:
            with open(file_path, 'r') as f:
                content = f.read()
                return extract_ips(content)
        
        # Try common column names for IPs
        ip_columns = ['IP', 'ip', 'IP Address', 'ip_address', 'Client IP', 'Source IP']
        for col in ip_columns:
            if col in df.columns:
                return df[col].dropna().astype(str).tolist()
        
        # If no known columns found, try to find IPs in all string columns
        text_data = ' '.join(df.select_dtypes(include=['object']).values.flatten().astype(str))
        return extract_ips(text_data)
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return []

# Route for Homepage
@app.route('/')
def index():
    return render_template('ip-checker.html')

# Route to process IP input
@app.route('/process_ips', methods=['POST'])
def process_ips():
    try:
        input_text = request.form.get('input_text', '').strip()
        if not input_text:
            return jsonify({"error": "No input provided", "results": []}), 400

        ip_addresses = extract_ips(input_text)
        if not ip_addresses:
            return jsonify({"error": "No valid IP addresses found", "results": []}), 400

        results = []
        for ip in ip_addresses:
            result = check_ip(ip)
            results.append(result)
            time.sleep(1)  # Rate limiting

        # Save results to Excel
        df = pd.DataFrame(results)
        df.to_excel('ip_scan_results.xlsx', index=False)

        return jsonify({"message": "Success", "results": results})

    except Exception as e:
        return jsonify({"error": str(e), "results": []}), 500

# Route for file uploads
@app.route('/upload_ip', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded", "results": []}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected", "results": []}), 400
            
        # Save the file temporarily
        file_path = "uploaded_ip.xlsx"
        file.save(file_path)
        
        ip_addresses = read_ips_from_file(file_path)
        if not ip_addresses:
            return jsonify({"error": "No valid IP addresses found in file", "results": []}), 400

        results = []
        for ip in ip_addresses:
            result = check_ip(ip)
            results.append(result)
            time.sleep(1)  # Rate limiting

        # Save results to Excel
        df = pd.DataFrame(results)
        df.to_excel('ip_scan_results.xlsx', index=False)

        return jsonify({"message": "Success", "results": results})

    except Exception as e:
        return jsonify({"error": str(e), "results": []}), 500

# Route to download results
@app.route('/download_results')
def download_file():
    try:
        return send_file('ip_scan_results.xlsx', 
                        as_attachment=True,
                        download_name='ip_scan_results.xlsx')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5001) 
