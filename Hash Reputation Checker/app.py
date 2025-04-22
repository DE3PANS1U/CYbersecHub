from flask import Flask, request, jsonify, render_template, send_file
import requests
import json
import pandas as pd
import time
import os

app = Flask(__name__)

# List of VirusTotal API keys (add multiple keys here)
API_KEYS = [
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507"  # Replace with your API keys
]

# Dictionary to track API usage per key
api_usage = {key: 0 for key in API_KEYS}

# Function to get available API key
def get_available_api_key():
    for key, count in api_usage.items():
        if count < 500:
            return key
    return None

# Function to check hash reputation
def check_hash(hash_value):
    api_key = get_available_api_key()
    if not api_key:
        return {"hash": hash_value, "malicious": "Error", "details": "API Limit Exceeded"}

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('data', {})
            api_usage[api_key] += 1
            return {
                "hash": hash_value,
                "malicious": data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A'),
                "details": data.get('attributes', {}).get('meaningful_name', 'N/A')
            }
    except Exception as e:
        print(f"Error checking hash {hash_value}: {str(e)}")
    
    return {"hash": hash_value, "malicious": "Error", "details": "Not Found"}

# Function to process uploaded file
def read_hashes_from_file(file_path):
    try:
        df = pd.read_excel(file_path)
        return df['Hash'].dropna().tolist() if 'Hash' in df.columns else []
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return []

# Route for Homepage
@app.route('/')
def index():
    return render_template('index.html')

# Route to process hash input manually
@app.route('/process_hashes', methods=['POST'])
def process_hashes():
    try:
        input_text = request.form['input_text']
        hash_values = [h.strip() for h in input_text.strip().split("\n") if h.strip()]
        
        results = []
        for hash_value in hash_values:
            result = check_hash(hash_value)
            results.append(result)
            time.sleep(1)  # Rate limiting
        
        df = pd.DataFrame(results)
        df.to_excel('hash_scan_results.xlsx', index=False)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route for file uploads
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        file_path = "uploaded.xlsx"
        file.save(file_path)
        
        hash_values = read_hashes_from_file(file_path)
        results = []
        for hash_value in hash_values:
            result = check_hash(hash_value)
            results.append(result)
            time.sleep(1)  # Rate limiting
        
        df = pd.DataFrame(results)
        df.to_excel('hash_scan_results.xlsx', index=False)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to download results
@app.route('/download')
def download_file():
    try:
        return send_file('hash_scan_results.xlsx', 
                        as_attachment=True,
                        download_name='hash_scan_results.xlsx')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5002) 