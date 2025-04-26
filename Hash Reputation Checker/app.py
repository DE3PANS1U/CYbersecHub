from flask import Flask, request, jsonify, render_template, send_file
import requests
import json
import pandas as pd
import time
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# List of VirusTotal API keys (add multiple keys here)
API_KEYS = [
    "ddf12f573c2891adcaab881ddb75079bf3aa3141c4c9eb165794e523167fc071",
    "1a628d053b9cdb10169de5bb0fb6f1f83e05d972788a43763c54ceb22fbce659",
    "8d6b76c60f21fdf378efc21d390e3615699b4cff3d59d8ccf2f1a4c8dcdfe680",
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507"
]

def test_api_key(api_key):
    """Test if an API key is working by making a simple request"""
    url = "https://www.virustotal.com/api/v3/users/me"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            quota = data.get('data', {}).get('attributes', {}).get('quota', {})
            daily_quota = quota.get('daily', 0)
            monthly_quota = quota.get('monthly', 0)
            return True, f"API key is valid! Daily quota: {daily_quota}, Monthly quota: {monthly_quota}"
        elif response.status_code == 401:
            return False, "Invalid API key"
        elif response.status_code == 429:
            return False, "Rate limit exceeded"
        else:
            return False, f"API test failed with status code {response.status_code}"
    except Exception as e:
        return False, str(e)

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

# Test API keys on startup
for key in API_KEYS:
    is_valid, message = test_api_key(key)
    api_usage[key]['is_valid'] = is_valid
    api_usage[key]['validation_message'] = message
    print(f"API Key Test Result: {message}")

def get_api_usage_stats():
    """Get detailed statistics about API key usage"""
    current_time = datetime.now()
    stats = {}
    for key, usage in api_usage.items():
        stats[key] = {
            'requests_today': usage['count'],
            'daily_limit': usage['daily_limit'],
            'time_since_last_request': (current_time - usage['last_request_time']).total_seconds() if usage['last_request_time'] else None,
            'is_valid': usage['is_valid'],
            'validation_message': usage['validation_message'],
            'consecutive_failures': usage['consecutive_failures']
        }
    return stats

def get_available_api_key():
    """Get an available API key with proper rate limiting"""
    current_time = datetime.now()
    
    # Reset daily counts if 24 hours have passed
    for key, usage in api_usage.items():
        if (current_time - usage['last_reset']) > timedelta(days=1):
            usage['count'] = 0
            usage['last_reset'] = current_time
            usage['consecutive_failures'] = 0
    
    # Find first available key with proper timing
    for key, usage in api_usage.items():
        if not usage['is_valid']:
            continue
            
        if usage['count'] < usage['daily_limit']:
            if usage['last_request_time'] is None:
                return key
                
            time_since_last_request = (current_time - usage['last_request_time']).total_seconds()
            if time_since_last_request >= usage['min_request_interval']:
                return key
    
    return None

def check_hash(hash_value, max_retries=3):
    """Check a hash with improved rate limit handling"""
    api_key = get_available_api_key()
    if not api_key:
        return {"hash": hash_value, "malicious": "Error", "details": "No available API keys"}

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    for attempt in range(max_retries):
        try:
            # Check if we need to wait before making the request
            current_time = datetime.now()
            last_request_time = api_usage[api_key]['last_request_time']
            if last_request_time is not None:
                time_since_last_request = (current_time - last_request_time).total_seconds()
                if time_since_last_request < api_usage[api_key]['min_request_interval']:
                    wait_time = api_usage[api_key]['min_request_interval'] - time_since_last_request
                    time.sleep(wait_time)
            
            response = requests.get(url, headers=headers)
            api_usage[api_key]['last_request_time'] = datetime.now()
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                api_usage[api_key]['count'] += 1
                api_usage[api_key]['consecutive_failures'] = 0
                return {
                    "hash": hash_value,
                    "malicious": data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A'),
                    "details": data.get('attributes', {}).get('meaningful_name', 'N/A')
                }
            elif response.status_code == 429:
                # Get rate limit reset time from headers
                reset_time = response.headers.get('x-ratelimit-reset')
                if reset_time:
                    reset_timestamp = int(reset_time)
                    current_timestamp = int(datetime.now().timestamp())
                    wait_time = max(1, reset_timestamp - current_timestamp)
                    print(f"Rate limit hit. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    # If no reset time in headers, wait with exponential backoff
                    wait_time = min(300, 2 ** attempt * api_usage[api_key]['min_request_interval'])
                    print(f"Rate limit hit. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
            else:
                api_usage[api_key]['consecutive_failures'] += 1
                api_usage[api_key]['last_failure_time'] = datetime.now()
                return {"hash": hash_value, "malicious": "Error", "details": f"API request failed with status code {response.status_code}"}
                
        except Exception as e:
            api_usage[api_key]['consecutive_failures'] += 1
            api_usage[api_key]['last_failure_time'] = datetime.now()
            if attempt == max_retries - 1:
                return {"hash": hash_value, "malicious": "Error", "details": str(e)}
            time.sleep(5)  # Wait 5 seconds before retrying
    
    return {"hash": hash_value, "malicious": "Error", "details": "Max retries exceeded"}

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
            # No need for additional sleep here as check_hash handles rate limiting
        
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
            # No need for additional sleep here as check_hash handles rate limiting
        
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