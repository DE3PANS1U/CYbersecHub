from flask import Flask, request, jsonify, render_template, send_file
import requests
import json
import pandas as pd
import time
import os
import base64

app = Flask(__name__)

# List of VirusTotal API keys (add multiple keys here)
API_KEYS = [
    "64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507"
]

# Dictionary to track API usage per key
api_usage = {key: 0 for key in API_KEYS}

# Function to get an available API key
def get_available_api_key():
    for key, count in api_usage.items():
        if count < 500:
            return key
    return None

# Function to encode URL in base64 (as required by VirusTotal)
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# Function to check URL reputation
def check_url(url):
    api_key = get_available_api_key()
    if not api_key:
        return {"url": url, "malicious": "Error", "details": "API Limit Exceeded"}

    encoded_url = encode_url(url)
    url_vt = "https://www.virustotal.com/api/v3/urls"

    headers = {"accept": "application/json", "x-apikey": api_key}
    data = {"url": url}

    response = requests.post(url_vt, headers=headers, data=data)

    if response.status_code == 200:
        result = response.json()
        url_id = result["data"]["id"]

        # Fetch detailed report using the URL ID
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code == 200:
            data = report_response.json().get("data", {})
            api_usage[api_key] += 1
            return {
                "url": url,
                "malicious": data.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", "N/A"),
                "details": data.get("attributes", {}).get("title", "N/A")
            }

    return {"url": url, "malicious": "Error", "details": "Not Found"}

# Function to process uploaded file
def read_urls_from_file(file_path):
    df = pd.read_excel(file_path)
    return df['URL'].dropna().tolist() if 'URL' in df.columns else []

# Route for Homepage
@app.route('/')
def index():
    return render_template('index.html')

# Route to process URL input manually
@app.route('/process_urls', methods=['POST'])
def process_urls():
    input_text = request.form['input_text']
    urls = input_text.strip().split("\n")
    
    results = [check_url(url.strip()) for url in urls]
    df = pd.DataFrame(results)
    df.to_excel('url_scan_results.xlsx', index=False)
    
    return jsonify(results)

# Route for file uploads
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file_path = "uploaded.xlsx"
    file.save(file_path)
    
    urls = read_urls_from_file(file_path)
    results = [check_url(url.strip()) for url in urls]
    df = pd.DataFrame(results)
    df.to_excel('url_scan_results.xlsx', index=False)
    
    return jsonify(results)

# Route to download results
@app.route('/download')
def download_file():
    return send_file('url_scan_results.xlsx', as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, port=5003) 