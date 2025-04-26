import os
import hashlib
import requests
import pandas as pd
from flask import Flask, request, jsonify, render_template, send_file
from datetime import datetime

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
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

# Function to get an available API key
def get_available_api_key():
    for key, usage in api_usage.items():
        if usage['count'] < usage['daily_limit']:
            return key
    return None

# Function to calculate SHA-256 hash for a file
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to check hash reputation on VirusTotal
def check_hash(hash_value):
    api_key = get_available_api_key()
    if not api_key:
        return {"hash": hash_value, "malicious": "Error", "suspicious": "Error", "harmless": "Error", "detections": "API Limit Exceeded"}

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json().get("data", {}).get("attributes", {})

        # Extract relevant details
        malicious = data.get("last_analysis_stats", {}).get("malicious", "Unknown")
        suspicious = data.get("last_analysis_stats", {}).get("suspicious", "Unknown")
        harmless = data.get("last_analysis_stats", {}).get("harmless", "Unknown")
        meaningful_name = data.get("meaningful_name", "N/A")

        # Get security vendor detections (if any)
        vendor_detections = [engine for engine, result in data.get("last_analysis_results", {}).items() if result["category"] == "malicious"]
        detections = ", ".join(vendor_detections) if vendor_detections else "No detections"

        api_usage[api_key]['count'] += 1

        return {
            "hash": hash_value,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "details": meaningful_name,
            "detections": detections
        }

    return {"hash": hash_value, "malicious": "Error", "suspicious": "Error", "harmless": "Error", "detections": "Not Found"}

# Function to process file upload
@app.route("/upload", methods=["POST"])
def upload_file():
    uploaded_files = request.files.getlist("files")
    results = []

    for file in uploaded_files:
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)
        
        hash_value = calculate_hash(file_path)
        result = check_hash(hash_value)
        results.append(result)

    df = pd.DataFrame(results)
    df.to_excel("file_scan_results.xlsx", index=False)

    return jsonify(results)

# Route to download results
@app.route("/download")
def download_file():
    return send_file("file_scan_results.xlsx", as_attachment=True)

# Route for Homepage
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=True) 