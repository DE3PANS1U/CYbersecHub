import os
import hashlib
import requests
import pandas as pd
from flask import Flask, request, jsonify, render_template, send_file

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# List of VirusTotal API keys (rotates keys when limits are reached)
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

        api_usage[api_key] += 1

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