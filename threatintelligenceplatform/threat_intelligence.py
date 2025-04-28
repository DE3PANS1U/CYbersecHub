from flask import Blueprint, render_template, request, jsonify, send_file
import requests
import json
import random
import os
import hashlib
from datetime import datetime, timedelta
import pandas as pd
from werkzeug.utils import secure_filename

threat_bp = Blueprint('threat_intelligence', __name__, 
                     template_folder='templates',
                     static_folder='static',
                     url_prefix='/threat-intelligence')

# API Configuration
API_KEY = "at_rY2D12FSf75R5RSlLAIHZrS3Az1US"
BASE_URL_V1 = "https://api.threatintelligenceplatform.com/v1/"
BASE_URL_V2 = "https://api.threatintelligenceplatform.com/v2/"
ALIENVAULT_OTX_API_KEY = "87cc55de9e3285ad8e63ac6d221d3b07cb658128bc241f2e4eb907b6ba802be3"
THREATFOX_API_KEY = "40bf1afab89f555cf74c135da92f2f65b07991a82412a878"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWARE_BAZAAR_API_KEY = "YOUR_MALWARE_BAZAAR_API_KEY"
MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/"

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def make_api_call(base_url, endpoint, params=None):
    headers = {"Authorization": API_KEY}
    url = base_url + endpoint
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {e}"}

def fetch_alienvault_otx_pulses():
    url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
    headers = {'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if 'results' in data and isinstance(data['results'], list):
            random.shuffle(data['results'])
        return data
    else:
        return {"error": response.text}

def check_abuseipdb(ip_address):
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    try:
        response = requests.get(f"{ABUSEIPDB_URL}check", headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"AbuseIPDB API request failed: {e}"}

def check_malware_bazaar(hash_value):
    headers = {
        'API-KEY': MALWARE_BAZAAR_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'query': 'get_info',
        'hash': hash_value
    }
    try:
        response = requests.post(MALWARE_BAZAAR_URL, headers=headers, data=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"MalwareBazaar API request failed: {e}"}

def analyze_file(file_path):
    results = {
        "file_info": {},
        "hash_analysis": {},
        "threat_analysis": {}
    }
    
    # Get file information
    file_stats = os.stat(file_path)
    results["file_info"] = {
        "size": file_stats.st_size,
        "created": datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        "modified": datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Calculate file hashes
    with open(file_path, 'rb') as f:
        file_content = f.read()
        results["hash_analysis"] = {
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest()
        }
    
    # Check hashes against threat intelligence
    for hash_type, hash_value in results["hash_analysis"].items():
        threat_data = check_malware_bazaar(hash_value)
        if "error" not in threat_data:
            results["threat_analysis"][hash_type] = threat_data
    
    return results

@threat_bp.route('/', methods=['GET', 'POST'])
def index():
    otx_data = fetch_alienvault_otx_pulses()
    if request.method == 'POST':
        if 'domainName' in request.form:
            domain = request.form['domainName']
            infrastructure_data = make_api_call(BASE_URL_V1, "infrastructureAnalysis", {"domainName": domain})
            ssl_chain_data = make_api_call(BASE_URL_V1, "sslCertificatesChain", {"domainName": domain})
            ssl_config_data = make_api_call(BASE_URL_V1, "sslConfiguration", {"domainName": domain})
            malware_check_data = make_api_call(BASE_URL_V1, "malwareCheck", {"domainName": domain})
            connected_domains_data = make_api_call(BASE_URL_V1, "connectedDomains", {"domainName": domain})
            reputation_v1_data = make_api_call(BASE_URL_V1, "reputation", {"domainName": domain, "mode": "fast"})
            
            return render_template(
                'threatintelligenceplatform/index.html',
                infrastructure=infrastructure_data,
                ssl_chain=ssl_chain_data,
                ssl_config=ssl_config_data,
                malware_check=malware_check_data,
                connected_domains=connected_domains_data,
                reputation_v1=reputation_v1_data,
                domain=domain,
                otx_data=otx_data
            )
        elif 'ipAddress' in request.form:
            ip_address = request.form['ipAddress']
            abuseipdb_data = check_abuseipdb(ip_address)
            return render_template(
                'threatintelligenceplatform/index.html',
                ip_data=abuseipdb_data,
                ip_address=ip_address,
                otx_data=otx_data
            )
    return render_template('threatintelligenceplatform/index.html', otx_data=otx_data)

@threat_bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"})
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    
    try:
        analysis_results = analyze_file(file_path)
        return jsonify(analysis_results)
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

@threat_bp.route('/otx-live-feed')
def otx_live_feed():
    data = fetch_alienvault_otx_pulses()
    return render_template('threatintelligenceplatform/live_feed.html', data=data)

@threat_bp.route('/threatfox/recent-iocs')
def threatfox_recent_iocs():
    headers = {
        "Auth-Key": THREATFOX_API_KEY,
        "Content-Type": "application/json"
    }
    data = {"query": "get_iocs", "days": 1}
    try:
        response = requests.post(THREATFOX_API_URL, headers=headers, json=data)
        response.raise_for_status()
        iocs = response.json()
        # If the request is from a browser, render the template
        if request.accept_mimetypes.accept_html:
            return render_template('threatintelligenceplatform/threatfox_iocs.html', iocs=iocs)
        # Otherwise, return JSON (for API/AJAX)
        return jsonify(iocs)
    except requests.exceptions.RequestException as e:
        error = {"error": f"ThreatFox API request failed: {e}"}
        if request.accept_mimetypes.accept_html:
            return render_template('threatintelligenceplatform/threatfox_iocs.html', iocs=error)
        return jsonify(error)

@threat_bp.route('/historical-data')
def historical_data():
    # Get historical data from the last 30 days
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    
    # Fetch historical data from various sources
    historical_data = {
        "otx_pulses": fetch_alienvault_otx_pulses(),
        "threatfox_iocs": get_threatfox_historical_data(start_date, end_date)
    }
    
    return render_template('threatintelligenceplatform/historical.html', data=historical_data)

def get_threatfox_historical_data(start_date, end_date):
    headers = {
        "Auth-Key": THREATFOX_API_KEY,
        "Content-Type": "application/json"
    }
    data = {
        "query": "get_iocs",
        "start_date": start_date.strftime('%Y-%m-%d'),
        "end_date": end_date.strftime('%Y-%m-%d')
    }
    try:
        response = requests.post(THREATFOX_API_URL, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"ThreatFox historical data request failed: {e}"} 