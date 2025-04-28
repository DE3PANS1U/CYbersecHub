from flask import Flask, render_template, request, jsonify
import requests
import json
import random

app = Flask(__name__)

# Replace with your actual API key
API_KEY = "at_rY2D12FSf75R5RSlLAIHZrS3Az1US"
BASE_URL_V1 = "https://api.threatintelligenceplatform.com/v1/"
BASE_URL_V2 = "https://api.threatintelligenceplatform.com/v2/"
ALIENVAULT_OTX_API_KEY = "87cc55de9e3285ad8e63ac6d221d3b07cb658128bc241f2e4eb907b6ba802be3"
THREATFOX_API_KEY = "40bf1afab89f555cf74c135da92f2f65b07991a82412a878"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

def make_api_call(base_url, endpoint, params=None):
    headers = {"Authorization": API_KEY}
    url = base_url + endpoint
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {e}"}

def fetch_alienvault_otx_pulses():
    url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'  # Use subscribed pulses endpoint
    headers = {'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if 'results' in data and isinstance(data['results'], list):
            random.shuffle(data['results'])
        return data
    else:
        return {"error": response.text}

# --- OTX API: Additional Endpoints ---
def fetch_otx_indicators():
    url = 'https://otx.alienvault.com/api/v1/indicators'
    headers = {'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else {"error": response.text}

def fetch_otx_pulse_details(pulse_id):
    url = f'https://otx.alienvault.com/api/v1/pulses/{pulse_id}'
    headers = {'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else {"error": response.text}

def fetch_otx_pulse_indicators(pulse_id):
    url = f'https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators'
    headers = {'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else {"error": response.text}

def fetch_otx_search_pulses(query):
    url = f'https://otx.alienvault.com/api/v1/search/pulses?q={query}'
    headers = {'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else {"error": response.text}

def fetch_otx_user_info(username):
    url = f'https://otx.alienvault.com/api/v1/users/{username}'
    headers = {'X-OTX-API-KEY': ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else {"error": response.text}

def fetch_threatfox_recent_iocs(days=1):
    headers = {
        "Auth-Key": THREATFOX_API_KEY,
        "Content-Type": "application/json"
    }
    data = {"query": "get_iocs", "days": days}
    try:
        response = requests.post(THREATFOX_API_URL, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"ThreatFox API request failed: {e}"}

@app.route('/', methods=['GET', 'POST'])
def index():
    otx_data = fetch_alienvault_otx_pulses()  # Fetch live feed
    if request.method == 'POST':
        domain = request.form['domainName']
        infrastructure_data = make_api_call(BASE_URL_V1, "infrastructureAnalysis", {"domainName": domain})
        print("[DEBUG] infrastructure_data:", infrastructure_data)
        ssl_chain_data = make_api_call(BASE_URL_V1, "sslCertificatesChain", {"domainName": domain})
        print("[DEBUG] ssl_chain_data:", ssl_chain_data)
        ssl_config_data = make_api_call(BASE_URL_V1, "sslConfiguration", {"domainName": domain})
        print("[DEBUG] ssl_config_data:", ssl_config_data)
        malware_check_data = make_api_call(BASE_URL_V1, "malwareCheck", {"domainName": domain})
        print("[DEBUG] malware_check_data:", malware_check_data)
        connected_domains_data = make_api_call(BASE_URL_V1, "connectedDomains", {"domainName": domain})
        print("[DEBUG] connected_domains_data:", connected_domains_data)
        reputation_v1_data = make_api_call(BASE_URL_V1, "reputation", {"domainName": domain, "mode": "fast"})
        print("[DEBUG] reputation_v1_data:", reputation_v1_data)

        return render_template(
            'index.html',
            infrastructure=infrastructure_data,
            ssl_chain=ssl_chain_data,
            ssl_config=ssl_config_data,
            malware_check=malware_check_data,
            connected_domains=connected_domains_data,
            reputation_v1=reputation_v1_data,
            domain=domain,
            otx_data=otx_data
        )
    return render_template('index.html', otx_data=otx_data)

@app.route('/otx-live-feed')
def otx_live_feed():
    data = fetch_alienvault_otx_pulses()
    return render_template('live_feed.html', data=data)

@app.route('/otx/indicators')
def otx_indicators():
    data = fetch_otx_indicators()
    return jsonify(data)

@app.route('/otx/pulse/<pulse_id>')
def otx_pulse_details(pulse_id):
    data = fetch_otx_pulse_details(pulse_id)
    return jsonify(data)

@app.route('/otx/pulse/<pulse_id>/indicators')
def otx_pulse_indicators(pulse_id):
    data = fetch_otx_pulse_indicators(pulse_id)
    return jsonify(data)

@app.route('/otx/search/pulses')
def otx_search_pulses():
    query = request.args.get('q', '')
    data = fetch_otx_search_pulses(query)
    return jsonify(data)

@app.route('/otx/user/<username>')
def otx_user_info(username):
    data = fetch_otx_user_info(username)
    return jsonify(data)

@app.route('/threatfox/recent-iocs')
def threatfox_recent_iocs():
    data = fetch_threatfox_recent_iocs()
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)