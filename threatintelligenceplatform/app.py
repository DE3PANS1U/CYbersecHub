from flask import Flask, render_template, request, jsonify
import requests
import json

app = Flask(__name__)

# Replace with your actual API key
API_KEY = "at_rY2D12FSf75R5RSlLAIHZrS3Az1US"
BASE_URL_V1 = "https://api.threatintelligenceplatform.com/v1/"
BASE_URL_V2 = "https://api.threatintelligenceplatform.com/v2/"

def make_api_call(base_url, endpoint, params=None):
    headers = {"Authorization": API_KEY}
    url = base_url + endpoint
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {e}"}

@app.route('/', methods=['GET', 'POST'])
def index():
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
            domain=domain
        )
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)