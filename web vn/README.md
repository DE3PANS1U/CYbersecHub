# Web Vulnerability Scanner

A web-based vulnerability scanner that analyzes websites for common security issues, SSL/TLS configuration, and open ports.

## Features

- Security Headers Analysis
- SSL/TLS Certificate Information
- Open Port Detection
- Modern and User-friendly Interface
- Real-time Scanning Results

## Requirements

- Python 3.7+
- Flask
- Requests
- BeautifulSoup4
- python-nmap
- urllib3

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd web-vulnerability-scanner
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. Enter the target website URL in the input field (e.g., example.com)
2. Click the "Scan" button
3. Wait for the scan to complete
4. Review the results displayed in the following sections:
   - Target Information
   - Security Headers
   - SSL/TLS Information
   - Open Ports

## Security Note

This tool is intended for educational and testing purposes only. Always obtain proper authorization before scanning any website or system.

## License

MIT License 