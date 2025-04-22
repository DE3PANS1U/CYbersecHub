# IP Reputation Checker

A tool to check IP addresses against VirusTotal's database for security analysis. Part of the Cybersecurity Tools Hub.

## Features

- Check individual IP addresses or multiple IPs at once
- Upload Excel files containing IP addresses
- View detailed reputation information including malicious score and AS label
- Download results in Excel format
- Modern, responsive interface with drag-and-drop file upload

## Setup

1. Install the required Python packages:
```bash
pip install -r requirements.txt
```

2. Configure your VirusTotal API key:
- Open `app.py`
- Replace `"your_api_key_1"` with your actual VirusTotal API key
- You can add multiple API keys for better rate limiting handling

3. Run the application:
```bash
python app.py
```

4. Access the tool at `http://localhost:5001`

## Usage

### Manual IP Check
1. Enter one or more IP addresses in the text area (one per line)
2. Click "Check IPs"
3. View results in the table below

### Excel File Upload
1. Prepare an Excel file with a column named "Client Ip"
2. Either drag and drop the file or click to browse
3. Click "Upload & Check"
4. View results and download the complete report

## Rate Limiting

The tool implements rate limiting to comply with VirusTotal's API restrictions:
- 4 requests per minute for the free API
- 500 requests per day per API key
- Multiple API keys can be configured for higher limits

## Notes

- Requires a valid VirusTotal API key
- Excel files must have a column named "Client Ip"
- Results are cached in 'ip_scan_results.xlsx' 