import requests
import json
from datetime import datetime

def test_api_key(api_key):
    """Test if an API key is working by making a simple request"""
    url = "https://www.virustotal.com/api/v3/users/me"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        print(f"\nTesting API key: {api_key}")
        print("Making request to VirusTotal API...")
        
        response = requests.get(url, headers=headers)
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get quota information
            quota = attributes.get('quota', {})
            daily_quota = quota.get('daily', 0)
            monthly_quota = quota.get('monthly', 0)
            daily_used = quota.get('daily_used', 0)
            monthly_used = quota.get('monthly_used', 0)
            
            # Calculate remaining quota
            daily_remaining = daily_quota - daily_used if daily_quota > 0 else 0
            monthly_remaining = monthly_quota - monthly_used if monthly_quota > 0 else 0
            
            # Get user information
            user_since = datetime.fromtimestamp(attributes.get('user_since', 0))
            first_name = attributes.get('first_name', 'Unknown')
            last_name = attributes.get('last_name', 'Unknown')
            status = attributes.get('status', 'Unknown')
            reputation = attributes.get('reputation', 0)
            
            print("\nAPI Key is VALID!")
            print("\n=== User Information ===")
            print(f"Name: {first_name} {last_name}")
            print(f"Status: {status}")
            print(f"User since: {user_since.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Reputation: {reputation}")
            
            print("\n=== Quota Information ===")
            print(f"Daily quota: {daily_quota}")
            print(f"Daily used: {daily_used}")
            print(f"Daily remaining: {daily_remaining}")
            print(f"Monthly quota: {monthly_quota}")
            print(f"Monthly used: {monthly_used}")
            print(f"Monthly remaining: {monthly_remaining}")
            
            # Calculate usage percentage
            if daily_quota > 0:
                daily_percentage = (daily_used / daily_quota) * 100
                print(f"Daily usage: {daily_percentage:.2f}%")
            if monthly_quota > 0:
                monthly_percentage = (monthly_used / monthly_quota) * 100
                print(f"Monthly usage: {monthly_percentage:.2f}%")
            
            # Get API limits from headers
            rate_limit = response.headers.get('x-ratelimit-limit', 'Unknown')
            rate_remaining = response.headers.get('x-ratelimit-remaining', 'Unknown')
            rate_reset = response.headers.get('x-ratelimit-reset', 'Unknown')
            
            print("\n=== Rate Limit Information ===")
            print(f"Rate limit: {rate_limit}")
            print(f"Rate remaining: {rate_remaining}")
            if rate_reset != 'Unknown':
                reset_time = datetime.fromtimestamp(int(rate_reset))
                print(f"Rate reset time: {reset_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            print("\n=== Full Response ===")
            print(json.dumps(data, indent=2))
            
        elif response.status_code == 401:
            print("\nAPI Key is INVALID!")
            print("Please check your API key and try again.")
        elif response.status_code == 429:
            print("\nRATE LIMIT EXCEEDED!")
            print("Please wait a few minutes before trying again.")
            # Get rate limit reset time from headers
            rate_reset = response.headers.get('x-ratelimit-reset', 'Unknown')
            if rate_reset != 'Unknown':
                reset_time = datetime.fromtimestamp(int(rate_reset))
                print(f"Rate limit will reset at: {reset_time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print(f"\nError: {response.status_code}")
            print("Response:", response.text)
            
    except Exception as e:
        print(f"\nError occurred: {str(e)}")

def test_ip_check(api_key, ip_address):
    """Test IP address checking with VirusTotal API"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        print(f"\nChecking IP address: {ip_address}")
        print("Making request to VirusTotal API...")
        
        response = requests.get(url, headers=headers)
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get analysis stats
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            
            # Get network information
            as_owner = attributes.get('as_owner', 'Unknown')
            country = attributes.get('country', 'Unknown')
            continent = attributes.get('continent', 'Unknown')
            
            print("\n=== IP Analysis Results ===")
            print(f"IP Address: {ip_address}")
            print(f"AS Owner: {as_owner}")
            print(f"Country: {country}")
            print(f"Continent: {continent}")
            
            print("\n=== Security Analysis ===")
            print(f"Malicious: {malicious}")
            print(f"Suspicious: {suspicious}")
            print(f"Harmless: {harmless}")
            print(f"Undetected: {undetected}")
            
            # Get rate limit information
            rate_limit = response.headers.get('x-ratelimit-limit', 'Unknown')
            rate_remaining = response.headers.get('x-ratelimit-remaining', 'Unknown')
            rate_reset = response.headers.get('x-ratelimit-reset', 'Unknown')
            
            print("\n=== Rate Limit Information ===")
            print(f"Rate limit: {rate_limit}")
            print(f"Rate remaining: {rate_remaining}")
            if rate_reset != 'Unknown':
                reset_time = datetime.fromtimestamp(int(rate_reset))
                print(f"Rate reset time: {reset_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            print("\n=== Full Response ===")
            print(json.dumps(data, indent=2))
            
        elif response.status_code == 401:
            print("\nAPI Key is INVALID!")
            print("Please check your API key and try again.")
        elif response.status_code == 429:
            print("\nRATE LIMIT EXCEEDED!")
            print("Please wait a few minutes before trying again.")
            rate_reset = response.headers.get('x-ratelimit-reset', 'Unknown')
            if rate_reset != 'Unknown':
                reset_time = datetime.fromtimestamp(int(rate_reset))
                print(f"Rate limit will reset at: {reset_time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print(f"\nError: {response.status_code}")
            print("Response:", response.text)
            
    except Exception as e:
        print(f"\nError occurred: {str(e)}")

def test_hash_check(api_key, hash_value):
    """Test hash checking with VirusTotal API"""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        print(f"\nChecking hash: {hash_value}")
        print("Making request to VirusTotal API...")
        
        response = requests.get(url, headers=headers)
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get analysis stats
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            
            # Get file information
            file_name = attributes.get('meaningful_name', 'Unknown')
            file_size = attributes.get('size', 'Unknown')
            file_type = attributes.get('type_description', 'Unknown')
            
            print("\n=== Hash Analysis Results ===")
            print(f"Hash: {hash_value}")
            print(f"File Name: {file_name}")
            print(f"File Size: {file_size} bytes")
            print(f"File Type: {file_type}")
            
            print("\n=== Security Analysis ===")
            print(f"Malicious: {malicious}")
            print(f"Suspicious: {suspicious}")
            print(f"Harmless: {harmless}")
            print(f"Undetected: {undetected}")
            
            # Get rate limit information
            rate_limit = response.headers.get('x-ratelimit-limit', 'Unknown')
            rate_remaining = response.headers.get('x-ratelimit-remaining', 'Unknown')
            rate_reset = response.headers.get('x-ratelimit-reset', 'Unknown')
            
            print("\n=== Rate Limit Information ===")
            print(f"Rate limit: {rate_limit}")
            print(f"Rate remaining: {rate_remaining}")
            if rate_reset != 'Unknown':
                reset_time = datetime.fromtimestamp(int(rate_reset))
                print(f"Rate reset time: {reset_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            print("\n=== Full Response ===")
            print(json.dumps(data, indent=2))
            
        elif response.status_code == 401:
            print("\nAPI Key is INVALID!")
            print("Please check your API key and try again.")
        elif response.status_code == 429:
            print("\nRATE LIMIT EXCEEDED!")
            print("Please wait a few minutes before trying again.")
            rate_reset = response.headers.get('x-ratelimit-reset', 'Unknown')
            if rate_reset != 'Unknown':
                reset_time = datetime.fromtimestamp(int(rate_reset))
                print(f"Rate limit will reset at: {reset_time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print(f"\nError: {response.status_code}")
            print("Response:", response.text)
            
    except Exception as e:
        print(f"\nError occurred: {str(e)}")

if __name__ == "__main__":
    # Your API key
    api_key = "8d6b76c60f21fdf378efc21d390e3615699b4cff3d59d8ccf2f1a4c8dcdfe680"
    
    # Test the API key
    test_api_key(api_key)
    
    # IP address to check
    ip_address = "8.8.8.8"
    
    # Test the IP check
    test_ip_check(api_key, ip_address)
    
    # Hash to check
    hash_value = "fff3948c3d832bde1ed6db47a4cbf779"
    
    # Test the hash check
    test_hash_check(api_key, hash_value) 