import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    raise ValueError("VirusTotal API key not set in environment variables")

headers = {
    "x-apikey": VT_API_KEY
}


# IP LOOKUP
def check_ip(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None

    data = response.json()

    return data["data"]["attributes"]["last_analysis_stats"]


# DOMAIN LOOKUP
def check_domain(domain):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None

    data = response.json()

    return data["data"]["attributes"]["last_analysis_stats"]
    
import base64

def check_url(url):

    headers = {
        "x-apikey": VT_API_KEY
    }

    # Encode URL in base64 (VirusTotal requirement)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(vt_url, headers=headers)

    if response.status_code != 200:
        return None

    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0)
    }

def check_hash(file_hash):

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None

    data = response.json()

    return data["data"]["attributes"]["last_analysis_stats"]
    data = response.json()

    return data["data"]["attributes"]["last_analysis_stats"]
