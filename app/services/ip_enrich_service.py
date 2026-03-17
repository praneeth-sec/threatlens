import requests

def enrich_ip(ip):

    result = {}

    # 🌍 IPINFO (location + ISP)
    try:
        ipinfo = requests.get(f"https://ipinfo.io/{ip}/json").json()

        result["country"] = ipinfo.get("country")
        result["city"] = ipinfo.get("city")
        result["org"] = ipinfo.get("org")
    except:
        pass

    # ⚠️ AbuseIPDB
    try:
        headers = {
            "Key": os.getenv("ABUSEIPDB_API_KEY"),
            "Accept": "application/json"
        }

        res = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
            headers=headers
        )

        data = res.json()["data"]

        result["abuse_score"] = data.get("abuseConfidenceScore")
    except:
        result["abuse_score"] = 0

    return result
