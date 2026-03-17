import requests
import time
import os

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

def scan_url(url):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    data = {
        "url": url,
        "visibility": "public"
    }

    try:
        # submit scan
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=data
        )

        result = response.json()
        uuid = result.get("uuid")

        # wait for scan to complete
        time.sleep(5)

        screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"

        return {
            "uuid": uuid,
            "screenshot": screenshot_url,
            "result_url": f"https://urlscan.io/result/{uuid}"
        }

    except:
        return None
