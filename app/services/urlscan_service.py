import requests
import time
import os

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

def scan_url(url):
    try:
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }

        data = {
            "url": url,
            "visibility": "public"
        }

        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=data,
            timeout=5
        )

        if response.status_code != 200:
            return None

        uuid = response.json().get("uuid")

        if not uuid:
            return None

        # 🔥 WAIT for scan to complete
        time.sleep(5)

        result_url = f"https://urlscan.io/api/v1/result/{uuid}/"

        result = requests.get(result_url, timeout=5)

        if result.status_code != 200:
            return None

        data = result.json()

        screenshot = data.get("task", {}).get("screenshotURL")

        return {
            "screenshot": screenshot,
            "result_url": f"https://urlscan.io/result/{uuid}/"
        }

    except Exception as e:
        print("URLScan error:", e)
        return None
