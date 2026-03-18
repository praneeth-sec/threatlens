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
            timeout=10
        )

        if response.status_code != 200:
            print("Scan submit failed:", response.text)
            return None

        uuid = response.json().get("uuid")

        if not uuid:
            return None

        result_api = f"https://urlscan.io/api/v1/result/{uuid}/"

        # 🔥 FIX 1: wait properly (instead of fixed sleep)
        for _ in range(10):  # retry ~20 seconds
            result = requests.get(result_api, timeout=10)

            if result.status_code == 200:
                data = result.json()

                # 🔥 FIX 2: correct screenshot path
                screenshot = data.get("page", {}).get("screenshot")

                if screenshot:
                    return {
                        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
                        "result_url": f"https://urlscan.io/result/{uuid}/"
                    }

            time.sleep(2)

        # fallback if screenshot not ready
        return {
            "screenshot": None,
            "result_url": f"https://urlscan.io/result/{uuid}/"
        }

    except Exception as e:
        print("URLScan error:", e)
        return None
