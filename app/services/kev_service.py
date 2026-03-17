import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_trending_vulns():

    try:

        response = requests.get(KEV_URL)

        data = response.json()

        vulns = data["vulnerabilities"]

        trending = []

        for vuln in vulns[:10]:

            trending.append({
                "cve": vuln["cveID"],
                "vendor": vuln["vendorProject"],
                "product": vuln["product"],
                "date": vuln["dateAdded"],
                "action": vuln["requiredAction"]
            })

        return trending

    except:
        return []
