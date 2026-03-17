import requests

def fetch_cve_data(cve_id):

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    r = requests.get(url)
    data = r.json()

    vuln = data["vulnerabilities"][0]["cve"]

    description = vuln["descriptions"][0]["value"]

    published = vuln["published"]

    metrics = vuln.get("metrics", {})

    cvss = "N/A"
    severity = "Unknown"

    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

    vendor = "Unknown"

    if "configurations" in vuln:
        try:
            vendor = vuln["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"]
        except:
            pass

    return {
        "id": cve_id,
        "description": description,
        "cvss": cvss,
        "severity": severity,
        "published": published,
        "vendor": vendor
    }
