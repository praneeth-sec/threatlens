import re
from flask import Blueprint, jsonify
from app.services.analysis_service import analyze_cve_with_llm
from app.services.scoring_service import calculate_priority
from app.models.database import save_report, get_all_reports, cve_exists
from flask import render_template
from flask import session, redirect
from app.services.vt_service import check_ip, check_domain, check_url, check_hash
from flask import request
from app.services.ip_enrich_service import enrich_ip
from app.services.urlscan_service import scan_url

main_bp = Blueprint("main", __name__)

def detect_ioc_type(ioc):

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if re.match(ip_pattern, ioc):
        return "ip"

    if ioc.startswith("http"):
        return "url"

    if re.match(domain_pattern, ioc):
        return "domain"

    if len(ioc) in [32,40,64]:
        return "hash"

    return "unknown"

@main_bp.route("/ioc-lookup", methods=["GET","POST"])
def ioc_lookup():

    extra = None
    urlscan = None
    tags = []

    if request.method == "POST":

        ioc = request.form["ip"]
        ioc_type = detect_ioc_type(ioc)

        # ===== FETCH DATA =====
        if ioc_type == "ip":
            vt_result = check_ip(ioc)
            extra = enrich_ip(ioc)

        elif ioc_type == "domain":
            vt_result = check_domain(ioc)

        elif ioc_type == "url":
            vt_result = check_url(ioc)
            urlscan = scan_url(ioc)

        elif ioc_type == "hash":
            vt_result = check_hash(ioc)

        else:
            return render_template("ip_lookup.html", error="Unsupported IOC type")

        if not vt_result:
            return render_template("ip_lookup.html", error="Error fetching data")

        # ===== STATS =====
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        harmless = vt_result.get("harmless", 0)
        total = malicious + suspicious + harmless

        # ===== VERDICT =====
        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # ===== TAG LOGIC =====
        if ioc.endswith(".exe"):
            tags.append("Executable Download")

        if "malware" in ioc:
            tags.append("Malware Distribution")

        if malicious > 0:
            tags.append("Malicious Indicator")

        if ioc_type == "url":
            tags.append("Direct File Download")

        # ===== SOURCES (for UI) =====
        sources = {
            "virustotal": vt_result,
            "urlscan": urlscan,
            "abuseipdb": extra
        }

        return render_template(
            "ip_lookup.html",
            ioc=ioc,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            total=total,
            verdict=verdict,
            extra=extra,
            urlscan=urlscan,
            sources=sources,
            tags=tags
        )

    return render_template("ip_lookup.html")
           

@main_bp.route("/")
def home():
    return render_template("home.html")


@main_bp.route("/reports")
def reports():
    rows = get_all_reports()
    return jsonify(rows)


@main_bp.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    return render_template("dashboard.html")


@main_bp.route("/stats")
def stats():

    reports = get_all_reports()

    total = len(reports)

    critical = len([r for r in reports if r["risk_level"].lower() == "critical"])
    high = len([r for r in reports if r["risk_level"].lower() == "high"])
    medium = len([r for r in reports if r["risk_level"].lower() == "medium"])

    return jsonify({
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium
    })


@main_bp.route("/cve/<cve_id>")
def cve_details(cve_id):

    reports = get_all_reports()

    for r in reports:
        if r["cve_id"] == cve_id:
            return render_template("cve_details.html", report=r)

    return "CVE not found"


@main_bp.route("/generate-analysis", methods=["POST"])
def generate_analysis():

    from app.models.database import clear_reports
    clear_reports()

    vulnerabilities = fetch_latest_cves()
    results = []

    for item in vulnerabilities:

        cve_data = item.get("cve", {})
        print("METRICS DATA:", cve_data.get("metrics"))
        cve_id = cve_data.get("id", "Unknown")

        if cve_exists(cve_id):
            continue

        # Extract description
        description = ""
        try:
            description = cve_data["descriptions"][0]["value"]
        except:
            pass

        # Extract CVSS score safely
        cvss_score = 0
        metrics = cve_data.get("metrics", {})

        try:
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        except:
            cvss_score = 0

        # Run AI analysis
        analysis = analyze_cve_with_llm(cve_id, description)

        if analysis:

            analysis["cve_id"] = cve_id
            analysis["cvss_score"] = cvss_score
            analysis["priority_score"] = calculate_priority(cvss_score)

            save_report(analysis)
            results.append(analysis)

    return jsonify(results)
    
@main_bp.route("/epss/<cve>")
def epss_score(cve):

    import requests

    url = f"https://api.first.org/data/v1/epss?cve={cve}"

    r = requests.get(url)
    data = r.json()

    if data["data"]:
        score = float(data["data"][0]["epss"])
    else:
        score = 0

    return jsonify({
        "score": score
    })
    
@main_bp.route("/threat-feed")
def threat_feed():

    reports = get_all_reports()

    feed = []

    for r in reports[:5]:

        cve_id = r["cve_id"]

        try:
            import requests
            epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            res = requests.get(epss_url)
            data = res.json()

            if data["data"]:
                epss = float(data["data"][0]["epss"])
            else:
                epss = 0
        except:
            epss = 0

        exploit = "HIGH" if epss > 0.5 else "LOW"

        feed.append({
            "cve": cve_id,
            "risk": r.get("risk_level", "Unknown"),
            "epss": round(epss, 2),
            "exploit": exploit
        })

    return jsonify(feed)
