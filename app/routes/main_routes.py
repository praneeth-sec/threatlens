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

    extra = None  # ✅ FIX: always initialize

    if request.method == "POST":

        ioc = request.form["ip"]
        ioc_type = detect_ioc_type(ioc)
        
        print("IOC:", ioc)
        print("TYPE:", ioc_type)
        
        if ioc_type == "ip":
            result = check_ip(ioc)
            extra = enrich_ip(ioc)  # ✅ KEEP THIS
            print("EXTRA DATA:", extra)
            
        elif ioc_type == "domain":
            result = check_domain(ioc)
            
        elif ioc_type == "url":
            result = check_url(ioc)
            
        elif ioc_type == "hash":
            result = check_hash(ioc)
            
        else:
            return render_template(
                "ip_lookup.html",
                error="IOC type not supported yet",
                extra=extra  # ✅ FIX
            )
        

        if not result:
            return render_template(
                "ip_lookup.html",
                error="Error contacting VirusTotal or invalid IOC",
                result=result,
                ip=ioc,
                extra=extra  # ✅ FIX
            )

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)
        harmless = result.get("harmless", 0)
        total = malicious + suspicious + harmless

        # reputation score
        reputation_score = f"{malicious}/{total}"

        # verdict
        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # threat level
        ratio = malicious / total if total > 0 else 0

        if ratio > 0.3:
            threat_level = "HIGH"
        elif ratio > 0.1:
            threat_level = "MEDIUM"
        elif malicious > 0:
            threat_level = "LOW"
        else:
            threat_level = "SAFE"

        return render_template(
            "ip_lookup.html",
            result=result,
            ioc=ioc,
            verdict=verdict,
            reputation_score=reputation_score,
            threat_level=threat_level,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            total=total,
            extra=extra  # ✅ FIX
        )

    return render_template("ip_lookup.html", extra=None)  # ✅ FIX


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
