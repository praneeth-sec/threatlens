import re
import requests

from flask import Blueprint, jsonify, render_template, session, redirect, request

from app.services.analysis_service import analyze_cve_with_llm
from app.services.scoring_service import calculate_priority
from app.models.database import save_report, get_all_reports, cve_exists

from app.services.vt_service import check_ip, check_domain, check_url, check_hash
from app.services.ip_enrich_service import enrich_ip
from app.services.urlscan_service import scan_url
from app.services.ioc_ai_service import generate_ioc_analysis

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

    if len(ioc) in [32, 40, 64]:
        return "hash"

    return "unknown"


# ===== OTX =====
def check_otx(ioc, ioc_type):
    try:
        res = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general",
            timeout=5
        )

        if res.status_code == 200:
            data = res.json()

            if data.get("pulse_info", {}).get("count", 0) > 0:
                return {
                    "status": "malicious",
                    "link": f"https://otx.alienvault.com/indicator/{ioc_type}/{ioc}"
                }

    except:
        pass

    return {"status": "unknown", "link": None}


# ===== MALWARE BAZAAR =====
def check_malwarebazaar(ioc):
    try:
        res = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": ioc},
            timeout=5
        )

        data = res.json()

        if data.get("query_status") == "ok":
            return {
                "status": "malicious",
                "link": f"https://bazaar.abuse.ch/sample/{ioc}/"
            }

    except:
        pass

    return {"status": "unknown", "link": None}


@main_bp.route("/ioc-lookup", methods=["GET", "POST"])
def ioc_lookup():

    extra = None
    urlscan = None
    tags = []
    otx = None
    mb = None
    ai_result = None

    if request.method == "POST":

        ioc = request.form["ip"]
        ioc_type = detect_ioc_type(ioc)

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

        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        harmless = vt_result.get("harmless", 0)
        total = malicious + suspicious + harmless

        verdict = "MALICIOUS" if malicious > 0 else "SAFE"

        # TAGS
        if ioc.endswith(".exe"):
            tags.append("Executable Download")

        if "malware" in ioc:
            tags.append("Malware Distribution")

        if malicious > 0:
            tags.append("Malicious Indicator")

        if ioc_type == "url":
            tags.append("Direct File Download")

        # SOURCES
        otx = check_otx(ioc, ioc_type)

        if ioc_type == "hash":
            mb = check_malwarebazaar(ioc)
        else:
            mb = {"status": "N/A", "link": None}

        # VT LINK
        vt_link = f"https://www.virustotal.com/gui/search/{ioc}"

        # AI
        ai_result = generate_ioc_analysis(ioc, malicious, total, tags)

        return render_template(
            "ip_lookup.html",
            ioc=ioc,
            malicious=malicious,
            total=total,
            verdict=verdict,
            extra=extra,
            urlscan=urlscan,
            tags=tags,
            otx=otx,
            mb=mb,
            vt_link=vt_link,
            ai_result=ai_result
        )

    return render_template("ip_lookup.html")


# ================= OTHER ROUTES =================
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
