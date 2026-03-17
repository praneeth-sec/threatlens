from flask import Blueprint, render_template, request
from app.services.cve_lookup_service import fetch_cve_data
from app.services.exploit_service import check_exploit_sources
from app.services.ai_service import generate_mitigation
from app.services.cache_service import get_cache, save_cache

cve_bp = Blueprint("cve", __name__)

@cve_bp.route("/cve-analyzer/<cve_id>")
def cve_direct_lookup(cve_id):

    cve_result = fetch_cve_data(cve_id)
    exploit = check_exploit_sources(cve_id)
    ai_analysis = generate_mitigation(
        cve_result["description"]
)

    return render_template(
        "cve_analyzer.html",
        cve_result=cve_result,
        cve_id=cve_id,
        exploit=exploit,
        ai_analysis=ai_analysis
    )

@cve_bp.route("/cve-analyzer", methods=["GET", "POST"])
def cve_page():

    cve_result = None
    exploit = None
    ai_analysis = None
    cve_id = None

    if request.method == "POST":

        cve_id = request.form.get("cve")

        print("Received CVE:", cve_id)

        if cve_id:

            # 🔵 CHECK CACHE FIRST
            cached = get_cache(cve_id)

            if cached:
                print("Cache hit!")

                cve_result = cached["cve_result"]
                exploit = cached["exploit"]
                ai_analysis = cached["ai_analysis"]

            else:

                print("Cache miss - fetching from APIs")

                cve_result = fetch_cve_data(cve_id)

                if cve_result:

                    exploit = check_exploit_sources(cve_id)

                    ai_analysis = generate_mitigation(
                        cve_result["description"]
                    )

                    # 🔵 SAVE TO CACHE
                    save_cache(cve_id, {
                        "cve_result": cve_result,
                        "exploit": exploit,
                        "ai_analysis": ai_analysis
                    })

    return render_template(
        "cve_analyzer.html",
        cve_result=cve_result,
        exploit=exploit,
        ai_analysis=ai_analysis,
        cve_id=cve_id
    )
