from flask import Blueprint, render_template
from app.services.kev_service import fetch_trending_vulns
from flask import jsonify

trending_bp = Blueprint("trending", __name__)


@trending_bp.route("/trending-vulnerabilities")
def trending_vulnerabilities():

    vulns = fetch_trending_vulns()

    return render_template(
        "trending_vulns.html",
        vulns=vulns
    )
@trending_bp.route("/trending-feed")
def trending_feed():

    vulns = fetch_trending_vulns()

    feed = []

    for v in vulns[:5]:
        feed.append(f"{v['cve']} actively exploited in the wild")

    return jsonify(feed)
