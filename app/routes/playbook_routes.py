from flask import Blueprint, render_template, request
from app.services.ai_service import generate_playbook
import markdown

playbook_bp = Blueprint("playbook", __name__)

@playbook_bp.route("/playbooks", methods=["GET","POST"])
def playbooks():

    playbook = None

    if request.method == "POST":

        alert = request.form["alert"]

        playbook = generate_playbook(alert)
        playbook = markdown.markdown(playbook)

    return render_template(
        "playbooks.html",
        playbook=playbook
    )
