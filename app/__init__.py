from flask import Flask
import os

from app.routes.main_routes import main_bp
from app.routes.auth_routes import auth_bp
from app.models.database import init_db
from app.routes.cve_routes import cve_bp
from app.routes.trending_routes import trending_bp
from app.routes.playbook_routes import playbook_bp

def create_app():
    app = Flask(__name__)

    # ✅ FIXED: use environment variable
    app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

    # register routes
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(cve_bp)
    app.register_blueprint(trending_bp)
    app.register_blueprint(playbook_bp)

    # initialize database
    init_db()

    return app
