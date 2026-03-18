from flask import Blueprint, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection
import requests
import os


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        
        recaptcha_response = request.form.get("g-recaptcha-response")

        secret_key = os.getenv("RECAPTCHA_SECRET_KEY")

        verify_url = "https://www.google.com/recaptcha/api/siteverify"

        payload = {
            "secret": secret_key,
            "response": recaptcha_response
        }

        r = requests.post(verify_url, data=payload)
        result = r.json()

        if not result.get("success"):
            return render_template(
                "signup.html",
                error="CAPTCHA verification failed"
            )

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # CHECK IF EMAIL EXISTS
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template("signup.html", error="Email already exists")

        cursor.execute(
            "INSERT INTO users (username,email,password) VALUES (%s,%s,%s)",
            (username, email, password_hash)
        )

        conn.commit()
        conn.close()

        return render_template("login.html", success="Account created successfully! Please login.")

    return render_template("signup.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]
        
        recaptcha_response = request.form.get("g-recaptcha-response")

        secret_key = os.getenv("RECAPTCHA_SECRET_KEY")

        verify_url = "https://www.google.com/recaptcha/api/siteverify"

        payload = {
            "secret": secret_key,
            "response": recaptcha_response
        }

        r = requests.post(verify_url, data=payload)
        result = r.json()

        if not result.get("success"):
            return render_template(
                "login.html",
                error="CAPTCHA verification failed"
            )
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[3], password):

            session["user_id"] = user[0]
            session["username"] = user[1]

            return render_template("dashboard.html", login_success=True)

        else:
            return render_template(
                "login.html",
                error="Invalid email or password"
            )

    return render_template("login.html")


@auth_bp.route("/init-db")
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    conn.commit()
    conn.close()

    return "DB Initialized"
    
@auth_bp.route("/update-db")
def update_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT;")
    cursor.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP;")

    conn.commit()
    conn.close()

    return "DB Updated"


@auth_bp.route("/logout")
def logout():

    session.clear()

    return redirect("/login")
