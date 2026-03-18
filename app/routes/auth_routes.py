from flask import Blueprint, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection
from datetime import datetime, timedelta
from email.mime.text import MIMEText
import requests
import os
import secrets
import smtplib

def send_reset_email(to_email, token):

    reset_link = f"https://threatlens-3m5n.onrender.com/reset-password/{token}"

    subject = "ThreatLens Password Reset"
    body = f"""
Click the link below to reset your password:

{reset_link}

This link expires in 15 minutes.
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = os.getenv("EMAIL_USER")
    msg["To"] = to_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
        server.starttls()
        server.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
        server.send_message(msg)
        server.quit()

        print("Email sent successfully")

    except Exception as e:
        print("Email error:", e)

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

            return redirect("/dashboard")

        else:
            return render_template(
                "login.html",
                error="Invalid email or password"
            )

    return render_template("login.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            expiry = datetime.utcnow() + timedelta(minutes=15)

            cursor.execute(
                "UPDATE users SET reset_token=%s, reset_token_expiry=%s WHERE email=%s",
                (token, expiry, email)
            )
            conn.commit()

            send_reset_email(email, token)

        conn.close()

        return render_template("forgot_password.html", success="If account exists, reset link sent")

    return render_template("forgot_password.html")

@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE reset_token=%s", (token,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return "Invalid token"

    expiry = user[5]  # index for expiry
    
    if isinstance(expiry, str):
         expiry = datetime.fromisoformat(expiry)

    if datetime.utcnow() > expiry:
        conn.close()
        return "Token expired"

    if request.method == "POST":
        new_password = request.form["password"]
        hashed = generate_password_hash(new_password)

        cursor.execute(
            "UPDATE users SET password=%s, reset_token=NULL, reset_token_expiry=NULL WHERE id=%s",
            (hashed, user[0])
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("reset_password.html")

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
