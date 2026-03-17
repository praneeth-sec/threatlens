import sqlite3
from datetime import datetime

DB_NAME = "threatlens.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        risk_level TEXT,
        attack_scenario TEXT,
        detection_strategy TEXT,
        mitigation TEXT,
        priority_score INTEGER,
        cvss_score REAL,
        created_at TEXT
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT UNIQUE,
        password TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()
    
    


def save_report(report):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO reports (
        cve_id,
        risk_level,
        attack_scenario,
        detection_strategy,
        mitigation,
        priority_score,
        cvss_score,
        created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report.get("cve_id"),
        report.get("risk_level"),
        report.get("attack_scenario"),
        report.get("detection_strategy"),
        report.get("mitigation"),
        report.get("priority_score"),
        report.get("cvss_score"),
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()


def get_all_reports():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM reports ORDER BY id DESC")
    rows = cursor.fetchall()

    reports = []

    for row in rows:
        report = {
            "id": row[0],
            "cve_id": row[1],
            "risk_level": row[2],
            "attack_scenario": row[3],
            "detection_strategy": row[4],
            "mitigation": row[5],
            "priority_score": row[6],
            "cvss_score": row[7],
            "created_at": row[8]
        }

        reports.append(report)

    conn.close()
    return reports
    
def clear_reports():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM reports")

    conn.commit()
    conn.close()


def cve_exists(cve_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT 1 FROM reports WHERE cve_id=?", (cve_id,))
    result = cursor.fetchone()

    conn.close()

    return result is not None
