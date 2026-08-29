import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "database" / "phishing_reports.db"
EXPORT_PATH = BASE_DIR / "exports" / "phishing_reports_export.csv"


def connect():
    DB_PATH.parent.mkdir(exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT,
                subject TEXT,
                email_body TEXT,
                links TEXT,
                attachment_name TEXT,
                risk_level TEXT,
                phishing_score INTEGER,
                confidence TEXT,
                detected_indicators TEXT,
                explanation TEXT,
                recommended_actions TEXT,
                report_path TEXT,
                created_at TEXT
            )
            """
        )
        conn.commit()


def save_report(email_data, result):
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO email_reports (
                sender_email, subject, email_body, links, attachment_name,
                risk_level, phishing_score, confidence, detected_indicators,
                explanation, recommended_actions, report_path, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email_data.get("sender_email", ""),
                email_data.get("subject", ""),
                email_data.get("email_body", ""),
                email_data.get("links", ""),
                email_data.get("attachment_name", ""),
                result.get("risk_level", "Low"),
                result.get("phishing_score", 0),
                result.get("confidence", "Low"),
                json.dumps(result.get("detected_indicators", [])),
                result.get("explanation", ""),
                json.dumps(result.get("recommended_actions", [])),
                "",
                created_at,
            ),
        )
        conn.commit()
        return cur.lastrowid


def update_report_path(report_id, path):
    with connect() as conn:
        conn.execute("UPDATE email_reports SET report_path=? WHERE id=?", (path, report_id))
        conn.commit()


def row_to_dict(row):
    if not row:
        return None
    keys = [
        "id", "sender_email", "subject", "email_body", "links", "attachment_name",
        "risk_level", "phishing_score", "confidence", "detected_indicators",
        "explanation", "recommended_actions", "report_path", "created_at"
    ]
    data = dict(zip(keys, row))
    data["detected_indicators"] = json.loads(data["detected_indicators"] or "[]")
    data["recommended_actions"] = json.loads(data["recommended_actions"] or "[]")
    return data


def get_report(report_id):
    with connect() as conn:
        cur = conn.execute("SELECT * FROM email_reports WHERE id=?", (report_id,))
        return row_to_dict(cur.fetchone())


def get_reports():
    with connect() as conn:
        cur = conn.execute("SELECT * FROM email_reports ORDER BY id DESC")
        return [row_to_dict(row) for row in cur.fetchall()]


def export_reports_csv():
    reports = get_reports()
    EXPORT_PATH.parent.mkdir(exist_ok=True)
    with EXPORT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "created_at", "sender_email", "subject", "risk_level", "phishing_score", "confidence"])
        for row in reports:
            writer.writerow([row["id"], row["created_at"], row["sender_email"], row["subject"], row["risk_level"], row["phishing_score"], row["confidence"]])
    return EXPORT_PATH
