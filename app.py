import csv
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from services.analyzer import analyze_email
from services.automation import send_optional_alert
from services.database import init_db, save_report, update_report_path, get_report, get_reports, export_reports_csv
from services.report_generator import generate_report_html

BASE_DIR = Path(__file__).parent
HOST = "127.0.0.1"
PORT = 8000


def load_template(name, **values):
    path = BASE_DIR / "templates" / name
    html = path.read_text(encoding="utf-8")
    for key, value in values.items():
        html = html.replace("{{ " + key + " }}", str(value))
    return html


def make_list(items):
    if not items:
        return "<li>No item found</li>"
    return "\n".join(f"<li>{safe_text(item)}</li>" for item in items)


def safe_text(value):
    value = "" if value is None else str(value)
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def risk_badge(risk):
    risk = safe_text(risk)
    return f'<span class="badge badge-{risk.lower()}">{risk}</span>'


def report_rows(reports):
    if not reports:
        return '<tr><td colspan="6" class="empty">No reports created yet.</td></tr>'
    rows = []
    for row in reports:
        rows.append(
            "<tr>"
            f"<td>{row['id']}</td>"
            f"<td>{safe_text(row['created_at'])}</td>"
            f"<td>{safe_text(row['sender_email'])}</td>"
            f"<td>{safe_text(row['subject'])}</td>"
            f"<td>{risk_badge(row['risk_level'])}</td>"
            f"<td>{row['phishing_score']}</td>"
            f"<td><a class='small-btn' href='/result/{row['id']}'>View</a></td>"
            "</tr>"
        )
    return "\n".join(rows)


class AppHandler(BaseHTTPRequestHandler):
    def send_html(self, html, status=200):
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path):
        if not path.exists() or not path.is_file():
            self.send_html(load_template("error.html", title="File Not Found", message="The requested file was not found."), 404)
            return
        content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            html = load_template("index.html")
            self.send_html(html)
            return

        if path == "/dashboard":
            reports = get_reports()
            html = load_template("dashboard.html", report_rows=report_rows(reports), total_reports=len(reports))
            self.send_html(html)
            return

        if path == "/export.csv":
            export_path = export_reports_csv()
            self.send_file(export_path)
            return

        if path.startswith("/result/"):
            report_id = path.split("/result/", 1)[1].strip("/")
            if not report_id.isdigit():
                self.send_html(load_template("error.html", title="Invalid Report", message="Invalid report id."), 400)
                return
            report = get_report(int(report_id))
            if not report:
                self.send_html(load_template("error.html", title="Report Not Found", message="No report was found for this id."), 404)
                return
            html = load_template(
                "result.html",
                report_id=report["id"],
                sender_email=safe_text(report["sender_email"]),
                subject=safe_text(report["subject"]),
                email_body=safe_text(report["email_body"]),
                links=safe_text(report["links"]),
                attachment_name=safe_text(report["attachment_name"]),
                risk_level=report["risk_level"],
                risk_badge=risk_badge(report["risk_level"]),
                phishing_score=report["phishing_score"],
                confidence=safe_text(report["confidence"]),
                indicators=make_list(report["detected_indicators"]),
                explanation=safe_text(report["explanation"]),
                recommended_actions=make_list(report["recommended_actions"]),
                created_at=safe_text(report["created_at"]),
                report_path=safe_text(report["report_path"] or "#")
            )
            self.send_html(html)
            return

        if path.startswith("/static/"):
            rel = path.replace("/static/", "", 1)
            self.send_file(BASE_DIR / "static" / rel)
            return

        if path.startswith("/reports/"):
            rel = path.replace("/reports/", "", 1)
            self.send_file(BASE_DIR / "reports" / rel)
            return

        self.send_html(load_template("error.html", title="Page Not Found", message="This page does not exist."), 404)

    def do_POST(self):
        if self.path != "/analyze":
            self.send_html(load_template("error.html", title="Invalid Request", message="This POST route is not supported."), 404)
            return

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw_body)

        email_data = {
            "sender_email": form.get("sender_email", [""])[0].strip(),
            "subject": form.get("subject", [""])[0].strip(),
            "email_body": form.get("email_body", [""])[0].strip(),
            "links": form.get("links", [""])[0].strip(),
            "attachment_name": form.get("attachment_name", [""])[0].strip(),
        }

        if not email_data["email_body"] and not email_data["subject"]:
            html = load_template("error.html", title="Missing Email Content", message="Please enter at least an email subject or email body.")
            self.send_html(html, 400)
            return

        result = analyze_email(email_data)
        report_id = save_report(email_data, result)
        report_file = generate_report_html(report_id, email_data, result)
        update_report_path(report_id, f"/reports/{report_file.name}")
        send_optional_alert(email_data, result, report_id)

        self.send_response(303)
        self.send_header("Location", f"/result/{report_id}")
        self.end_headers()


def main():
    init_db()
    server = HTTPServer((HOST, PORT), AppHandler)
    print("+================================================+")
    print("| AI-Powered Phishing Email Analyzer             |")
    print("+================================================+")
    print(f"Running at: http://{HOST}:{PORT}")
    print("Press CTRL + C to stop the server.")
    server.serve_forever()


if __name__ == "__main__":
    main()
