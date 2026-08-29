import json
import os
import urllib.request


def send_optional_alert(email_data, result, report_id):
    webhook = os.environ.get("N8N_WEBHOOK_URL", "").strip()
    if not webhook:
        return False
    if result.get("risk_level") not in ["High", "Critical"]:
        return False
    payload = {
        "report_id": report_id,
        "sender_email": email_data.get("sender_email", ""),
        "subject": email_data.get("subject", ""),
        "risk_level": result.get("risk_level"),
        "phishing_score": result.get("phishing_score"),
        "recommended_actions": result.get("recommended_actions", [])
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(request, timeout=5)
        return True
    except Exception:
        return False
