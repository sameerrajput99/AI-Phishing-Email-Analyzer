import math
import re
from urllib.parse import urlparse

URGENCY_WORDS = ["urgent", "immediately", "now", "last warning", "limited time", "within 24 hours", "final notice", "account blocked", "suspended"]
CREDENTIAL_WORDS = ["password", "login", "verify", "otp", "pin", "security code", "update your account", "confirm your identity"]
MONEY_WORDS = ["bank", "payment", "invoice", "refund", "wallet", "transaction", "salary", "tax", "claim"]
ACTION_WORDS = ["click here", "open the link", "download", "enable macros", "reply with", "submit", "confirm"]
RISKY_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".zip", ".rar", ".iso", ".apk"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "shorturl.at"]
KNOWN_BRANDS = ["microsoft", "google", "paypal", "apple", "amazon", "meta", "facebook", "instagram", "netflix", "bank", "hbl", "mashreq", "ubl", "easypaisa", "jazzcash"]
FREE_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"]


def analyze_email(email_data):
    sender = email_data.get("sender_email", "")
    subject = email_data.get("subject", "")
    body = email_data.get("email_body", "")
    links_text = email_data.get("links", "")
    attachment = email_data.get("attachment_name", "")

    combined = f"{sender} {subject} {body} {links_text} {attachment}".lower()
    urls = extract_urls(f"{body} {links_text}")

    score = 0
    indicators = []

    urgency_hits = find_hits(combined, URGENCY_WORDS)
    if urgency_hits:
        add(indicators, f"Urgent or threatening language found: {', '.join(urgency_hits[:4])}")
        score += min(25, 8 + len(urgency_hits) * 5)

    credential_hits = find_hits(combined, CREDENTIAL_WORDS)
    if credential_hits:
        add(indicators, f"Credential or identity request found: {', '.join(credential_hits[:4])}")
        score += min(25, 10 + len(credential_hits) * 5)

    action_hits = find_hits(combined, ACTION_WORDS)
    if action_hits:
        add(indicators, f"Risky action request found: {', '.join(action_hits[:4])}")
        score += min(20, 7 + len(action_hits) * 4)

    money_hits = find_hits(combined, MONEY_WORDS)
    if money_hits:
        add(indicators, f"Financial or account related wording found: {', '.join(money_hits[:4])}")
        score += min(15, 5 + len(money_hits) * 3)

    link_points, link_indicators = analyze_links(urls)
    score += link_points
    indicators.extend(link_indicators)

    sender_points, sender_indicators = analyze_sender(sender, combined)
    score += sender_points
    indicators.extend(sender_indicators)

    attachment_points, attachment_indicators = analyze_attachment(attachment)
    score += attachment_points
    indicators.extend(attachment_indicators)

    entropy = text_entropy(body)
    if entropy > 4.7 and len(body) > 80:
        add(indicators, "Email body has unusual character distribution, which can appear in obfuscated phishing text")
        score += 5

    if not indicators:
        indicators.append("No strong phishing indicator found in the submitted email")

    score = max(0, min(100, int(score)))
    risk = risk_level(score)
    confidence = confidence_level(score, len(indicators), urls)
    explanation = make_explanation(risk, score, indicators)
    actions = recommended_actions(risk)

    return {
        "risk_level": risk,
        "phishing_score": score,
        "confidence": confidence,
        "detected_indicators": indicators,
        "explanation": explanation,
        "recommended_actions": actions,
        "url_count": len(urls)
    }


def extract_urls(text):
    pattern = r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"
    found = re.findall(pattern, text or "")
    cleaned = []
    for url in found:
        cleaned.append(url.strip().strip(").,;!"))
    return cleaned


def find_hits(text, words):
    hits = []
    for word in words:
        if word in text:
            hits.append(word)
    return hits


def add(items, text):
    if text not in items:
        items.append(text)


def analyze_links(urls):
    points = 0
    indicators = []
    for url in urls:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        host = (parsed.netloc or "").lower()
        if url.startswith("http://"):
            add(indicators, f"Non-HTTPS link found: {url}")
            points += 15
        if any(shortener in host for shortener in SHORTENERS):
            add(indicators, f"URL shortener found: {host}")
            points += 15
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
            add(indicators, f"IP address used instead of a normal domain: {host}")
            points += 20
        if "@" in url:
            add(indicators, f"Suspicious @ symbol found inside URL: {url}")
            points += 15
        if "xn--" in host:
            add(indicators, f"Possible punycode/lookalike domain found: {host}")
            points += 20
        if has_brand_lookalike(host):
            add(indicators, f"Possible brand lookalike domain found: {host}")
            points += 20
    return min(points, 35), indicators


def analyze_sender(sender, combined_text):
    points = 0
    indicators = []
    domain = sender.split("@")[-1].lower() if "@" in sender else ""
    local = sender.split("@")[0].lower() if "@" in sender else sender.lower()

    if sender and "@" not in sender:
        indicators.append("Sender email format looks incomplete or invalid")
        points += 10

    if domain in FREE_EMAIL_DOMAINS and any(brand in combined_text for brand in KNOWN_BRANDS):
        indicators.append("Brand/account related email is coming from a free email domain")
        points += 15

    if has_brand_lookalike(domain) or has_brand_lookalike(local):
        indicators.append("Sender appears to use a brand lookalike pattern")
        points += 20

    if domain.count("-") >= 2 or sum(ch.isdigit() for ch in domain) >= 3:
        indicators.append("Sender domain contains unusual hyphen or number pattern")
        points += 10

    return min(points, 30), indicators


def analyze_attachment(attachment):
    points = 0
    indicators = []
    name = (attachment or "").lower().strip()
    if not name:
        return 0, []
    for ext in RISKY_EXTENSIONS:
        if name.endswith(ext):
            indicators.append(f"Risky attachment extension detected: {ext}")
            points += 25
            break
    if ".pdf." in name or ".docx." in name or ".jpg." in name:
        indicators.append("Attachment uses double extension style, which is suspicious")
        points += 15
    return min(points, 30), indicators


def has_brand_lookalike(value):
    value = value.lower()
    replacements = {"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"}
    normalized = "".join(replacements.get(ch, ch) for ch in value)
    for brand in KNOWN_BRANDS:
        if brand in normalized and brand not in value:
            return True
    if "paypa1" in value or "micr0soft" in value or "g00gle" in value:
        return True
    return False


def text_entropy(text):
    if not text:
        return 0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    entropy = 0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def risk_level(score):
    if score >= 76:
        return "Critical"
    if score >= 51:
        return "High"
    if score >= 26:
        return "Medium"
    return "Low"


def confidence_level(score, indicator_count, urls):
    if score >= 70 or indicator_count >= 5:
        return "High"
    if score >= 35 or urls:
        return "Medium"
    return "Low"


def make_explanation(risk, score, indicators):
    if risk in ["High", "Critical"]:
        opening = f"This email appears {risk.lower()} risk because multiple phishing indicators were found."
    elif risk == "Medium":
        opening = "This email has some suspicious signs and should be checked carefully before taking action."
    else:
        opening = "This email currently shows low phishing risk based on the submitted content."
    top = "; ".join(indicators[:3])
    return f"{opening} The calculated phishing score is {score}/100. Main reasons: {top}."


def recommended_actions(risk):
    if risk == "Critical":
        return [
            "Do not click any link or download any attachment.",
            "Report the email to the security team immediately.",
            "Block or quarantine the sender.",
            "If credentials were entered, reset the password and review account activity."
        ]
    if risk == "High":
        return [
            "Do not interact with the email until verified.",
            "Check the sender domain and links carefully.",
            "Report the message as suspected phishing.",
            "Warn affected users if this email was received by multiple people."
        ]
    if risk == "Medium":
        return [
            "Verify the sender using an official channel.",
            "Avoid opening links unless the source is confirmed.",
            "Keep the email for review if the message seems unusual."
        ]
    return [
        "No urgent action required based on this analysis.",
        "Still verify links and attachments before interacting.",
        "Keep monitoring if similar emails arrive."
    ]
