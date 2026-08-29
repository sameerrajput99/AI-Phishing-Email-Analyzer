# AI-Powered Phishing Email Analyzer

Final internship project for AI, Automation & Security Engineering.

This project is a web-based phishing email analyzer. A user can paste a suspicious email, and the system checks phishing indicators, calculates a risk score, classifies the risk level, recommends actions, saves the result in SQLite, and generates an incident report.

## Main Features

- Suspicious email input form
- Sender, subject, body, link, and attachment analysis
- Phishing score from 0 to 100
- Risk level: Low, Medium, High, Critical
- Detected phishing indicators
- Recommended security actions
- SQLite dashboard history
- HTML incident report generation
- CSV export
- Optional n8n webhook alert for High/Critical reports

## Requirements

Python 3.14 or newer.

No external packages are required.

## How to Run

Open the project folder in VS Code, then run:

```bash
py app.py
```

Then open this link in your browser:

```text
http://127.0.0.1:8000
```

## Test Flow

1. Open the home page.
2. Paste a sample email from the `sample_emails` folder.
3. Click `Analyze Email`.
4. View the risk level, score, explanation, and actions.
5. Open the generated incident report.
6. Go to Dashboard to see saved reports.

## Optional Automation

If you want to trigger an n8n webhook for high-risk emails, set this environment variable before running the app:

```bash
set N8N_WEBHOOK_URL=https://your-n8n-webhook-url
py app.py
```

The app will send a JSON alert only when the risk level is High or Critical.

## Project Structure

```text
app.py
services/
  analyzer.py
  database.py
  report_generator.py
  automation.py
templates/
static/
sample_emails/
database/
reports/
exports/
docs/
```

## Notes

This project uses a local AI-style phishing analysis engine based on phishing indicators, risk scoring, link analysis, sender analysis, attachment analysis, and security recommendations. It is designed to run easily on Python 3.14 without package installation issues.
