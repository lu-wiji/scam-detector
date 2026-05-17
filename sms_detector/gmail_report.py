import base64
import os
from email.message import EmailMessage
from tkinter import messagebox

from .config import GMAIL_SENDER, SCOPES, CLIENT_SECRET_PATH, TOKEN_PATH

try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
except ImportError:
    Credentials = None
    InstalledAppFlow = None
    build = None


def _ensure_gmail_libs():
    if Credentials is None or InstalledAppFlow is None or build is None:
        messagebox.showerror(
            "Missing Gmail Libraries",
            "Install required packages: google-auth, google-auth-oauthlib, google-api-python-client",
        )
        return False
    return True


def _get_gmail_service():
    if not _ensure_gmail_libs():
        return None
    if not os.path.exists(CLIENT_SECRET_PATH):
        messagebox.showerror(
            "Missing OAuth Client",
            "client_secret.json not found in the app folder.",
        )
        return None

    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_PATH, SCOPES)
        creds = flow.run_local_server(port=8080)
        with open(TOKEN_PATH, "w") as token_file:
            token_file.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def _build_email_html(result: dict) -> str:
    finding_rows = ""
    for finding in result["findings"]:
        matches = ", ".join(finding["matches"]) if finding["matches"] else "-"
        finding_rows += (
            "<tr>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #E5E7EB;'>{finding['category']}</td>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #E5E7EB;'>{finding['description']}</td>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #E5E7EB;'>+{finding['score']}</td>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #E5E7EB;'>{matches}</td>"
            "</tr>"
        )

    if not finding_rows:
        finding_rows = (
            "<tr><td colspan='4' style='padding:10px;color:#6B7280;'>"
            "No threat patterns detected."
            "</td></tr>"
        )

    return f"""
    <div style=\"font-family:Segoe UI, Arial, sans-serif; color:#111827;\">
      <h2 style=\"margin:0 0 10px;\">SMS Phishing Detector Report</h2>
      <p style=\"margin:0 0 12px;color:#374151;\">Generated: {result['timestamp']}</p>

      <div style=\"border:1px solid #E5E7EB;border-radius:8px;padding:12px;margin-bottom:16px;\">
        <div style=\"font-size:18px;font-weight:700;color:{result['risk_color']};\">
          {result['risk_icon']} {result['risk']}
        </div>
        <div style=\"margin-top:6px;color:#374151;\">Threat Score: <b>{result['score']}/100</b></div>
      </div>

      <h3 style=\"margin:0 0 8px;\">Summary</h3>
      <p style=\"margin:0 0 16px;color:#374151;\">
        Findings: <b>{len(result['findings'])}</b>
      </p>

      <h3 style=\"margin:0 0 8px;\">Findings</h3>
      <table style=\"width:100%;border-collapse:collapse;border:1px solid #E5E7EB;border-radius:8px;\">
        <thead>
          <tr style=\"background:#F3F4F6;\">
            <th style=\"text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;\">Category</th>
            <th style=\"text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;\">Description</th>
            <th style=\"text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;\">Score</th>
            <th style=\"text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;\">Matches</th>
          </tr>
        </thead>
        <tbody>
          {finding_rows}
        </tbody>
      </table>

      <h3 style=\"margin:16px 0 8px;\">Extracted / Scanned Text</h3>
      <div style=\"white-space:pre-wrap;background:#F9FAFB;border:1px solid #E5E7EB;\"
           "border-radius:8px;padding:10px;color:#111827;\">
        {result['full_text']}
      </div>
    </div>
    """


def send_gmail_report(result: dict, recipient: str):
    service = _get_gmail_service()
    if service is None:
        return

    msg = EmailMessage()
    msg["To"] = recipient
    msg["From"] = GMAIL_SENDER
    msg["Subject"] = f"SMS Scan Report - {result['risk']} ({result['score']}/100)"
    msg.set_content(
        f"Risk: {result['risk']}\nScore: {result['score']}/100\n"
        f"Timestamp: {result['timestamp']}\n\n{result['full_text']}"
    )
    msg.add_alternative(_build_email_html(result), subtype="html")

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    service.users().messages().send(userId="me", body={"raw": raw}).execute()
