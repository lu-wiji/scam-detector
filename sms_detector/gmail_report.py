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
    # Try to load saved credentials
    if os.path.exists(TOKEN_PATH):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
        except Exception:
            # If the token file is malformed, ignore and force re-auth
            creds = None

    # If we have creds but no refresh_token (or it's missing), force re-auth so
    # we obtain a refresh token. Google only returns refresh tokens on the
    # first consent unless access_type='offline' and prompt='consent' are used.
    if creds and (not getattr(creds, "refresh_token", None)):
        try:
            os.remove(TOKEN_PATH)
        except Exception:
            pass
        creds = None

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_PATH, SCOPES)
        # Request offline access and force the consent screen so a refresh token
        # is returned and the app can refresh access tokens silently later.
        creds = flow.run_local_server(
            host="localhost",
            port=8080,
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        # Persist the full credential JSON (should include refresh_token)
        try:
            with open(TOKEN_PATH, "w") as token_file:
                token_file.write(creds.to_json())
        except Exception:
            # If we can't write the token, show an error to the user but
            # continue with the ephemeral credentials.
            messagebox.showwarning(
                "Token Save Warning",
                f"Unable to save token to {TOKEN_PATH}. The app will still try to send the email this session.",
            )

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
                    {result.get('risk_icon', '')} {result['risk']}
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
