import base64
import csv
import json
import os
import re
import threading
from datetime import datetime
from email.message import EmailMessage

import customtkinter as ctk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk, ImageEnhance, ImageFilter
import pytesseract

try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
except ImportError:
    Credentials = None
    InstalledAppFlow = None
    build = None

# Tesseract path for Windows
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Try importing OpenCV for camera (optional)
try:
    import cv2
    CAMERA_AVAILABLE = True
except ImportError:
    CAMERA_AVAILABLE = False

# Gmail OAuth settings
GMAIL_SENDER = "lowel.rubino29@gmail.com"
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRET_PATH = os.path.join(APP_DIR, "client_secret.json")
TOKEN_PATH = os.path.join(APP_DIR, "token.json")

# ─────────────────────────────────────────────
#  REGEX RULE ENGINE
# ─────────────────────────────────────────────

RULES = [
    {
        "id": 1,
        "category": "Suspicious URL",
        "pattern": r"https?://(?:[^\s]*\.)?(?:tk|ml|ga|cf|click|xyz|top|gq|pw|cc|bit\.ly|tinyurl|ow\.ly)[^\s]*",
        "score": 35,
        "description": "Shortened or suspicious domain URL detected",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 2,
        "category": "Urgency Language",
        "pattern": r"\b(urgent|act now|immediately|limited time|expires?|last chance|respond now|within \d+ hours?)\b",
        "score": 20,
        "description": "Urgency/pressure language to rush the victim",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 3,
        "category": "Bank / OTP Phishing",
        "pattern": r"\b(OTP|PIN|one[- ]time password|account.{0,15}suspend|verify.{0,15}account|bank.{0,15}detail|credit card.{0,15}confirm)\b",
        "score": 40,
        "description": "Fake bank alert or OTP harvesting attempt",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 4,
        "category": "Prize / Lottery Scam",
        "pattern": r"\b(you[\'']?ve? won|claim.{0,15}prize|free gift|selected winner|congratulations.{0,20}reward|lottery)\b",
        "score": 35,
        "description": "Fake prize or lottery scam pattern",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 5,
        "category": "Credential Harvesting",
        "pattern": r"\b(click.{0,15}link|login.{0,15}below|confirm.{0,15}password|enter.{0,15}credentials|sign.{0,15}in.{0,15}here)\b",
        "score": 30,
        "description": "Attempting to steal login credentials",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 6,
        "category": "Suspicious Phone Number",
        "pattern": r"(?<!\d)(\+?63|0)9\d{9}(?!\d)",
        "score": 15,
        "description": "Philippine mobile number used as lure",
        "color": "#FFD700",
        "badge_bg": "#3D3300",
    },
    {
        "id": 7,
        "category": "Personal Info Request",
        "pattern": r"\b(send.{0,15}(your )?(full name|address|birthday|SSS|TIN|PhilHealth|Pag-?IBIG)|provide.{0,15}personal)\b",
        "score": 30,
        "description": "Requesting sensitive personal information",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 8,
        "category": "Money Transfer",
        "pattern": r"\b(GCash|Maya|PayMaya|Palawan|money transfer|send.{0,10}(php|pesos?|\d+))\b",
        "score": 25,
        "description": "Suspicious money transfer request or mention",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
]

SCAN_HISTORY = []


# ─────────────────────────────────────────────
#  OCR + SCAN PIPELINE
# ─────────────────────────────────────────────

def preprocess_image(image: Image.Image) -> Image.Image:
    """Enhance image for better OCR accuracy."""
    image = image.convert("L")                          # grayscale
    image = image.filter(ImageFilter.SHARPEN)           # sharpen
    image = ImageEnhance.Contrast(image).enhance(2.0)   # boost contrast
    return image


def extract_text(image: Image.Image) -> str:
    """Run Tesseract OCR on the image."""
    processed = preprocess_image(image)
    text = pytesseract.image_to_string(processed, config="--psm 6")
    return text.strip()


def scan_message(text: str) -> dict:
    """Run all regex rules and return a result dict."""
    results = []
    total_score = 0
    text_lower = text.lower()

    for rule in RULES:
        matches = re.findall(rule["pattern"], text_lower, re.IGNORECASE)
        if matches:
            unique = list(set(m if isinstance(m, str) else m[0] for m in matches))
            results.append({
                "category": rule["category"],
                "description": rule["description"],
                "matches": unique,
                "score": rule["score"],
                "color": rule["color"],
                "badge_bg": rule["badge_bg"],
            })
            total_score += rule["score"]

    total_score = min(total_score, 100)

    if total_score >= 60:
        risk, risk_color, risk_bg, risk_icon = "HIGH RISK", "#FF4C4C", "#2A0A0A", "🔴"
    elif total_score >= 30:
        risk, risk_color, risk_bg, risk_icon = "MEDIUM RISK", "#FF8C00", "#2A1A00", "🟡"
    elif total_score > 0:
        risk, risk_color, risk_bg, risk_icon = "LOW RISK", "#FFD700", "#2A2600", "🟡"
    else:
        risk, risk_color, risk_bg, risk_icon = "SAFE", "#00C48C", "#002A1E", "🟢"

    return {
        "score": total_score,
        "risk": risk,
        "risk_color": risk_color,
        "risk_bg": risk_bg,
        "risk_icon": risk_icon,
        "findings": results,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message_preview": text[:80] + ("..." if len(text) > 80 else ""),
        "full_text": text,
    }


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
    <div style="font-family:Segoe UI, Arial, sans-serif; color:#111827;">
      <h2 style="margin:0 0 10px;">SMS Phishing Detector Report</h2>
      <p style="margin:0 0 12px;color:#374151;">Generated: {result['timestamp']}</p>

      <div style="border:1px solid #E5E7EB;border-radius:8px;padding:12px;margin-bottom:16px;">
        <div style="font-size:18px;font-weight:700;color:{result['risk_color']};">
          {result['risk_icon']} {result['risk']}
        </div>
        <div style="margin-top:6px;color:#374151;">Threat Score: <b>{result['score']}/100</b></div>
      </div>

      <h3 style="margin:0 0 8px;">Summary</h3>
      <p style="margin:0 0 16px;color:#374151;">
        Findings: <b>{len(result['findings'])}</b>
      </p>

      <h3 style="margin:0 0 8px;">Findings</h3>
      <table style="width:100%;border-collapse:collapse;border:1px solid #E5E7EB;border-radius:8px;">
        <thead>
          <tr style="background:#F3F4F6;">
            <th style="text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;">Category</th>
            <th style="text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;">Description</th>
            <th style="text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;">Score</th>
            <th style="text-align:left;padding:8px 10px;border-bottom:1px solid #E5E7EB;">Matches</th>
          </tr>
        </thead>
        <tbody>
          {finding_rows}
        </tbody>
      </table>

      <h3 style="margin:16px 0 8px;">Extracted / Scanned Text</h3>
      <div style="white-space:pre-wrap;background:#F9FAFB;border:1px solid #E5E7EB;"
           "border-radius:8px;padding:10px;color:#111827;">
        {result['full_text']}
      </div>
    </div>
    """


def _send_gmail_report(result: dict, recipient: str):
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


# ─────────────────────────────────────────────
#  CAMERA WINDOW
# ─────────────────────────────────────────────

class CameraWindow(ctk.CTkToplevel):
    def __init__(self, parent, on_capture_callback):
        super().__init__(parent)
        self.title("📷 Camera Capture")
        self.geometry("660x520")
        self.resizable(False, False)
        self.on_capture_callback = on_capture_callback
        self.cap = None
        self.running = False
        self.current_frame = None
        self._build_ui()
        self._start_camera()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        ctk.CTkLabel(
            self,
            text="Position the SMS message in the frame, then capture.",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF",
        ).pack(pady=(12, 6))

        self.canvas = ctk.CTkLabel(self, text="", width=640, height=400)
        self.canvas.pack(padx=10)

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=10)

        ctk.CTkButton(
            btn_row,
            text="📸  Capture & Scan",
            command=self._capture,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#00C48C",
            hover_color="#00A374",
            text_color="#0D1117",
            height=40,
            width=180,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_row,
            text="Cancel",
            command=self._on_close,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=40,
            width=100,
        ).pack(side="left")

    def _start_camera(self):
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showerror("Camera Error", "Could not open camera.")
            self.destroy()
            return
        self.running = True
        self._update_feed()

    def _update_feed(self):
        if not self.running:
            return
        ret, frame = self.cap.read()
        if ret:
            self.current_frame = frame
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb).resize((640, 400))
            photo = ImageTk.PhotoImage(img)
            self.canvas.configure(image=photo)
            self.canvas.image = photo
        self.after(30, self._update_feed)

    def _capture(self):
        if self.current_frame is None:
            messagebox.showerror("Error", "No frame captured.")
            return
        rgb = cv2.cvtColor(self.current_frame, cv2.COLOR_BGR2RGB)
        image = Image.fromarray(rgb)
        self._on_close()
        self.on_capture_callback(image)

    def _on_close(self):
        self.running = False
        if self.cap:
            self.cap.release()
        self.destroy()


# ─────────────────────────────────────────────
#  MAIN APPLICATION
# ─────────────────────────────────────────────

class SMSDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SMS Phishing & Spam Detector")
        self.geometry("950x750")
        self.minsize(800, 600)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.last_result = None
        self.recipient_var = ctk.StringVar(value=GMAIL_SENDER)
        self._build_ui()

    # ── Layout ──────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color="#0D1117", corner_radius=0, height=64)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        ctk.CTkLabel(
            header,
            text="🛡️  SMS Phishing & Spam Detector",
            font=ctk.CTkFont(family="Courier New", size=20, weight="bold"),
            text_color="#00C48C",
        ).pack(side="left", padx=24, pady=14)
        ctk.CTkLabel(
            header,
            text="Regex + OCR Threat Detection",
            font=ctk.CTkFont(size=11),
            text_color="#555E6E",
        ).pack(side="right", padx=24)

        # Tabs
        self.tabs = ctk.CTkTabview(self, fg_color="#0D1B2A")
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=12, pady=(6, 12))
        self.tabs.add("Scanner")
        self.tabs.add("Image Scan")
        self.tabs.add("Rule Engine")
        self.tabs.add("History")

        self._build_scanner_tab(self.tabs.tab("Scanner"))
        self._build_image_tab(self.tabs.tab("Image Scan"))
        self._build_rules_tab(self.tabs.tab("Rule Engine"))
        self._build_history_tab(self.tabs.tab("History"))

    # ── Scanner Tab ─────────────────────────
    def _build_scanner_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        input_frame = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10)
        input_frame.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 6))
        input_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            input_frame,
            text="Paste SMS Message Below:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#9CA3AF",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 2))

        self.sms_input = ctk.CTkTextbox(
            input_frame,
            height=100,
            font=ctk.CTkFont(family="Courier New", size=13),
            fg_color="#0D1117",
            text_color="#E5E7EB",
            border_color="#1F2937",
            border_width=1,
        )
        self.sms_input.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 4))

        btn_row = ctk.CTkFrame(input_frame, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 10))
        btn_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            btn_row,
            text="⚡  SCAN MESSAGE",
            command=self._run_text_scan,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#00C48C",
            hover_color="#00A374",
            text_color="#0D1117",
            height=38,
            width=180,
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            btn_row,
            text="Clear",
            command=self._clear_text,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
            width=80,
        ).grid(row=0, column=1, sticky="w", padx=(8, 0))

        self.recipient_entry = ctk.CTkEntry(
            btn_row,
            textvariable=self.recipient_var,
            height=38,
            placeholder_text="Recipient email",
        )
        self.recipient_entry.grid(row=0, column=2, sticky="ew", padx=(12, 12))

        ctk.CTkButton(
            btn_row,
            text="📤 Export Report",
            command=lambda: self._export_report(self.sms_input.get("1.0", "end").strip()),
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
            width=130,
        ).grid(row=0, column=4, sticky="e")

        ctk.CTkButton(
            btn_row,
            text="📧 Send Report",
            command=self._send_latest_report,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
            width=120,
        ).grid(row=0, column=3, sticky="e", padx=(0, 8))

        self.text_results_frame = ctk.CTkScrollableFrame(
            parent, fg_color="#0D1B2A", corner_radius=10
        )
        self.text_results_frame.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self.text_results_frame.grid_columnconfigure(0, weight=1)
        self._show_placeholder(self.text_results_frame)

    # ── Image Scan Tab ───────────────────────
    def _build_image_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        # Top action buttons
        action_frame = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10)
        action_frame.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 6))
        action_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(
            action_frame,
            text="Scan an SMS screenshot or photo — OCR extracts the text automatically.",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF",
        ).grid(row=0, column=0, columnspan=2, padx=14, pady=(10, 8))

        ctk.CTkButton(
            action_frame,
            text="📁  Upload Image",
            command=self._upload_image,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1D4ED8",
            hover_color="#1E40AF",
            height=44,
        ).grid(row=1, column=0, padx=(14, 6), pady=(0, 12), sticky="ew")

        cam_btn = ctk.CTkButton(
            action_frame,
            text="📷  Capture from Camera",
            command=self._open_camera,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#7C3AED" if CAMERA_AVAILABLE else "#374151",
            hover_color="#6D28D9" if CAMERA_AVAILABLE else "#374151",
            height=44,
            state="normal" if CAMERA_AVAILABLE else "disabled",
        )
        cam_btn.grid(row=1, column=1, padx=(6, 14), pady=(0, 12), sticky="ew")

        ctk.CTkButton(
            action_frame,
            text="📧  Send Report",
            command=self._send_latest_report,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
        ).grid(row=2, column=0, columnspan=2, padx=14, pady=(0, 10), sticky="ew")

        if not CAMERA_AVAILABLE:
            ctk.CTkLabel(
                action_frame,
                text="⚠ opencv-python not installed — camera unavailable",
                font=ctk.CTkFont(size=10),
                text_color="#6B7280",
            ).grid(row=3, column=0, columnspan=2, pady=(0, 8))

        # Image preview + extracted text side by side
        preview_frame = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10)
        preview_frame.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 6))
        preview_frame.grid_columnconfigure(0, weight=1)
        preview_frame.grid_columnconfigure(1, weight=1)

        # Left: image preview
        ctk.CTkLabel(
            preview_frame,
            text="Image Preview",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#6B7280",
        ).grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.image_preview_label = ctk.CTkLabel(
            preview_frame,
            text="No image loaded",
            font=ctk.CTkFont(size=12),
            text_color="#374151",
            width=300,
            height=180,
            fg_color="#0D1117",
            corner_radius=6,
        )
        self.image_preview_label.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="nsew")

        # Right: extracted text
        ctk.CTkLabel(
            preview_frame,
            text="Extracted Text (auto OCR)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#6B7280",
        ).grid(row=0, column=1, padx=14, pady=(10, 4), sticky="w")

        self.ocr_text_box = ctk.CTkTextbox(
            preview_frame,
            height=180,
            font=ctk.CTkFont(family="Courier New", size=11),
            fg_color="#0D1117",
            text_color="#00C48C",
            border_color="#1F2937",
            border_width=1,
        )
        self.ocr_text_box.grid(row=1, column=1, padx=14, pady=(0, 12), sticky="nsew")

        # Status bar
        self.ocr_status = ctk.CTkLabel(
            parent,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF",
        )
        self.ocr_status.grid(row=2, column=0, sticky="n", pady=(0, 4))

        # Results
        self.image_results_frame = ctk.CTkScrollableFrame(
            parent, fg_color="#0D1B2A", corner_radius=10
        )
        self.image_results_frame.grid(row=3, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self.image_results_frame.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(3, weight=1)
        self._show_placeholder(self.image_results_frame)

    # ── Image Pipeline ───────────────────────
    def _upload_image(self):
        path = filedialog.askopenfilename(
            title="Select SMS Screenshot or Photo",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff *.webp")],
        )
        if not path:
            return
        image = Image.open(path)
        self._run_image_pipeline(image)

    def _open_camera(self):
        if not CAMERA_AVAILABLE:
            messagebox.showwarning("Unavailable", "Install opencv-python to use camera.")
            return
        CameraWindow(self, on_capture_callback=self._run_image_pipeline)

    def _run_image_pipeline(self, image: Image.Image):
        """Automated pipeline: show preview → OCR → scan → results."""
        # Show preview
        self._show_image_preview(image)

        # Update status
        self.ocr_status.configure(text="⏳ Running OCR... please wait", text_color="#FFD700")

        # Clear previous
        self.ocr_text_box.delete("1.0", "end")
        self._show_placeholder(self.image_results_frame)

        # Run OCR + scan in background thread so UI stays responsive
        def pipeline():
            try:
                # Step 1: OCR
                text = extract_text(image)

                # Step 2: Update UI with extracted text
                self.after(0, lambda: self._set_ocr_text(text))

                if not text:
                    self.after(0, lambda: self.ocr_status.configure(
                        text="⚠ No text detected in image. Try a clearer photo.",
                        text_color="#FF8C00",
                    ))
                    return

                # Step 3: Auto scan
                self.after(0, lambda: self.ocr_status.configure(
                    text="🔍 Scanning extracted text...", text_color="#00C48C"
                ))
                result = scan_message(text)
                SCAN_HISTORY.append(result)

                # Step 4: Display results
                self.after(0, lambda: self._finish_image_pipeline(result))

            except Exception as e:
                self.after(0, lambda: self.ocr_status.configure(
                    text=f"❌ Error: {e}", text_color="#FF4C4C"
                ))

        threading.Thread(target=pipeline, daemon=True).start()

    def _set_ocr_text(self, text):
        self.ocr_text_box.delete("1.0", "end")
        self.ocr_text_box.insert("1.0", text if text else "(no text found)")

    def _finish_image_pipeline(self, result):
        self.ocr_status.configure(
            text=f"✅ Scan complete — {len(result['findings'])} threat(s) found",
            text_color="#00C48C",
        )
        self.last_result = result
        self._refresh_history()
        self._display_results(result, self.image_results_frame)

    def _show_image_preview(self, image: Image.Image):
        preview = image.copy()
        preview.thumbnail((300, 180))
        photo = ImageTk.PhotoImage(preview)
        self.image_preview_label.configure(image=photo, text="")
        self.image_preview_label.image = photo

    # ── Shared Results Renderer ──────────────
    def _show_placeholder(self, frame):
        for w in frame.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            frame,
            text="Results will appear here after scanning.",
            font=ctk.CTkFont(size=13),
            text_color="#374151",
        ).pack(pady=40)

    def _display_results(self, result: dict, frame):
        for w in frame.winfo_children():
            w.destroy()

        # Risk banner
        banner = ctk.CTkFrame(
            frame,
            fg_color=result["risk_bg"],
            border_color=result["risk_color"],
            border_width=2,
            corner_radius=10,
        )
        banner.pack(fill="x", padx=4, pady=(6, 10))

        ctk.CTkLabel(
            banner,
            text=f"{result['risk_icon']}  {result['risk']}",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=result["risk_color"],
        ).pack(side="left", padx=20, pady=14)

        ctk.CTkLabel(
            banner,
            text=f"Threat Score: {result['score']}/100",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=result["risk_color"],
        ).pack(side="right", padx=20)

        # Score bar
        bar_frame = ctk.CTkFrame(frame, fg_color="#111827", corner_radius=8)
        bar_frame.pack(fill="x", padx=4, pady=(0, 10))
        ctk.CTkLabel(
            bar_frame, text="Threat Level",
            font=ctk.CTkFont(size=11), text_color="#9CA3AF",
        ).pack(anchor="w", padx=12, pady=(8, 2))
        bar = ctk.CTkProgressBar(
            bar_frame, progress_color=result["risk_color"],
            fg_color="#1F2937", height=14,
        )
        bar.pack(fill="x", padx=12, pady=(0, 10))
        bar.set(result["score"] / 100)

        if not result["findings"]:
            ctk.CTkLabel(
                frame,
                text="✅  No threats detected. Message appears safe.",
                font=ctk.CTkFont(size=14),
                text_color="#00C48C",
            ).pack(pady=20)
            return

        ctk.CTkLabel(
            frame,
            text=f"⚠️  {len(result['findings'])} threat pattern(s) found:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#E5E7EB",
        ).pack(anchor="w", padx=8, pady=(0, 6))

        for finding in result["findings"]:
            card = ctk.CTkFrame(
                frame,
                fg_color="#111827",
                border_color=finding["color"],
                border_width=1,
                corner_radius=8,
            )
            card.pack(fill="x", padx=4, pady=3)
            card.grid_columnconfigure(1, weight=1)

            badge = ctk.CTkFrame(card, fg_color=finding["badge_bg"], corner_radius=6, width=140)
            badge.grid(row=0, column=0, padx=(10, 8), pady=10, sticky="ns")
            ctk.CTkLabel(
                badge,
                text=finding["category"],
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=finding["color"],
                wraplength=120,
            ).pack(padx=8, pady=6)

            detail = ctk.CTkFrame(card, fg_color="transparent")
            detail.grid(row=0, column=1, sticky="ew", pady=8, padx=(0, 10))

            ctk.CTkLabel(
                detail,
                text=finding["description"],
                font=ctk.CTkFont(size=12),
                text_color="#D1D5DB",
                anchor="w",
            ).pack(anchor="w")

            match_str = "  |  ".join(f'"{m}"' for m in finding["matches"][:4])
            ctk.CTkLabel(
                detail,
                text=f"Matched: {match_str}",
                font=ctk.CTkFont(family="Courier New", size=11),
                text_color="#6B7280",
                anchor="w",
            ).pack(anchor="w")

            ctk.CTkLabel(
                card,
                text=f"+{finding['score']}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=finding["color"],
            ).grid(row=0, column=2, padx=12)

    # ── Text Scanner ────────────────────────
    def _run_text_scan(self):
        text = self.sms_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please paste an SMS message first.")
            return
        result = scan_message(text)
        self.last_result = result
        SCAN_HISTORY.append(result)
        self._refresh_history()
        self._display_results(result, self.text_results_frame)

    def _clear_text(self):
        self.sms_input.delete("1.0", "end")
        self._show_placeholder(self.text_results_frame)

    def _send_latest_report(self):
        if self.last_result is None:
            messagebox.showwarning("No Report", "Run a scan first.")
            return
        recipient = self.recipient_var.get().strip()
        if not recipient or "@" not in recipient:
            messagebox.showwarning("Invalid Email", "Enter a valid recipient email.")
            return
        try:
            _send_gmail_report(self.last_result, recipient)
            messagebox.showinfo("Sent", f"Report sent to {recipient}.")
        except Exception as exc:
            messagebox.showerror("Email Error", str(exc))

    # ── Export ───────────────────────────────
    def _export_report(self, text):
        if not text:
            messagebox.showwarning("Nothing to Export", "Run a scan first.")
            return
        result = scan_message(text)
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("CSV", "*.csv")],
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        )
        if not path:
            return
        if path.endswith(".csv"):
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp", "Risk Level", "Score", "Category", "Description", "Matches"])
                for finding in result["findings"]:
                    w.writerow([
                        result["timestamp"], result["risk"], result["score"],
                        finding["category"], finding["description"],
                        "; ".join(finding["matches"]),
                    ])
        else:
            with open(path, "w") as f:
                f.write("SMS PHISHING DETECTOR — SCAN REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Timestamp : {result['timestamp']}\n")
                f.write(f"Risk Level: {result['risk']} (Score: {result['score']}/100)\n\n")
                f.write(f"Message Preview:\n{result['message_preview']}\n\n")
                f.write(f"Findings ({len(result['findings'])}):\n" + "-" * 40 + "\n")
                for i, finding in enumerate(result["findings"], 1):
                    f.write(f"{i}. [{finding['category']}] +{finding['score']} pts\n")
                    f.write(f"   {finding['description']}\n")
                    f.write(f"   Matched: {', '.join(finding['matches'])}\n\n")
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    # ── Rules Tab ───────────────────────────
    def _build_rules_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(parent, fg_color="#0D1B2A")
        scroll.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        scroll.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            scroll,
            text="Active Regex Rules",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB",
        ).pack(anchor="w", padx=8, pady=(8, 12))

        for rule in RULES:
            card = ctk.CTkFrame(scroll, fg_color="#111827", corner_radius=8)
            card.pack(fill="x", padx=4, pady=4)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 2))

            ctk.CTkLabel(
                top,
                text=rule["category"],
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=rule["color"],
            ).pack(side="left")
            ctk.CTkLabel(
                top,
                text=f"Score weight: +{rule['score']}",
                font=ctk.CTkFont(size=11),
                text_color="#6B7280",
            ).pack(side="right")

            ctk.CTkLabel(
                card,
                text=rule["description"],
                font=ctk.CTkFont(size=11),
                text_color="#9CA3AF",
                anchor="w",
            ).pack(anchor="w", padx=12, pady=(0, 4))

            pattern_box = ctk.CTkTextbox(
                card,
                height=36,
                font=ctk.CTkFont(family="Courier New", size=10),
                fg_color="#0D1117",
                text_color="#00C48C",
                border_width=0,
            )
            pattern_box.pack(fill="x", padx=12, pady=(0, 10))
            pattern_box.insert("1.0", rule["pattern"])
            pattern_box.configure(state="disabled")

    # ── History Tab ─────────────────────────
    def _build_history_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        self.history_frame = ctk.CTkScrollableFrame(parent, fg_color="#0D1B2A")
        self.history_frame.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self.history_frame.grid_columnconfigure(0, weight=1)
        self._refresh_history()

    def _refresh_history(self):
        for w in self.history_frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(
            self.history_frame,
            text="Scan History",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB",
        ).pack(anchor="w", padx=8, pady=(8, 12))

        if not SCAN_HISTORY:
            ctk.CTkLabel(
                self.history_frame,
                text="No scans yet.",
                font=ctk.CTkFont(size=13),
                text_color="#374151",
            ).pack(pady=30)
            return

        for entry in reversed(SCAN_HISTORY):
            row = ctk.CTkFrame(
                self.history_frame,
                fg_color="#111827",
                border_color=entry["risk_color"],
                border_width=1,
                corner_radius=8,
            )
            row.pack(fill="x", padx=4, pady=3)

            ctk.CTkLabel(
                row,
                text=f"{entry['risk_icon']} {entry['risk']}",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=entry["risk_color"],
                width=120,
            ).pack(side="left", padx=12, pady=10)

            ctk.CTkLabel(
                row,
                text=entry["message_preview"],
                font=ctk.CTkFont(family="Courier New", size=10),
                text_color="#6B7280",
            ).pack(side="left", padx=8)

            ctk.CTkLabel(
                row,
                text=entry["timestamp"],
                font=ctk.CTkFont(size=10),
                text_color="#374151",
            ).pack(side="right", padx=12)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app = SMSDetectorApp()
    app.mainloop()