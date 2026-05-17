import os

GMAIL_SENDER = "lowel.rubino29@gmail.com"
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_SECRET_PATH = os.path.join(PROJECT_ROOT, "client_secret.json")
TOKEN_PATH = os.path.join(PROJECT_ROOT, "token.json")

# Tesseract path for Windows
TESSERACT_CMD = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
