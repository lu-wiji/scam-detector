# SMS Phishing and Spam Detector

Desktop app that scans SMS text (and SMS screenshots) for phishing and spam patterns using regex rules and OCR. It highlights suspicious phrases, assigns a risk score, and can export or email a scan report.

## Features
- Text scan with risk scoring and findings
- Image scan with OCR (Tesseract)
- Camera capture for live image scans (optional, via OpenCV)
- Export reports to TXT or CSV
- Email reports through Gmail OAuth
- Scan history view

## Requirements
- Python 3.10+
- Tesseract OCR installed (Windows default path used)
- Packages:
  - customtkinter
  - pillow
  - pytesseract
  - google-auth
  - google-auth-oauthlib
  - google-api-python-client
  - opencv-python (optional, for camera capture)

## Setup
1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install customtkinter pillow pytesseract google-auth google-auth-oauthlib google-api-python-client
   pip install opencv-python
   ```
3. Install Tesseract OCR:
   - Windows: https://github.com/tesseract-ocr/tesseract
   - Ensure the path in sms_phishing_detector.py matches your install:
     ```python
     pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
     ```

## Gmail Report (Optional)
To send reports by email, place your OAuth client file in the app folder:
- client_secret.json (ignored by git)
- token.json

The app will create token.json on first sign-in.

## Run
```bash
python sms_phishing_detector.py
```

## Notes
- Camera capture requires OpenCV. If it is not installed, the button is disabled.
- Regex rules and scores are defined at the top of sms_phishing_detector.py.

## License
MIT License. See LICENSE.
