import re
from datetime import datetime

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
