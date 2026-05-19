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
        "pattern": r"\b(urgent action required|urgent|act now|immediately verify|respond within \d+ hours?|respond within \d+ hours|respond within \d+ hours?|your account will be suspended|final warning|limited time|expires today|expires|last chance|avoid account closure|failure to respond|security alert|suspicious activity detected|confirm now|time-sensitive request|do not ignore|immediate attention required|account locked|unauthorized login attempt|unusual sign-in detected|respond now|confirm now)\b",
        "score": 25,
        "description": "Urgency/pressure language to rush the victim",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 3,
        "category": "Bank / OTP Phishing",
        "pattern": r"\b(OTP required|OTP|one[- ]time password|confirm your PIN|confirm your PIN|confirm your PIN|bank verification|credit card confirmation|unusual transaction detected|verify your bank details|payment failed|account suspended|refund available|claim your refund|transaction declined|verify payment method|tax refund available|pending transaction|unauthorized payment attempt|your balance is on hold|banking security alert)\b",
        "score": 40,
        "description": "Fake bank alert or OTP harvesting attempt",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 4,
        "category": "Prize / Lottery Scam",
        "pattern": r"\b(congratulations you won|you[\'\']?ve? won|selected winner|claim your prize|claim.{0,15}prize|free gift|exclusive reward|lottery winner|lucky customer|cash reward|special promotion|free iPhone|gift card reward|spin to win|bonus reward|instant winner|limited giveaway|redeem your reward|surprise reward|winner announcement|promotional offer|you have been selected)\b",
        "score": 35,
        "description": "Fake prize or lottery scam pattern",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 5,
        "category": "Credential Harvesting",
        "pattern": r"\b(click the link below|click.{0,15}link|login here|login.{0,15}below|sign in now|sign.{0,15}in.{0,15}here|verify your password|confirm your credentials|enter your login details|update your account|re-authenticate|validate your identity|reset your password|secure your account|verify your email|account verification required|confirm your identity|continue to login|unlock your account|verify your information|update billing information|submit your credentials|authentication required)\b",
        "score": 35,
        "description": "Attempting to steal login credentials",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 9,
        "category": "Delivery / Package Scam",
        "pattern": r"\b(package delivery failed|shipping issue|incorrect address|track your package|reschedule delivery|unpaid shipping fee|customs clearance pending|delivery suspended|confirm delivery details|parcel on hold|package waiting|courier notification|delivery attempt failed|shipment delayed|click to track package)\b",
        "score": 20,
        "description": "Delivery or courier themed scam pattern",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 10,
        "category": "Tech Support / Fake Security",
        "pattern": r"\b(virus detected|device infected|malware warning|security risk detected|your phone is infected|system compromised|install security update|urgent antivirus alert|remove threats now|suspicious device activity|firewall warning|account breach detected|scan your device|trojan detected|update required immediately)\b",
        "score": 25,
        "description": "Fake tech support or security alert",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 11,
        "category": "Job / Money Scam",
        "pattern": r"\b(earn money fast|work from home|guaranteed income|no experience required|daily earnings|investment opportunity|double your money|passive income|crypto profit|high return investment|financial freedom|easy cash|instant payout|paid survey opportunity|remote position available)\b",
        "score": 20,
        "description": "Job, investment or easy-money scam language",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 12,
        "category": "Emotional Manipulation",
        "pattern": r"\b(confidential request|keep this private|help needed urgently|trust me|don[\'\']?t tell anyone|emergency assistance|verify immediately|your loved one needs help|unexpected problem|account at risk|avoid penalties|important notice|urgent business proposal|confidential transaction)\b",
        "score": 15,
        "description": "Social engineering / emotional manipulation phrases",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 13,
        "category": "Suspicious Shorteners / Domains",
        "pattern": r"\b(bit\.ly|tinyurl|ow\.ly|cutt\.ly|goo\.gl|rebrand\.ly|tiny\.cc|lnkd\.in|rb\.gy)\b",
        "score": 30,
        "description": "Shortened URLs often used to obfuscate destination",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 14,
        "category": "Suspicious TLD",
        "pattern": r"\b(\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.click|\.work|\.support)\b",
        "score": 20,
        "description": "TLDs frequently abused for scams",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 15,
        "category": "Package Delivery Scam",
        "pattern": r"\b(package delivery (has )?(been )?(suspended|failed)|delivery (attempt )?failed|redeliver|redelivery fee|update your details within \d+ hours?|reschedule delivery|track your package|click to track package|unpaid shipping fee|customs clearance pending|confirm delivery details|parcel on hold)\b",
        "score": 25,
        "description": "Smishing/package delivery patterns including redelivery fees and tracking links",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 16,
        "category": "Fake Job Offer",
        "pattern": r"\b(remote (part[- ]time|part[- ]time) position|selected for a remote|earn up to \d{1,3}[,\d]* ?(php|PHP|pesos?)|contact our hiring manager|whatsapp|wa\.me|no experience required|guaranteed income|work from home)\b",
        "score": 20,
        "description": "Job-offer language used to lure victims into advance-fee or task scams",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 17,
        "category": "Subscription Auto-Renewal / Fake Invoice",
        "pattern": r"\b(will auto-?renew|auto-?renewal|annual .* will auto-?renew|your .* will auto-?renew|did not authorize this charge|call support immediately|call .* to cancel|unauthorized charge|cancel immediately)\b",
        "score": 20,
        "description": "Fake invoice/auto-renewal phrasing that pushes victims to call or respond",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
    },
    {
        "id": 18,
        "category": "Wrong Number / Social Engineering Lead-in",
        "pattern": r"\b(wrong number|are we still meeting|are we meeting|hi .* are we still|did we meet for)\b",
        "score": 10,
        "description": "Casual 'wrong number' or meeting messages that can be pig-butcher conversation openers",
        "color": "#FFD700",
        "badge_bg": "#3D3300",
    },
    {
        "id": 19,
        "category": "Storage / Account Data Threat",
        "pattern": r"\b(i?cloud storage is full|your (icloud|google|gmail|apple|microsoft) (storage|account) (is )?(full|over quota)|permanently deleted in \d+ hours|click here to upgrade your storage|upgrade your storage for free)\b",
        "score": 30,
        "description": "Threats about cloud storage or data loss used to phish credentials",
        "color": "#FF4C4C",
        "badge_bg": "#3D1A1A",
    },
    {
        "id": 20,
        "category": "Survey / Giveaway Trap",
        "pattern": r"\b(complete this (1[- ]minute|one[- ]minute|minute) survey|pay a small shipping fee|pay .* shipping fee|small shipping fee|survey to claim|pay a trivial shipping fee|pay \$?\d{1,3}(?:\.\d{2})? for shipping)\b",
        "score": 30,
        "description": "Survey/giveaway language that requests a small fee to harvest payment details",
        "color": "#FF8C00",
        "badge_bg": "#3D2A00",
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

    if total_score >= 50:
        risk, risk_color, risk_bg, risk_icon = "HIGH RISK", "#FF4C4C", "#2A0A0A", "🔴"
    elif total_score >= 25:
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
