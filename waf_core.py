import os
import re
import urllib.parse
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, abort, render_template_string

app = Flask(__name__)

# --- SECURE CREDENTIALS (Strictly from Environment) ---
# Ab code mein koi password nahi hai. Render settings se uthaye ga.
GMAIL_USER = os.environ.get("GMAIL_USER") 
GMAIL_PASS = os.environ.get("GMAIL_PASS") 

# --- ADVANCED SECURITY RULES ---
SECURITY_RULES = [
    r"<script.*?>", r"alert\(", r"onerror=", r"onload=",             # XSS
    r"union\s+select", r"insert\s+into", r"drop\s+table",             # SQLi Keywords
    r"'.*?or.*?1\s*=\s*1", r"'.*?--", r"\d+\s*=\s*\d+",               # SQLi Logic
    r"\.\./\.\./", r"/etc/passwd", r"boot\.ini",                     # Path Traversal
    r";\s*cat\s+", r";\s*whoami", r";\s*ls", r"cmd\.exe",            # Command Injection
    r"\bwhoami\b", r"\buname\b", r"\bhostname\b", r"net user",        # System Discovery
    r"\{\s*\"\$[a-z]+\""                                             # NoSQL Injection
]

# --- UI TEMPLATE ---
UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Saad-Shield | Security Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background-color: #161b22; padding: 40px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); border: 1px solid #30363d; text-align: center; width: 420px; }
        h1 { color: #58a6ff; margin-bottom: 10px; font-size: 26px; }
        .status-badge { background-color: #238636; color: white; padding: 6px 16px; border-radius: 20px; font-size: 14px; display: inline-block; margin-bottom: 25px; }
        .info-box { background-color: #0d1117; border-radius: 8px; padding: 18px; margin-top: 20px; border-left: 4px solid #58a6ff; text-align: left; }
        .footer { margin-top: 35px; font-size: 13px; color: #484f58; border-top: 1px solid #30363d; padding-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Saad-Shield</h1>
        <div class="status-badge">System Protected</div>
        <p style="color: #8b949e;">Advanced WAF monitoring is active.</p>
        <div class="info-box">
            <p><strong>Status:</strong> Active & Smart</p>
            <p><strong>Mode:</strong> Regex Pattern Matching</p>
            <p><strong>Alerts:</strong> Configured for Environment</p>
        </div>
        <div class="footer">Developed by <b>Muhammad Saad</b></div>
    </div>
</body>
</html>
"""

def send_alert_email(ip, reason, payload):
    # Check if credentials exist before sending
    if not GMAIL_USER or not GMAIL_PASS:
        print("[-] Email skipped: Credentials not set in Environment Variables.")
        return

    try:
        msg = MIMEText(f"Saad Bhai, Attack Blocked!\n\nIP: {ip}\nType: {reason}\nPayload: {payload}")
        msg['Subject'] = f'🛡️ Saad-Shield Alert: {reason}'
        msg['From'] = GMAIL_USER
        msg['To'] = GMAIL_USER
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_PASS)
            server.send_message(msg)
        print(f"[+] Security Alert Sent.")
    except Exception as e:
        print(f"[-] Email Failed: {e}")

@app.before_request
def smart_waf():
    if request.path == '/favicon.ico': return None
    client_ip = request.remote_addr
    raw_url = urllib.parse.unquote(request.url).lower()
    raw_body = urllib.parse.unquote(request.get_data(as_text=True)).lower()
    user_agent = request.headers.get('User-Agent', '').lower()

    for pattern in SECURITY_RULES:
        if re.search(pattern, raw_url) or re.search(pattern, raw_body):
            send_alert_email(client_ip, "Security Violation", f"Data: {raw_url}")
            return abort(403)
    return None

@app.route('/')
def home():
    return render_template_string(UI_HTML)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)