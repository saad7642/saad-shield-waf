import os
import re
import urllib.parse
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, abort, render_template_string

app = Flask(__name__)

# --- SECURE CREDENTIALS (Render Environment Variables) ---
GMAIL_USER = os.environ.get("GMAIL_USER") 
GMAIL_PASS = os.environ.get("GMAIL_PASS") 

# Startup Check: Render Logs mein nazar aayega agar Keys miss hain
print(f"[*] Booting Saad-Shield...")
print(f"[*] Config Check: GMAIL_USER is {'LOADED' if GMAIL_USER else 'MISSING'}")
print(f"[*] Config Check: GMAIL_PASS is {'LOADED' if GMAIL_PASS else 'MISSING'}")

# --- SECURITY RULES (Updated for all attack types) ---
SECURITY_RULES = [
    r"<script.*?>", r"alert\(", r"onerror=", r"onload=",             
    r"union\s+select", r"insert\s+into", r"drop\s+table",             
    r"'.*?or.*?1\s*=\s*1", r"'.*?--", r"\d+\s*=\s*\d+",               
    r"\.\./\.\./", r"/etc/passwd", r"boot\.ini",                     
    r";\s*cat\s+", r";\s*whoami", r";\s*ls", r"cmd\.exe",            
    r"\bwhoami\b", r"\buname\b", r"\bhostname\b", r"net user",        
    r"\{\s*\"\$[a-z]+\""                                             
]

UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Saad-Shield | Live Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; text-align: center; padding-top: 100px; }
        .box { background: #161b22; padding: 40px; border-radius: 15px; border: 1px solid #30363d; display: inline-block; }
        h1 { color: #58a6ff; }
        .status { color: #238636; font-weight: bold; }
    </style>
</head>
<body>
    <div class="box">
        <h1>🛡️ Muhammad Saad Shield</h1>
        <p>Status: <span class="status">LIVE & PROTECTING</span></p>
        <hr style="border: 0.5px solid #30363d;">
        <p style="font-size: 12px; color: #8b949e;">Security Monitoring Active on Render</p>
    </div>
</body>
</html>
"""

def send_alert_email(ip, reason, payload):
    # Freshly fetch credentials
    u = os.environ.get("GMAIL_USER")
    p = os.environ.get("GMAIL_PASS")
    
    if not u or not p:
        print(f"[-] EMAIL ERROR: Credentials not found in Environment!")
        return

    try:
        msg = MIMEText(f"Saad Bhai, Attack Blocked!\n\nIP: {ip}\nType: {reason}\nPayload: {payload}")
        msg['Subject'] = f'🛡️ SECURITY ALERT: {reason}'
        msg['From'] = u
        msg['To'] = u 
        
        print(f"[#] Attempting to send alert email to {u}...")
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(u, p)
            server.send_message(msg)
        print(f"[+] SUCCESS: Alert Email Sent!")
    except Exception as e:
        print(f"[-] SMTP FATAL ERROR: {e}")

@app.before_request
def smart_waf():
    if request.path == '/favicon.ico': return None
    
    client_ip = request.remote_addr
    
    # Scans URL, Body, and crucial Headers (User-Agent)
    data_to_scan = [
        urllib.parse.unquote(request.url).lower(),
        urllib.parse.unquote(request.get_data(as_text=True)).lower(),
        request.headers.get('User-Agent', '').lower()
    ]

    for content in data_to_scan:
        for pattern in SECURITY_RULES:
            if re.search(pattern, content):
                print(f"[!] THREAT DETECTED: {pattern}")
                send_alert_email(client_ip, "Policy Violation", content[:150])
                return abort(403)
    return None

@app.route('/')
def home():
    return render_template_string(UI_HTML)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)