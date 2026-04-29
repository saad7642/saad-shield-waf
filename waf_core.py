import os
import re
import urllib.parse
import smtplib
import threading
import ssl  # New import for SSL Context
from email.mime.text import MIMEText
from flask import Flask, request, abort, render_template_string

app = Flask(__name__)

# --- SECURE CREDENTIALS ---
GMAIL_USER = os.environ.get("GMAIL_USER") 
GMAIL_PASS = os.environ.get("GMAIL_PASS") 

# --- SECURITY RULES ---
SECURITY_RULES = [
    r"<script.*?>", r"alert\(", r"onerror=", r"onload=",             
    r"union\s+select", r"insert\s+into", r"drop\s+table",             
    r"'.*?or.*?1\s*=\s*1", r"'.*?--", r"\d+\s*=\s*\d+",               
    r"\.\./\.\./", r"/etc/passwd", r";\s*cat\s+", r";\s*whoami",            
    r"\bwhoami\b", r"\{\s*\"\$[a-z]+\""                                             
]

# --- UI TEMPLATE (Muhammad Saad Professional Dashboard) ---
UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Saad-Shield | Security Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background-color: #161b22; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #30363d; text-align: center; width: 420px; }
        h1 { color: #58a6ff; margin-bottom: 5px; font-size: 28px; }
        .status-badge { background: rgba(35, 134, 54, 0.2); color: #3fb950; padding: 5px 15px; border-radius: 20px; font-size: 13px; display: inline-block; border: 1px solid #238636; margin-bottom: 20px; }
        p { color: #8b949e; font-size: 15px; line-height: 1.5; }
        .footer { margin-top: 30px; font-size: 12px; color: #484f58; border-top: 1px solid #30363d; padding-top: 15px; }
        .footer b { color: #58a6ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Saad-Shield</h1>
        <div class="status-badge">● System Live & Protected</div>
        <p>WAF is actively monitoring traffic.<br>Security rules are being enforced.</p>
        <div class="footer">
            Developed by <b>Muhammad Saad</b><br>
            SQA & Cyber Security Specialist
        </div>
    </div>
</body>
</html>
"""

# --- BACKGROUND EMAIL TASK ---
def send_mail_task(ip, reason, payload):
    print(f"[DEBUG] Email task started for IP: {ip}")
    u = GMAIL_USER
    p = GMAIL_PASS
    
    if not u or not p:
        print(f"[-] ERROR: Missing Env Vars.")
        return

    try:
        msg = MIMEText(f"Saad Bhai, Attack Blocked!\n\nIP: {ip}\nType: {reason}\nPayload: {payload}")
        msg['Subject'] = f'🛡️ WAF ALERT: {reason}'
        msg['From'] = u
        msg['To'] = u 
        
        # FIX: SSL Context prevents hanging on handshake
        context = ssl.create_default_context()
        
        print(f"[DEBUG] Connecting to SSL Port 465...")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context, timeout=15) as server:
            print(f"[DEBUG] Connection Established. Logging in...")
            server.login(u, p)
            print(f"[DEBUG] Login Successful!")
            server.send_message(msg)
            
        print(f"[+] SUCCESS: Alert Email Sent to {u}")
    except Exception as e:
        print(f"[-] SMTP FATAL ERROR: {str(e)}")

@app.before_request
def smart_waf():
    if request.path == '/favicon.ico': return None
    client_ip = request.remote_addr
    
    to_scan = [
        urllib.parse.unquote(request.url).lower(),
        urllib.parse.unquote(request.get_data(as_text=True)).lower(),
        request.headers.get('User-Agent', '').lower()
    ]

    for content in to_scan:
        for pattern in SECURITY_RULES:
            if re.search(pattern, content):
                print(f"[!] THREAT DETECTED: {pattern}")
                threading.Thread(target=send_mail_task, args=(client_ip, "Policy Violation", content[:150])).start()
                return abort(403)
    return None

@app.route('/')
def home():
    return render_template_string(UI_HTML)

if __name__ == '__main__':
    # Using Port 10000 for Render
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)