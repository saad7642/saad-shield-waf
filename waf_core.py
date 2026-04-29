import os
import re
import urllib.parse
import smtplib
import threading  # Naya: Background mail ke liye
from email.mime.text import MIMEText
from flask import Flask, request, abort, render_template_string

app = Flask(__name__)

GMAIL_USER = os.environ.get("GMAIL_USER") 
GMAIL_PASS = os.environ.get("GMAIL_PASS") 

SECURITY_RULES = [
    r"<script.*?>", r"alert\(", r"onerror=", r"onload=",             
    r"union\s+select", r"insert\s+into", r"drop\s+table",             
    r"'.*?or.*?1\s*=\s*1", r"'.*?--", r"\d+\s*=\s*\d+",               
    r"\.\./\.\./", r"/etc/passwd", r";\s*cat\s+", r";\s*whoami",            
    r"\bwhoami\b", r"\{\s*\"\$[a-z]+\""                                             
]

# Email bhejne ka function jo background mein chalega
def send_mail_task(ip, reason, payload):
    if not GMAIL_USER or not GMAIL_PASS:
        return
    try:
        msg = MIMEText(f"Saad Bhai, Attack Blocked!\n\nIP: {ip}\nType: {reason}\nPayload: {payload}")
        msg['Subject'] = f'🛡️ WAF ALERT: {reason}'
        msg['From'] = GMAIL_USER
        msg['To'] = GMAIL_USER 
        
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_PASS)
            server.send_message(msg)
        print(f"[+] Background Email Sent!")
    except Exception as e:
        print(f"[-] Background SMTP Error: {e}")

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
                print(f"[!] THREAT: {pattern}")
                # Email ko background thread mein chalayein taake request hang na ho
                threading.Thread(target=send_mail_task, args=(client_ip, "Policy Violation", content[:100])).start()
                return abort(403)
    return None

@app.route('/')
def home():
    return "<h1>🛡️ Saad-Shield Live</h1>"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)